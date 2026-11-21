package lockout

import (
	"fmt"
	"sync"
	"time"
)

// 并发账户锁定策略: 连续 FailThreshold 次失败 -> 锁定 LockDuration。
const (
	FailThreshold = 5
	LockDuration  = 15 * time.Minute
)

// 触发位置锚点, 报告中的 "触发位置" 列引用这些常量。
const (
	LocAuthorize   = "service.go:authorize"         // 权限判断(锁定门闸)
	LocIncrement   = "service.go:read-modify-write" // 计数读-改-写(竞态触发点)
	LocDedupAbsent = "service.go:dedup-missing"     // 缺失的去重检查
)

type Service struct {
	store *Store
	// dupBarrier 让同一 RequestID 的重复对象在计数前对齐,
	// 从而确定性地复现 TOCTOU 竞态(所有副本都通过门闸后才各自 +1)。
	// 只为出现次数 >=2 的 RequestID 预建, 唯一请求不经过屏障。
	dupBarrier map[string]*sync.WaitGroup
}

func NewService(s *Store) *Service { return &Service{store: s} }

// authorize 是权限判断: 账户处于锁定期则拒绝。
func (svc *Service) authorize(req Request) (bool, error) {
	_, lockedUntil, err := svc.store.GetAccount(req.Username)
	if err != nil {
		return false, err
	}
	now := time.Now().Unix()
	allowed := lockedUntil <= now
	decision := "ALLOW"
	if !allowed {
		decision = "DENY_LOCKED"
	}
	_, err = svc.store.LogAttempt(req.RequestID, req.RawOffset, req.Username,
		"authorize", decision,
		fmt.Sprintf("loc=%s locked_until=%d now=%d", LocAuthorize, lockedUntil, now))
	return allowed, err
}

// Handle 处理单条登录请求。失败时累加计数, 达到阈值即锁定。
// 注意: 这里刻意不做按 RequestID 去重, 且 IncrementFail 的读-改-写无事务保护。
// 重复对象并发进入时会互相覆盖计数(丢失更新), 使锁定阈值永远差 1 —— 即异常场景。
func (svc *Service) Handle(req Request) error {
	allowed, err := svc.authorize(req)
	if err != nil {
		return err
	}
	if !allowed {
		return nil
	}
	if req.Success {
		_, err := svc.store.LogAttempt(req.RequestID, req.RawOffset, req.Username,
			"login", "SUCCESS", "counter reset not implemented in recon")
		return err
	}
	// 读-改-写窗口: 先读计数
	failCount, _, err := svc.store.GetAccount(req.Username)
	if err != nil {
		return err
	}
	// 重复对象对齐点: 同一 RequestID 的所有副本在读完计数后汇合,
	// 保证它们读到相同的旧值再各自写回, 确定性复现丢失更新。
	if barrier, ok := svc.dupBarrier[req.RequestID]; ok {
		barrier.Done()
		barrier.Wait()
	}
	count := failCount + 1
	if err := svc.store.SetFail(req.Username, count); err != nil {
		return err
	}
	detail := fmt.Sprintf("loc=%s fail_count=%d threshold=%d", LocIncrement, count, FailThreshold)
	if _, err := svc.store.LogAttempt(req.RequestID, req.RawOffset, req.Username,
		"increment", "COUNTED", detail); err != nil {
		return err
	}
	if count >= FailThreshold {
		until := time.Now().Add(LockDuration).Unix()
		if err := svc.store.Lock(req.Username, until); err != nil {
			return err
		}
		_, err := svc.store.LogAttempt(req.RequestID, req.RawOffset, req.Username,
			"lock", "LOCKED", fmt.Sprintf("locked_until=%d", until))
		return err
	}
	return nil
}

// ProcessConcurrent 并发处理一批请求(模拟并发登录流量)。
func (svc *Service) ProcessConcurrent(reqs []Request) error {
	counts := map[string]int{}
	for _, r := range reqs {
		counts[r.RequestID]++
	}
	svc.dupBarrier = map[string]*sync.WaitGroup{}
	for id, n := range counts {
		if n >= 2 {
			barrier := &sync.WaitGroup{}
			barrier.Add(n)
			svc.dupBarrier[id] = barrier
		}
	}
	var wg sync.WaitGroup
	errCh := make(chan error, len(reqs))
	for _, r := range reqs {
		wg.Add(1)
		go func(req Request) {
			defer wg.Done()
			if err := svc.Handle(req); err != nil {
				errCh <- err
			}
		}(r)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}
