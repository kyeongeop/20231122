package checker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/example/syscallwhitelist/internal/model"
	"github.com/example/syscallwhitelist/internal/store"
	"github.com/example/syscallwhitelist/internal/tempstate"
)

// maxRawEvidence 限制单步保留的原始输入证据长度，避免页面被超长输入撑爆。
const maxRawEvidence = 160

// Checker 把一条记录沿固定流水线处理，并为每个结论留下可回溯证据。
type Checker struct {
	store *store.Store
	temp  *tempstate.Manager
}

func New(st *store.Store, tmp *tempstate.Manager) *Checker {
	return &Checker{store: st, temp: tmp}
}

// Process 处理单条记录。任何 panic 都会被 recover 转成 error 结论，
// 从而保证调用方可以继续处理后续对象。
func (c *Checker) Process(rec model.Record) (finding model.Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic recovered: %v", r)
			finding = model.Finding{
				RecordID: rec.ID,
				Verdict:  model.VerdictError,
				Reason:   err.Error(),
				Steps:    finding.Steps,
				Evidence: finding.Evidence,
			}
		}
	}()
	return c.run(rec), nil
}

func (c *Checker) run(rec model.Record) model.Finding {
	f := model.Finding{
		RecordID: rec.ID,
		Evidence: map[string]string{},
	}
	rawSHA := sha256.Sum256([]byte(rec.Raw))
	rawHash := hex.EncodeToString(rawSHA[:])
	f.Evidence["raw_sha256"] = rawHash
	f.Evidence["raw_len"] = fmt.Sprintf("%d", len(rec.Raw))
	if err := c.store.SaveRawInput(rec, rawHash); err != nil {
		return c.fail(f, "persist raw input: "+err.Error())
	}
	addStep(&f, "ingest", "接收原始信封并计算字节哈希",
		clip(rec.Raw), "sha256="+rawHash)

	// 阶段 1：在临时目录落地处理状态（结束统一清理）。
	workDir, cleanup, err := c.temp.Allocate(rec.ID)
	if err != nil {
		return c.fail(f, "allocate temp state: "+err.Error())
	}
	defer cleanup()
	addStep(&f, "tempstate", "在隔离临时目录落地处理状态",
		"record_id="+rec.ID, "workdir="+workDir)

	// 阶段 2：解析失败属于输入异常，隔离为 error，不中断批处理。
	if rec.ParseError != "" {
		addStep(&f, "parse", "信封解析报错", clip(rec.Raw), rec.ParseError)
		return c.fail(f, "parse error: "+rec.ParseError)
	}

	// 阶段 3：截断记录。无法看到完整签名与负载，属于无法判断边界，
	// 但保留截断长度、原始哈希等关键证据。
	if rec.Truncated {
		f.Evidence["truncated"] = "true"
		f.Evidence["declared_version"] = rec.Version
		addStep(&f, "truncation", "检测到输入在传输中被截断",
			clip(rec.Raw),
			fmt.Sprintf("raw_len=%d，签名字段不完整，无法验证", len(rec.Raw)))
		f.Verdict = model.VerdictUndecidable
		f.Reason = "记录被截断，签名与负载不完整，证据不足以做出可信/拒绝判断"
		c.persist(f)
		return f
	}

	// 阶段 4：来源是否在受信任登记中。
	src, known, err := c.store.GetSource(rec.SourceID)
	if err != nil {
		return c.fail(f, "lookup source: "+err.Error())
	}
	addStep(&f, "source_lookup", "比对受信任来源登记表",
		"source_id="+rec.SourceID,
		fmt.Sprintf("known=%v", known))
	if !known {
		f.Verdict = model.VerdictRejected
		f.Reason = fmt.Sprintf("来源 %q 不在受信任登记表内", rec.SourceID)
		f.Evidence["source_known"] = "false"
		c.persist(f)
		return f
	}

	// 阶段 5：签名公钥指纹比对。
	sigOK := rec.Signature == src.PubKey
	f.Evidence["expected_pubkey"] = src.PubKey
	f.Evidence["provided_signature"] = rec.Signature
	addStep(&f, "signature", "比对记录签名与登记公钥指纹",
		"sig="+rec.Signature,
		fmt.Sprintf("match=%v", sigOK))
	if !sigOK {
		f.Verdict = model.VerdictRejected
		f.Reason = "签名公钥指纹与受信任来源不一致"
		c.persist(f)
		return f
	}

	// 阶段 6：定位声明依据的白名单版本快照。
	snap, ok, err := c.store.GetSnapshot(rec.Version)
	if err != nil {
		return c.fail(f, "lookup snapshot: "+err.Error())
	}
	addStep(&f, "snapshot_lookup", "加载声明版本的白名单快照",
		"version="+rec.Version,
		fmt.Sprintf("found=%v fingerprint=%s", ok, snap.Fingerprint))
	if !ok {
		// 找不到快照版本：无法判断的边界（区别于明确拒绝）。
		f.Evidence["snapshot_found"] = "false"
		f.Verdict = model.VerdictUndecidable
		f.Reason = fmt.Sprintf("白名单版本 %q 无快照，无法核对系统调用", rec.Version)
		c.persist(f)
		return f
	}
	f.SnapshotVersion = snap.Version

	// 阶段 7：在快照内核对系统调用号。
	match := lookupSyscall(snap.Syscalls, rec.SyscallNo)
	addStep(&f, "syscall_match", "在快照系统调用表中查找调用号",
		fmt.Sprintf("syscall_no=%d", rec.SyscallNo),
		fmt.Sprintf("matched=%v", match != nil))
	if match == nil {
		f.Verdict = model.VerdictRejected
		f.Reason = fmt.Sprintf("系统调用号 %d 不在版本 %s 白名单内",
			rec.SyscallNo, rec.Version)
		c.persist(f)
		return f
	}

	f.Matched = match
	f.Verdict = model.VerdictTrusted
	f.Reason = fmt.Sprintf("来源可信、签名一致，且 %s(no=%d) 命中 %s 白名单",
		match.Name, match.Number, rec.Version)
	f.Evidence["snapshot_fingerprint"] = snap.Fingerprint
	c.persist(f)
	return f
}

func (c *Checker) persist(f model.Finding) {
	_ = c.store.SaveFinding(f)
}

func (c *Checker) fail(f model.Finding, reason string) model.Finding {
	f.Verdict = model.VerdictError
	f.Reason = reason
	addStep(&f, "error", "处理异常已隔离", "", reason)
	c.persist(f)
	return f
}

func addStep(f *model.Finding, stage, detail, input, output string) {
	f.Steps = append(f.Steps, model.EvidenceStep{
		Seq:    len(f.Steps) + 1,
		Stage:  stage,
		Detail: detail,
		Input:  input,
		Output: output,
	})
}

func lookupSyscall(calls []model.Syscall, no int) *model.Syscall {
	for i := range calls {
		if calls[i].Number == no {
			return &calls[i]
		}
	}
	return nil
}

func clip(s string) string {
	if len(s) <= maxRawEvidence {
		return s
	}
	return s[:maxRawEvidence] + "...(clipped)"
}
