package report

import (
	"html/template"
	"io"
	"os"
	"time"

	"github.com/example/syscallwhitelist/internal/model"
)

// PageData 是检查页渲染所需的全部数据。
type PageData struct {
	GeneratedAt  string
	SnapshotVers []string
	Findings     []model.Finding
	RawByID      map[string]RawView
	Counters     map[string]int
	TempCleaned  bool
	TempLiveLeft int
}

// RawView 保留每条记录的原始输入视图，支撑“回到原始输入”。
type RawView struct {
	Raw       string
	SHA256    string
	Truncated bool
}

var pageTpl = template.Must(template.New("page").Funcs(template.FuncMap{
	"verdictClass": func(v model.Verdict) string {
		switch v {
		case model.VerdictTrusted:
			return "ok"
		case model.VerdictRejected:
			return "rej"
		case model.VerdictUndecidable:
			return "unk"
		default:
			return "err"
		}
	},
	"verdictLabel": func(v model.Verdict) string {
		switch v {
		case model.VerdictTrusted:
			return "可信"
		case model.VerdictRejected:
			return "拒绝"
		case model.VerdictUndecidable:
			return "无法判断"
		default:
			return "处理异常"
		}
	},
}).Parse(pageHTML))

// Render 把检查页写入 w。
func Render(w io.Writer, d PageData) error {
	if d.GeneratedAt == "" {
		d.GeneratedAt = time.Now().Format(time.RFC3339)
	}
	return pageTpl.Execute(w, d)
}

// WriteFile 渲染并写入指定 HTML 文件。
func WriteFile(path string, d PageData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return Render(f, d)
}
