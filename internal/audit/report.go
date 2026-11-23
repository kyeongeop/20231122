package audit

import (
	"fmt"
	"html"
	"os"
	"strings"
)

type reportRow struct {
	ObjectID int64
	Label    string
	Kind     string
	Raw      string
	SHA      string
	Verdict  string
	Reason   string
	Steps    []Step
	Evidence []Evidence
}

// RenderReport writes the provenance check page for a run as static HTML.
func (s *Store) RenderReport(runID int64, outPath string) error {
	rows, err := s.loadReportRows(runID)
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\">")
	b.WriteString("<title>密码重置令牌审计 · 来源检查页</title>")
	b.WriteString(`<style>
body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem}
code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}
.card{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
.valid{border-left:6px solid #2e7d32}.expired{border-left:6px solid #c62828}
.unknown-extension{border-left:6px solid #6a5acd}.undecidable{border-left:6px solid #f9a825}
.error{border-left:6px solid #757575}
h1{font-size:1.4rem}h2{font-size:1.05rem;margin:.2rem 0}
ol{margin:.3rem 0}.kv{font-size:.85rem}
</style></head><body>`)
	b.WriteString("<h1>密码重置令牌审计 · 来源检查页</h1>")
	fmt.Fprintf(&b, "<p>运行 #%d · 每条结论均可回溯到原始输入与处理步骤。</p>", runID)
	b.WriteString("<h2>结论总览</h2><table><tr><th>对象</th><th>类型</th><th>结论</th><th>理由</th><th>来源</th></tr>")
	for _, r := range rows {
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td><a href=\"#obj-%d\">追溯</a></td></tr>",
			esc(r.Label), esc(r.Kind), esc(r.Verdict), esc(r.Reason), r.ObjectID)
	}
	b.WriteString("</table><h2>逐对象来源链</h2>")
	for _, r := range rows {
		fmt.Fprintf(&b, "<div class=\"card %s\" id=\"obj-%d\"><h2>%s <code>%s</code></h2>",
			esc(r.Verdict), r.ObjectID, esc(r.Label), esc(r.Verdict))
		fmt.Fprintf(&b, "<p class=\"kv\">原始输入: <code>%s</code><br>SHA-256: <code>%s</code></p>",
			esc(r.Raw), esc(r.SHA))
		b.WriteString("<p>处理步骤:</p><ol>")
		for _, st := range r.Steps {
			fmt.Fprintf(&b, "<li><code>%s</code> — %s</li>", esc(st.Name), esc(st.Detail))
		}
		b.WriteString("</ol><p>关键证据:</p><ul>")
		for _, ev := range r.Evidence {
			fmt.Fprintf(&b, "<li class=\"kv\"><code>%s</code> = <code>%s</code></li>",
				esc(ev.Key), esc(ev.Value))
		}
		b.WriteString("</ul></div>")
	}
	b.WriteString("</body></html>")
	return os.WriteFile(outPath, []byte(b.String()), 0o644)
}

func esc(s string) string { return html.EscapeString(s) }
