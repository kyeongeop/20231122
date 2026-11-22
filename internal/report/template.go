package report

const pageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>系统调用白名单来源检查</title>
<style>
  body { font-family: -apple-system, "Segoe UI", sans-serif; margin: 24px;
         color: #1f2933; background: #f7f8fa; }
  h1 { font-size: 22px; }
  .meta { color: #52606d; font-size: 13px; margin-bottom: 16px; }
  .summary { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
  .chip { padding: 6px 12px; border-radius: 14px; font-size: 13px;
          background: #fff; border: 1px solid #d9e2ec; }
  .chip b { font-size: 15px; }
  .card { background: #fff; border: 1px solid #d9e2ec; border-radius: 8px;
          padding: 16px; margin-bottom: 16px; }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 12px;
           font-size: 12px; color: #fff; }
  .ok { background: #2e7d32; }
  .rej { background: #c62828; }
  .unk { background: #ef6c00; }
  .err { background: #616161; }
  .reason { margin: 8px 0; font-weight: 600; }
  .raw { background: #0f172a; color: #a7f3d0; padding: 10px; border-radius: 6px;
         font-family: ui-monospace, monospace; font-size: 12px;
         white-space: pre-wrap; word-break: break-all; }
  table { border-collapse: collapse; width: 100%; margin-top: 10px; font-size: 12px; }
  th, td { border: 1px solid #d9e2ec; padding: 6px 8px; text-align: left;
           vertical-align: top; }
  th { background: #eef2f6; }
  code { background: #eef2f6; padding: 1px 5px; border-radius: 4px; }
  .clean { margin-top: 8px; font-size: 13px; }
</style>
</head>
<body>
<h1>系统调用白名单 · 来源检查页</h1>
<div class="meta">
  生成时间：{{.GeneratedAt}} ｜ 已载入白名单快照：
  {{range .SnapshotVers}}<code>{{.}}</code> {{end}}
</div>
<div class="summary">
  <div class="chip">可信 <b>{{index .Counters "trusted"}}</b></div>
  <div class="chip">合计 <b>{{len .Findings}}</b></div>
</div>

{{range .Findings}}
<div class="card">
  <div>
    <span class="badge {{verdictClass .Verdict}}">{{verdictLabel .Verdict}}</span>
    <b>{{.RecordID}}</b>
    {{if .SnapshotVersion}}｜依据快照 <code>{{.SnapshotVersion}}</code>{{end}}
    {{if .Matched}}｜命中 <code>{{.Matched.Name}}({{.Matched.Number}}, {{.Matched.Risk}})</code>{{end}}
  </div>
  <div class="reason">{{.Reason}}</div>
  {{with index $.RawByID .RecordID}}
  <div class="meta">原始输入（SHA-256 <code>{{.SHA256}}</code>{{if .Truncated}}，已标记截断{{end}}）：</div>
  <div class="raw">{{.Raw}}</div>
  {{end}}
  <table>
    <tr><th>#</th><th>阶段</th><th>说明</th><th>输入证据</th><th>产出</th></tr>
    {{range .Steps}}
    <tr>
      <td>{{.Seq}}</td><td>{{.Stage}}</td><td>{{.Detail}}</td>
      <td><code>{{.Input}}</code></td><td><code>{{.Output}}</code></td>
    </tr>
    {{end}}
  </table>
  <div class="meta" style="margin-top:8px">
    关键证据：
    {{range $k, $v := .Evidence}}<code>{{$k}}={{$v}}</code> {{end}}
  </div>
</div>
{{end}}

<div class="card clean">
  <b>临时状态清理：</b>
  {{if .TempCleaned}}托管临时根目录已删除，残留工作目录 {{.TempLiveLeft}} 个。
  {{else}}警告：临时目录仍有残留（{{.TempLiveLeft}} 个）。{{end}}
</div>
</body>
</html>`
