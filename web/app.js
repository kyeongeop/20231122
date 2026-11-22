const state = {
  summaries: [],
  stats: null,
  audit: null,
  selectedStepId: null,
  selectedArtifactId: null,
  selectedEvidence: null,
  loading: true,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const STATUS_LABELS = {
  pass: "PASS",
  fail: "FAIL",
  undecided: "UNDECIDED",
  blocked: "BLOCKED",
  truncated: "TRUNCATED",
  warn: "WARN",
};

const STATUS_NAMES = {
  pass: "通过",
  fail: "失败",
  undecided: "无法判断",
  blocked: "已阻断",
  truncated: "已截断",
  warn: "提示",
};

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function shortHash(value, length = 12) {
  return value ? value.slice(0, length) : "—";
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function statusPill(status) {
  return `<span class="status-pill ${escapeHTML(status)}">${escapeHTML(STATUS_LABELS[status] || status)}</span>`;
}

function icon(name) {
  const icons = {
    copy: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="5" y="5" width="8" height="8" rx="1"/><path d="M3 11V3h8"/></svg>',
    switch: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M3 5h9l-2-2M13 11H4l2 2"/></svg>',
    arrow: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><path d="M3 8h9M9 5l3 3-3 3"/></svg>',
  };
  return icons[name] || "";
}

async function fetchJSON(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function init() {
  try {
    const [list, stats] = await Promise.all([
      fetchJSON("/api/audits"),
      fetchJSON("/api/summary"),
    ]);
    state.summaries = list.items || [];
    state.stats = stats;
    renderSidebar();
    const linked = new URLSearchParams(location.hash.slice(1));
    const requested = linked.get("audit");
    const first = state.summaries.find((item) => item.id === requested)
      || state.summaries.find((item) => item.state === "complete" && item.replayOf)
      || state.summaries.find((item) => item.state === "truncated")
      || state.summaries[0];
    if (first) {
      await selectAudit(first.id, {
        step: linked.get("step"),
        artifact: linked.get("artifact"),
        start: linked.get("start"),
        end: linked.get("end"),
      });
    } else {
      renderEmpty("没有可检查的审计记录。");
    }
  } catch (error) {
    renderEmpty(`无法读取证据库：${escapeHTML(error.message)}`);
  }
}

async function selectAudit(id, deepLink = null) {
  state.loading = true;
  state.selectedStepId = null;
  state.selectedArtifactId = null;
  renderSidebar();
  try {
    const audit = await fetchJSON(`/api/audits/${encodeURIComponent(id)}`);
    state.audit = audit;
    state.loading = false;
    const linkedStep = deepLink?.step ? audit.steps.find((step) => step.id === deepLink.step) : null;
    const initialStep = linkedStep || audit.firstError || audit.boundary || audit.steps?.[0];
    state.selectedStepId = initialStep?.id || null;
    state.selectedEvidence = initialStep?.evidence || null;
    if (deepLink?.artifact && deepLink.start !== null && deepLink.end !== null) {
      const start = Number(deepLink.start);
      const end = Number(deepLink.end);
      if (Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end >= start) {
        state.selectedEvidence = {
          artifactId: deepLink.artifact,
          start,
          end,
          hash: "",
          note: "由证据深链接恢复的 byte 区间。",
        };
      }
    }
    state.selectedArtifactId = deepLink?.artifact
      || initialStep?.evidence?.artifactId
      || audit.artifacts?.[0]?.id
      || null;
    renderAudit();
    renderSidebar();
    $(".main")?.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: "smooth" });
  } catch (error) {
    state.loading = false;
    renderEmpty(`无法读取该记录：${escapeHTML(error.message)}`);
  }
}

function renderEmpty(message) {
  $("#main").innerHTML = `<div class="empty-state">${message}</div>`;
}

function renderSidebar() {
  const count = state.summaries.length;
  $("#record-count").textContent = String(count).padStart(2, "0");
  const list = $("#record-list");
  list.innerHTML = state.summaries.map((item, index) => {
    const active = state.audit?.id === item.id;
    const iconText = item.state === "truncated" ? "TR" : "RP";
    const relation = item.replayOf
      ? `<div class="record-rel">↳ replay of ${escapeHTML(item.replayOf.replace("aud_trunc_", "").toUpperCase())}</div>`
      : "";
    return `
      <button class="record-item ${active ? "active" : ""}" data-audit-id="${escapeHTML(item.id)}" data-state="${escapeHTML(item.state)}">
        <span class="record-icon">${iconText}</span>
        <span class="record-main">
          <span class="record-topline">
            <span class="record-label">${escapeHTML(item.label)}</span>
            <span class="record-state">${item.state === "truncated" ? "HALT" : "RPLY"}</span>
          </span>
          <span class="record-sub">${item.state === "truncated" ? "截断 · 原始证据" : "恢复 · 重放结果"} · ${formatDate(item.capturedAt)}</span>
          ${relation}
        </span>
      </button>
      ${index < count - 1 ? '<div class="record-connector" aria-hidden="true"></div>' : ""}
    `;
  }).join("");
  renderCasePanel();
  if (state.stats) {
    $("#engine-label").textContent = state.stats.engine || "Go";
  }
}

function renderCasePanel() {
  const panel = $("#case-panel");
  if (!state.audit) {
    panel.innerHTML = `
      <div class="case-kicker">Active case</div>
      <div class="case-id">等待选择记录</div>
    `;
    return;
  }
  const audit = state.audit;
  panel.innerHTML = `
    <div class="case-kicker">Active case</div>
    <div class="case-id">${escapeHTML(audit.caseId)}</div>
    <div class="case-facts">
      <div class="case-fact"><span>目标</span><b>${escapeHTML(audit.target)}</b></div>
      <div class="case-fact"><span>方法</span><b>${escapeHTML(audit.method)}</b></div>
      <div class="case-fact"><span>采集</span><b>${escapeHTML(audit.source)}</b></div>
      <div class="case-fact"><span>时间</span><b>${formatDate(audit.capturedAt)}</b></div>
      <div class="case-fact"><span>证据数</span><b>${audit.artifacts.length} immutable</b></div>
    </div>
  `;
}

function renderAudit() {
  const audit = state.audit;
  const replayTarget = audit.replay
    ? (audit.replay.replayAuditId === audit.id ? audit.replay.truncatedAuditId : audit.replay.replayAuditId)
    : null;
  const replayLabel = state.summaries.find((item) => item.id === replayTarget)?.label || "关联记录";
  const verdictLabel = audit.state === "truncated" ? "处理已停止" : (audit.verdict === "blocked" ? "策略阻断" : "检查完成");

  $("#main").innerHTML = `
    <header class="audit-head">
      <div>
        <div class="eyebrow">Policy trace / source verification</div>
        <h1 class="audit-title">${escapeHTML(audit.title)}</h1>
        <div class="audit-sub">
          <code>${escapeHTML(audit.id)}</code>
          <span>·</span>
          <span>${escapeHTML(audit.method)} ${escapeHTML(audit.target)}</span>
          <span>·</span>
          <span>${formatDate(audit.capturedAt)}</span>
        </div>
      </div>
      <div class="head-actions">
        ${replayTarget ? `<button class="button" data-action="switch-audit" data-audit-id="${escapeHTML(replayTarget)}">${icon("switch")} 查看 ${escapeHTML(replayLabel)}</button>` : ""}
        <button class="button dark" data-action="copy-link">${icon("copy")} 复制证据链接</button>
      </div>
    </header>
    ${renderOverview(audit, verdictLabel)}
    ${renderSignals(audit, replayTarget, replayLabel)}
    <div class="audit-grid">
      ${renderSteps(audit)}
      ${renderRawPanel(audit)}
    </div>
    ${renderFindings(audit)}
    <div class="lower-grid">
      ${renderReplay(audit, replayTarget, replayLabel)}
      ${renderRetention(audit)}
    </div>
    <footer class="page-foot">
      <span>Case ${escapeHTML(audit.caseId)} · evidence graph persisted in SQLite</span>
      <span>每个结论可回跳至 step → artifact byte range → SHA-256</span>
    </footer>
  `;
}

function renderOverview(audit, verdictLabel) {
  const firstOrder = audit.firstError ? String(audit.firstError.ordinal).padStart(2, "0") : "—";
  const artifactBytes = audit.artifacts.reduce((sum, item) => sum + item.capturedBytes, 0);
  return `
    <section class="trace-overview" aria-label="审计概览">
      <div class="overview-bar">
        <div class="overview-cell overview-primary">
          <div class="label">系统判定</div>
          <div class="value"><span class="verdict-dot ${audit.state === "truncated" ? "halted" : ""}"></span>${escapeHTML(verdictLabel)}</div>
        </div>
        <div class="overview-cell">
          <div class="label">首个错误</div>
          <div class="value critical">${firstOrder}<span class="unit">state</span></div>
        </div>
        <div class="overview-cell">
          <div class="label">未决边界</div>
          <div class="value ${audit.counts.undecided ? "uncertain" : ""}">${String(audit.counts.undecided).padStart(2, "0")}<span class="unit">open</span></div>
        </div>
        <div class="overview-cell">
          <div class="label">不可变证据</div>
          <div class="value">${String(audit.artifacts.length).padStart(2, "0")}<span class="unit">artifacts</span></div>
        </div>
        <div class="overview-cell">
          <div class="label">证据体积</div>
          <div class="value">${artifactBytes}<span class="unit">bytes</span></div>
        </div>
      </div>
      <div class="trace-rail" aria-label="处理状态链">
        ${audit.steps.map((step) => `
          <div class="rail-step" data-status="${escapeHTML(step.status)}">
            <span class="rail-dot">${String(step.ordinal).padStart(2, "0")}</span>
            <span class="rail-label">${escapeHTML(step.label)}</span>
          </div>
        `).join("")}
      </div>
    </section>
  `;
}

function renderSignals(audit, replayTarget, replayLabel) {
  const first = audit.firstError;
  const boundary = audit.boundary;
  let firstCard = "";
  if (first) {
    firstCard = `
      <article class="signal-card">
        <div class="signal-num">${String(first.ordinal).padStart(2, "0")}</div>
        <div>
          <div class="signal-kicker">First error state · 不计算加权总分</div>
          <h2 class="signal-title">${escapeHTML(first.summary)}</h2>
          <p class="signal-copy"><code>${escapeHTML(first.key)}</code> · ${escapeHTML((first.detail || "").slice(0, 112))}</p>
        </div>
        <button class="signal-action" data-action="jump-step" data-step-id="${escapeHTML(first.id)}">定位证据 →</button>
      </article>
    `;
  } else {
    firstCard = `
      <article class="signal-card">
        <div class="signal-num">OK</div>
        <div>
          <div class="signal-kicker">No decisive error</div>
          <h2 class="signal-title">没有发现确定性错误状态</h2>
          <p class="signal-copy">仍需结合未决边界判断证据覆盖范围。</p>
        </div>
      </article>
    `;
  }

  let boundaryCard = "";
  if (boundary) {
    boundaryCard = `
      <article class="signal-card boundary">
        <div class="signal-num">?</div>
        <div>
          <div class="signal-kicker">Undecided boundary · 保留未知</div>
          <h2 class="signal-title">${escapeHTML(boundary.summary)}</h2>
          <p class="signal-copy">${escapeHTML((boundary.detail || "").slice(0, 90))}</p>
        </div>
        <button class="signal-action" data-action="jump-step" data-step-id="${escapeHTML(boundary.id)}">查看边界 →</button>
      </article>
    `;
  } else if (replayTarget) {
    boundaryCard = `
      <article class="signal-card boundary">
        <div class="signal-num">↳</div>
        <div>
          <div class="signal-kicker">Recovery replay available</div>
          <h2 class="signal-title">恢复后的重放可补充证据</h2>
          <p class="signal-copy">${escapeHTML(replayLabel)} 只追加接缝后的内容，不覆盖当前截断记录。</p>
        </div>
        <button class="signal-action" data-action="switch-audit" data-audit-id="${escapeHTML(replayTarget)}">打开重放 →</button>
      </article>
    `;
  }
  return `<section class="signal-grid">${firstCard}${boundaryCard}</section>`;
}

function renderSteps(audit) {
  return `
    <section class="panel" aria-label="处理步骤">
      <div class="panel-head">
        <h2 class="panel-title">处理状态链 <code>ordered / append-only</code></h2>
        <span class="panel-note">${audit.counts.pass} pass · ${audit.counts.fail} fail · ${audit.counts.undecided} open</span>
      </div>
      <div class="step-list">
        ${audit.steps.map((step) => {
          const selected = state.selectedStepId === step.id;
          const evidence = step.evidence;
          const canSelect = Boolean(evidence && evidence.artifactId);
          return `
            <button class="step-row ${selected ? "selected" : ""} ${canSelect ? "" : "no-evidence"}"
              data-action="select-step" data-step-id="${escapeHTML(step.id)}" data-status="${escapeHTML(step.status)}"
              ${canSelect ? "" : 'aria-disabled="true"'}>
              <span class="step-index">${String(step.ordinal).padStart(2, "0")}<span class="step-marker"></span></span>
              <span class="step-content">
                <span class="step-top">
                  <span class="step-label">${escapeHTML(step.label)}</span>
                  <span class="step-key">${escapeHTML(step.key)}</span>
                  ${statusPill(step.status)}
                </span>
                <span class="step-summary">${escapeHTML(step.summary)}</span>
                <span class="step-detail">${escapeHTML(step.detail || "")}</span>
                <span class="step-meta">
                  <span>${escapeHTML(STATUS_NAMES[step.status] || step.status)}</span>
                  <span>${step.durationMs} ms</span>
                  ${canSelect ? `<span class="evidence-link">bytes ${evidence.start}..${evidence.end}</span>` : "<span>no evidence attached</span>"}
                  ${audit.firstError?.id === step.id ? "<span>首个确定性错误</span>" : ""}
                </span>
              </span>
            </button>
          `;
        }).join("")}
      </div>
    </section>
  `;
}

function selectedStep(audit) {
  return audit.steps.find((step) => step.id === state.selectedStepId) || null;
}

function selectedArtifact(audit) {
  return audit.artifacts.find((artifact) => artifact.id === state.selectedArtifactId) || audit.artifacts[0] || null;
}

function renderRawPanel(audit) {
  const artifact = selectedArtifact(audit);
  const step = selectedStep(audit);
  if (!artifact) {
    return `<section class="panel raw-panel"><div class="panel-head"><h2 class="panel-title">原始输入</h2></div><div class="empty-state">无原始证据。</div></section>`;
  }
  const evidence = state.selectedEvidence?.artifactId === artifact.id
    ? state.selectedEvidence
    : (step?.evidence?.artifactId === artifact.id ? step.evidence : null);
  return `
    <section class="panel raw-panel" aria-label="原始输入">
      <div class="panel-head">
        <h2 class="panel-title">原始输入 <code>immutable bytes</code></h2>
        <div class="artifact-tabs">
          ${audit.artifacts.map((item) => `
            <button class="artifact-tab ${item.id === artifact.id ? "active" : ""}"
              data-action="select-artifact" data-artifact-id="${escapeHTML(item.id)}">${escapeHTML(item.kind)}</button>
          `).join("")}
        </div>
      </div>
      <div class="artifact-strip">
        <span><b>${escapeHTML(artifact.label)}</b></span>
        <span>${artifact.capturedBytes} B captured</span>
        <span>${artifact.expectedBytes} B expected</span>
        <span>sha256 ${escapeHTML(shortHash(artifact.sha256))}</span>
        <span class="immutable">● immutable</span>
        ${artifact.redactions ? `<span>${artifact.redactions} redaction</span>` : ""}
      </div>
      <div class="code-wrap" id="code-wrap">
        <div class="code-head">
          <span>${escapeHTML(artifact.id)} · UTF-8 / byte offsets</span>
          <span class="live">${evidence ? `evidence ${evidence.start}..${evidence.end}` : "完整原文"}</span>
        </div>
        <div class="code-content">${renderCode(artifact, evidence)}</div>
      </div>
      <div class="evidence-caption">
        <span>${evidence ? `<b>${escapeHTML(step.key)}</b> · ${escapeHTML(evidence.note || "无证据说明")}` : "点击左侧状态查看对应 byte 区间。"}</span>
        <span>sha ${escapeHTML(shortHash(evidence?.hash || artifact.sha256, 10))}</span>
      </div>
    </section>
  `;
}

function renderCode(artifact, evidence) {
  const content = artifact.content || "";
  const lines = content.split("\n");
  let offset = 0;
  const rows = lines.map((rawLine, index) => {
    const lineStart = offset;
    const lineEnd = offset + rawLine.length;
    offset = lineEnd + 1;
    const display = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    const overlapStart = evidence ? Math.max(0, evidence.start - lineStart) : -1;
    const overlapEnd = evidence ? Math.min(display.length, evidence.end - lineStart) : -1;
    const hasHighlight = Boolean(evidence && evidence.end > lineStart && evidence.start < lineEnd + 1);
    let text = escapeHTML(display);
    if (hasHighlight && overlapEnd > overlapStart) {
      text = escapeHTML(display.slice(0, overlapStart)) +
        `<mark>${escapeHTML(display.slice(overlapStart, overlapEnd))}</mark>` +
        escapeHTML(display.slice(overlapEnd));
    }
    return `
      <div class="code-line ${hasHighlight ? "highlight" : ""}" data-line="${index + 1}">
        <span class="line-no">${String(index + 1).padStart(3, "0")}</span>
        <span class="line-text">${text || " "}</span>
      </div>
    `;
  }).join("");
  const missing = artifact.expectedBytes - artifact.capturedBytes;
  const tail = missing > 0
    ? `<div class="truncation-tail">${missing} bytes 未采集 · 解析在此停止 · 不以推测补全</div>`
    : "";
  return rows + tail;
}

function renderFindings(audit) {
  return `
    <section class="panel findings-panel" aria-label="结论与证据">
      <div class="panel-head">
        <h2 class="panel-title">结论与证据 <code>claim → step → bytes</code></h2>
        <span class="panel-note">${audit.conclusions.length} conclusions · no aggregate score</span>
      </div>
      <div class="finding-list">
        ${audit.conclusions.map((finding) => `
          <article class="finding" data-status="${escapeHTML(finding.status)}">
            <div class="finding-mark">${finding.status === "pass" ? "✓" : finding.status === "undecided" ? "?" : "!"}</div>
            <div>
              <div class="finding-top">
                <span class="finding-code">${escapeHTML(finding.code)}</span>
                ${statusPill(finding.status)}
                ${finding.severity === "critical" || finding.severity === "high" ? '<span class="finding-code">deterministic</span>' : ""}
              </div>
              <h3 class="finding-title">${escapeHTML(finding.title)}</h3>
              <p class="finding-detail">${escapeHTML(finding.detail)}</p>
              <button class="evidence-jump" data-action="jump-evidence" data-step-id="${escapeHTML(finding.stepId)}"
                data-artifact-id="${escapeHTML(finding.evidence.artifactId || "")}"
                data-start="${finding.evidence.start || 0}" data-end="${finding.evidence.end || 0}">
                ${icon("arrow")} 回到 ${escapeHTML(finding.stepId || "来源")}
                <span class="jump-range">byte ${finding.evidence.start || 0}..${finding.evidence.end || 0}</span>
              </button>
            </div>
          </article>
        `).join("")}
      </div>
    </section>
  `;
}

function renderReplay(audit, replayTarget, replayLabel) {
  const replay = audit.replay;
  if (!replay) {
    return `
      <section class="panel">
        <div class="panel-head"><h2 class="panel-title">恢复重放 <code>not available</code></h2></div>
        <div class="empty-state">该记录没有关联的恢复重放。</div>
      </section>
    `;
  }
  const currentIsReplay = replay.replayAuditId === audit.id;
  return `
    <section class="panel" aria-label="恢复重放">
      <div class="panel-head">
        <h2 class="panel-title">恢复重放 <code>append-only seam</code></h2>
        <span class="panel-note">${replay.seamVerified ? "seam verified" : "seam unverified"}</span>
      </div>
      <div class="replay-body">
        <div class="replay-flow">
          <div class="replay-node ${currentIsReplay ? "" : "recovered"}">
            <div class="node-label">ORIGINAL / TRUNCATED</div>
            <div class="node-id">${escapeHTML(replay.truncatedAuditId)}</div>
            <div class="node-copy">保留原始前缀，不覆盖、不补写。</div>
          </div>
          <div class="replay-arrow"><span>seam @ ${replay.seamOffset}</span></div>
          <div class="replay-node ${currentIsReplay ? "recovered" : ""}">
            <div class="node-label">RECOVERED / REPLAY</div>
            <div class="node-id">${escapeHTML(replay.replayAuditId)}</div>
            <div class="node-copy">追加 ${replay.recoveredBytes} bytes 后重新执行完整状态链。</div>
          </div>
        </div>
        <div class="replay-meta">
          <div class="replay-metric"><div class="label">seam offset</div><div class="value">${replay.seamOffset} B</div></div>
          <div class="replay-metric"><div class="label">recovered</div><div class="value">${replay.recoveredBytes} B</div></div>
          <div class="replay-metric"><div class="label">prefix check</div><div class="value">${replay.seamVerified ? "MATCH" : "FAIL"}</div></div>
        </div>
        <p class="replay-note">${escapeHTML(replay.note)}</p>
        ${replayTarget ? `<button class="button" data-action="switch-audit" data-audit-id="${escapeHTML(replayTarget)}">${icon("switch")} 切换到 ${escapeHTML(replayLabel)}</button>` : ""}
      </div>
    </section>
  `;
}

function renderRetention(audit) {
  const artifact = selectedArtifact(audit);
  return `
    <section class="panel" aria-label="证据保留">
      <div class="panel-head">
        <h2 class="panel-title">证据保留 <code>retention contract</code></h2>
        <span class="panel-note">read-only</span>
      </div>
      <div class="retention-body">
        <div class="retention-row">
          <span class="retention-key">当前对象</span>
          <span class="retention-value">${escapeHTML(artifact?.id || "—")}</span>
        </div>
        <div class="retention-row">
          <span class="retention-key">SHA-256</span>
          <span class="retention-value">${escapeHTML(artifact?.sha256 || "—")}</span>
        </div>
        <div class="retention-row">
          <span class="retention-key">字节范围</span>
          <span class="retention-value">0..${artifact?.capturedBytes ?? 0} · ${artifact?.capturedBytes ?? 0} bytes</span>
        </div>
        <div class="retention-row">
          <span class="retention-key">不可变性</span>
          <span class="retention-value good">${artifact?.immutable ? "IMMUTABLE · append only" : "MUTABLE"}</span>
        </div>
        <div class="retention-row">
          <span class="retention-key">脱敏</span>
          <span class="retention-value">${artifact?.redactions ? `${artifact.redactions} 处；保留字段与位置` : "无"}</span>
        </div>
        <div class="retention-row">
          <span class="retention-key">说明</span>
          <span class="retention-value">${escapeHTML(artifact?.note || "—")}</span>
        </div>
      </div>
    </section>
  `;
}

function selectStep(stepId, scroll = true, evidenceOverride = null) {
  if (!state.audit) return;
  const step = state.audit.steps.find((item) => item.id === stepId);
  if (!step) return;
  state.selectedStepId = step.id;
  state.selectedEvidence = evidenceOverride || step.evidence || null;
  if (state.selectedEvidence?.artifactId) {
    state.selectedArtifactId = state.selectedEvidence.artifactId;
  }
  renderAudit();
  renderSidebar();
  if (scroll) {
    focusSelectedStep();
  }
}

function focusSelectedStep() {
  const row = Array.from(document.querySelectorAll(".step-row"))
    .find((item) => item.dataset.stepId === state.selectedStepId);
  row?.scrollIntoView({ behavior: "smooth", block: "center" });
  const mark = $(".code-line.highlight");
  mark?.scrollIntoView({ behavior: "smooth", block: "center" });
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("visible"), 2200);
}

async function copyEvidenceLink() {
  if (!state.audit) return;
  const step = selectedStep(state.audit);
  const artifact = selectedArtifact(state.audit);
  const evidence = state.selectedEvidence || step?.evidence;
  const params = new URLSearchParams({
    audit: state.audit.id,
    step: step?.id || "",
    artifact: artifact?.id || "",
    start: String(evidence?.start ?? 0),
    end: String(evidence?.end ?? 0),
  });
  const link = `${location.origin}${location.pathname}#${params.toString()}`;
  try {
    await navigator.clipboard.writeText(link);
    showToast("证据链接已复制：审计记录 + 状态 + byte 区间");
  } catch {
    history.replaceState(null, "", `#${params.toString()}`);
    showToast("浏览器未授权剪贴板；已把证据链接写入地址栏。");
  }
}

document.addEventListener("click", async (event) => {
  const target = event.target.closest("[data-action]");
  if (!target) return;
  const action = target.dataset.action;
  if (action === "switch-audit") {
    await selectAudit(target.dataset.auditId);
  } else if (action === "select-step") {
    selectStep(target.dataset.stepId, true);
  } else if (action === "select-artifact") {
    state.selectedArtifactId = target.dataset.artifactId;
    state.selectedEvidence = null;
    renderAudit();
  } else if (action === "jump-step") {
    selectStep(target.dataset.stepId, true);
  } else if (action === "jump-evidence") {
    let evidence = null;
    if (target.dataset.artifactId) {
      evidence = {
        artifactId: target.dataset.artifactId,
        start: Number(target.dataset.start || 0),
        end: Number(target.dataset.end || 0),
        hash: "",
        note: "结论直接绑定的原始证据切片。",
      };
    }
    selectStep(target.dataset.stepId, true, evidence);
  } else if (action === "copy-link") {
    await copyEvidenceLink();
  }
});

document.addEventListener("click", (event) => {
  const item = event.target.closest("[data-audit-id]");
  if (!item || item.dataset.action) return;
  selectAudit(item.dataset.auditId);
});

document.addEventListener("DOMContentLoaded", init);
