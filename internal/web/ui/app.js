const state = {
  data: null,
  selectedId: "",
  filter: "all",
  toastTimer: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

document.addEventListener("DOMContentLoaded", () => {
  bindStaticEvents();
  loadCase();
});

async function loadCase() {
  try {
    const response = await fetch("/api/case", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(await response.text());
    state.data = await response.json();
    if (!state.selectedId || !findObject(state.selectedId)) {
      state.selectedId = state.data.objects.find((obj) => obj.status === "indeterminate")?.id
        || state.data.objects[0]?.id || "";
    }
    renderAll();
  } catch (error) {
    $("#object-list").innerHTML = `<div class="empty-state">无法读取证据库：${escapeHTML(error.message)}</div>`;
    $("#detail-panel").innerHTML = `<div class="empty-state">请确认 Go 服务与 SQLite 数据库可用。</div>`;
    toast("证据库加载失败", true);
  }
}

function renderAll() {
  const data = state.data;
  if (!data) return;
  $("#top-case-id").textContent = data.id;
  $("#breadcrumb-case").textContent = data.id;
  $("#nav-object-count").textContent = pad(data.stats.objects);
  $("#nav-evidence-count").textContent = pad(data.stats.evidence);
  $("#stat-objects").textContent = pad(data.stats.objects);
  $("#stat-verified").textContent = pad(data.stats.verified);
  $("#stat-indeterminate").textContent = pad(data.stats.indeterminate);
  $("#stat-evidence").textContent = data.stats.evidence;
  const coverage = data.stats.evidence ? Math.min(100, data.stats.traced / data.stats.evidence * 100) : 100;
  $("#stat-coverage-label").textContent = `${coverage.toFixed(1)}%`;
  $("#coverage-fill").style.width = `${coverage}%`;
  renderBoundaryAlert();
  renderObjects();
  renderDetail();
  renderEvidenceTable();
  renderFuzz();
  renderOperations();
  renderTemporary();
}

function renderBoundaryAlert() {
  const boundary = state.data.objects.find((obj) => obj.status === "indeterminate");
  const alert = $("#boundary-alert");
  alert.hidden = !boundary;
  if (!boundary) return;
  const note = boundary.conclusion?.boundaryNote || boundary.summary;
  $("#boundary-alert-text").textContent = `${boundary.name} · ${boundary.version} · ${note}`;
  $("#open-boundary").dataset.objectId = boundary.id;
}

function renderObjects() {
  const rows = state.data.objects.filter((obj) => {
    if (state.filter === "all") return true;
    if (state.filter === "snapshot") return obj.kind === "snapshot";
    return obj.isException || obj.status === "error";
  });
  if (!rows.some((obj) => obj.id === state.selectedId) && rows.length) {
    state.selectedId = rows[0].id;
  }
  $("#object-list").innerHTML = rows.map((obj) => objectRow(obj)).join("")
    || `<div class="empty-state">当前筛选下没有对象</div>`;
}

function objectRow(obj) {
  const status = statusInfo(obj.status);
  const selected = obj.id === state.selectedId ? " selected" : "";
  const rowClass = obj.status === "indeterminate" ? "indeterminate"
    : obj.isException ? "exception" : "verified";
  return `
    <button class="object-row ${rowClass}${selected}" type="button" data-object-id="${escapeAttr(obj.id)}">
      <span class="object-icon">${escapeHTML(obj.extension || "raw")}</span>
      <span class="object-main">
        <span class="object-name">
          <strong>${escapeHTML(obj.name)}</strong>
          <span class="version-tag">${escapeHTML(obj.version || "capture")}</span>
        </span>
        <span class="object-sub">
          <span>${kindLabel(obj.kind)}</span><i class="dot"></i>
          <span class="hash">sha256:${escapeHTML(obj.sha256.slice(0, 10))}</span>
          ${obj.isException ? '<i class="dot"></i><span>批次继续</span>' : ""}
        </span>
      </span>
      <span class="object-right">
        <span class="status-badge ${status.className}">${status.label}</span>
        <span class="object-select">${selected ? "OPEN" : "VIEW"}</span>
      </span>
    </button>`;
}

function renderDetail() {
  const obj = findObject(state.selectedId);
  const panel = $("#detail-panel");
  if (!obj) {
    panel.innerHTML = `<div class="empty-state">选择一个来源对象查看证据链</div>`;
    return;
  }
  panel.className = `panel detail-panel ${obj.status === "indeterminate" ? "is-boundary" : ""} ${obj.status === "error" ? "is-error" : ""}`;
  const conclusion = obj.conclusion || {};
  const status = statusInfo(obj.status);
  const steps = obj.steps || [];
  const snapshot = obj.snapshots?.[0] || {};
  const traceSteps = steps.slice(0, 5);
  const evidenceIDs = new Set(conclusion.evidenceIds || []);
  const keyEvidence = pickKeyEvidence(obj);

  panel.innerHTML = `
    <div class="detail-head">
      <div class="detail-symbol">${escapeHTML(obj.extension || "raw")}</div>
      <div class="detail-title-wrap">
        <div class="detail-title">
          <h2>${escapeHTML(obj.name)}</h2>
          <span class="detail-kind">${kindLabel(obj.kind)}</span>
          <span class="version-tag">${escapeHTML(obj.version || "capture")}</span>
          <span class="status-badge ${status.className}">${status.label}</span>
        </div>
        <div class="detail-locator">${escapeHTML(obj.sourceLocator)}</div>
      </div>
      <div class="detail-head-side">
        <div class="detail-actions">
          <button class="mini-btn" type="button" data-action="raw-input" data-object-id="${escapeAttr(obj.id)}">
            <svg viewBox="0 0 24 24"><path d="M5 4h14v16H5zM8 8h8M8 12h8M8 16h5"/></svg>原始输入
          </button>
          <button class="mini-btn" type="button" data-action="verify-one" data-object-id="${escapeAttr(obj.id)}">
            <svg viewBox="0 0 24 24"><path d="M20 11a8 8 0 1 0-2.3 6M20 4v7h-7"/></svg>复验
          </button>
        </div>
        <span class="muted mono" style="font-size:7px">${escapeHTML(obj.capturedAt)}</span>
      </div>
    </div>
    <div class="trace-strip">
      ${traceSteps.length ? traceSteps.map(traceNode).join("") : tracePlaceholder()}
    </div>
    <div class="detail-body">
      <div class="source-pane">
        <div class="pane-label"><span>ORIGINAL SOURCE</span><span class="source-ref">line ${snapshot.sourceLine || 1}</span></div>
        ${sourceViewer(snapshot)}
        <div class="source-caption"><strong>来源定位</strong><span>${escapeHTML(obj.sourceLocator)}</span></div>
      </div>
      <div class="verdict-pane">
        <div class="verdict-panel ${obj.status === "verified" ? "verified" : obj.status === "error" ? "error" : "boundary"}">
          <div class="verdict-head">
            <span class="verdict-mark">${verdictIcon(obj.status)}</span>
            <div>
              <div class="verdict-title">${escapeHTML(conclusion.summary || obj.summary)}</div>
              <div class="verdict-meta">verdict=${escapeHTML(conclusion.verdict || obj.status)} · confidence=${escapeHTML(conclusion.confidence || "unknown")} · evidence=${conclusion.evidenceIds?.length || 0}</div>
            </div>
          </div>
          <p class="verdict-summary">${escapeHTML(conclusion.rationale || obj.summary)}</p>
          ${conclusion.boundaryNote ? `<div class="boundary-box"><strong>BOUNDARY / KEEP</strong>${escapeHTML(conclusion.boundaryNote)}</div>` : ""}
          <div class="step-list">
            ${steps.slice(0, 5).map((step, index) => stepRow(step, index, evidenceIDs)).join("")}
          </div>
        </div>
      </div>
    </div>
    <div class="detail-foot">
      <span>${keyEvidence.length} evidence · ${Math.min(6, keyEvidence.length)} shown</span>
      <span class="hash">sha256:${escapeHTML(obj.sha256.slice(0, 18))}…</span>
      <span>${escapeHTML(obj.mediaType)} · ${formatBytes(obj.sizeBytes)}</span>
    </div>`;
}

function traceNode(step, index) {
  const bad = ["error", "unresolved"].includes(step.status);
  return `<div class="trace-node done ${bad ? "bad" : ""}">
    <span class="trace-dot">${pad(index + 1)}</span>
    <span class="trace-label">${escapeHTML(shortAction(step.action))}</span>
  </div>`;
}

function tracePlaceholder() {
  return ["capture", "parse", "canonical", "compare", "conclude"]
    .map((label, index) => `<div class="trace-node"><span class="trace-dot">${pad(index + 1)}</span><span class="trace-label">${label}</span></div>`)
    .join("");
}

function stepRow(step, index, referenced) {
  const bad = step.status === "error" || step.status === "unresolved";
  return `<div class="step-item ${bad ? "bad" : ""}">
    <span class="step-index">${index + 1}</span>
    <span>
      <span class="step-action">${escapeHTML(step.action)}</span>
      <span class="step-detail">${escapeHTML(step.detail)}</span>
    </span>
    ${step.evidenceId ? `<button class="step-evidence" type="button" data-evidence-id="${escapeAttr(step.evidenceId)}">${referenced.has(step.evidenceId) ? "linked ↗" : "evidence ↗"}</button>` : ""}
  </div>`;
}

function sourceViewer(snapshot) {
  const raw = snapshot.sourceExcerpt || "// source excerpt unavailable";
  const excerpt = raw.split("\n");
  const sourceLine = Math.max(1, Number(snapshot.sourceLine) || 1);
  const start = Math.max(1, sourceLine - 1);
  while (excerpt.length < 3) excerpt.push("");
  const highlightIndex = sourceLine - start;
  return `<div class="source-viewer">
    <div class="source-tab"><i class="file-dot"></i><span>${escapeHTML(snapshot.verifierSource || "source")}</span></div>
    <div class="source-code">
      <div class="code-lines">${excerpt.map((_, index) => start + index).join("\n")}</div>
      <pre class="code-text">${excerpt.map((line, index) => `<span class="${index === highlightIndex ? "code-highlight" : ""}">${highlightCode(line)}</span>`).join("\n")}</pre>
    </div>
  </div>`;
}

function renderEvidenceTable() {
  const obj = findObject(state.selectedId);
  const rows = obj ? pickKeyEvidence(obj).slice(0, 6) : [];
  $("#evidence-table").innerHTML = rows.map((evidence) => `
    <button class="evidence-row ${evidence.kind}" type="button" data-evidence-id="${escapeAttr(evidence.id)}" data-object-id="${escapeAttr(obj.id)}">
      <span class="evidence-icon">${evidenceIcon(evidence.kind)}</span>
      <span class="evidence-label">${escapeHTML(evidence.label)}</span>
      <span class="evidence-value">${escapeHTML(compactValue(evidence.value))}</span>
      <span class="evidence-hash">${escapeHTML(evidence.sha256.slice(0, 10))}</span>
      <span class="evidence-arrow">›</span>
    </button>`).join("") || `<div class="empty-state">该对象暂无关键证据</div>`;
}

function renderFuzz() {
  const run = state.data.fuzzRuns?.[0];
  if (!run) {
    $("#fuzz-content").innerHTML = `<div class="empty-state">尚无 fuzz 记录</div>`;
    return;
  }
  $("#fuzz-status").textContent = run.status;
  $("#fuzz-status").className = `status-badge ${run.status === "clean" ? "clean" : "warn"}`;
  $("#fuzz-content").innerHTML = `
    <div class="fuzz-metrics">
      <div class="fuzz-metric"><span>ENGINE</span><strong>${escapeHTML(run.engine)}</strong></div>
      <div class="fuzz-metric"><span>EXECUTIONS</span><strong>${Number(run.executions).toLocaleString("zh-CN")}</strong></div>
      <div class="fuzz-metric"><span>CRASHES</span><strong class="good">${run.crashes}</strong></div>
    </div>
    <div class="fuzz-artifact">
      <div class="fuzz-artifact-head"><span>artifact · ${escapeHTML(run.artifactSha256.slice(0, 12))}…</span><button class="copy-button" type="button" data-copy="${escapeAttr(run.artifactHex)}">COPY HEX</button></div>
      <code>${escapeHTML(run.artifactHex)}</code>
    </div>
    <p class="fuzz-note">${escapeHTML(run.note)}</p>`;
}

function renderOperations() {
  const ops = state.data.operations || [];
  $("#operation-list").innerHTML = ops.slice(0, 8).map((op) => `
    <div class="operation-row">
      <span class="operation-time">${escapeHTML(formatClock(op.createdAt))}</span>
      <span class="operation-detail" title="${escapeAttr(op.detail)}">${escapeHTML(op.detail)}</span>
      <span class="operation-action ${escapeAttr(op.outcome)}">${escapeHTML(op.outcome)}</span>
    </div>`).join("") || `<div class="empty-state">暂无处理日志</div>`;
}

function renderTemporary() {
  const stateRow = state.data.temporary?.[0];
  if (!stateRow) {
    $("#temp-state-title").textContent = "已清理";
    $("#temp-state-meta").textContent = "无临时复验目录";
    return;
  }
  const name = stateRow.path.split("/").filter(Boolean).pop() || stateRow.path;
  $("#temp-state-title").textContent = name;
  $("#temp-state-meta").textContent = `${stateRow.bytes} B · 等待收尾`;
}

function bindStaticEvents() {
  $("#object-list").addEventListener("click", (event) => {
    const row = event.target.closest("[data-object-id]");
    if (!row) return;
    state.selectedId = row.dataset.objectId;
    renderObjects();
    renderDetail();
    renderEvidenceTable();
    $("#detail-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
  });

  $$(".chip").forEach((chip) => chip.addEventListener("click", () => {
    $$(".chip").forEach((item) => item.classList.remove("active"));
    chip.classList.add("active");
    state.filter = chip.dataset.filter;
    renderObjects();
    renderDetail();
    renderEvidenceTable();
  }));

  $("#detail-panel").addEventListener("click", async (event) => {
    const evidenceButton = event.target.closest("[data-evidence-id]");
    if (evidenceButton) {
      openEvidence(evidenceButton.dataset.evidenceId);
      return;
    }
    const action = event.target.closest("[data-action]");
    if (!action) return;
    if (action.dataset.action === "raw-input") openRawInput(action.dataset.objectId);
    if (action.dataset.action === "verify-one") await verifyOne(action.dataset.objectId, action);
  });

  $("#evidence-table").addEventListener("click", (event) => {
    const row = event.target.closest("[data-evidence-id]");
    if (row) openEvidence(row.dataset.evidenceId);
  });

  $("#open-boundary").addEventListener("click", () => {
    const id = $("#open-boundary").dataset.objectId;
    if (!id) return;
    state.selectedId = id;
    renderObjects();
    renderDetail();
    renderEvidenceTable();
    $("#detail-panel").scrollIntoView({ behavior: "smooth", block: "center" });
  });

  $("#open-all-evidence").addEventListener("click", openAllEvidence);
  $("#recheck-all").addEventListener("click", recheckAll);
  $("#export-button").addEventListener("click", () => {
    window.location.assign("/api/export");
    toast("证据包已开始下载");
  });
  $("#cleanup-button").addEventListener("click", openCleanupModal);
  $("#modal-cancel").addEventListener("click", closeCleanupModal);
  $("#modal-confirm").addEventListener("click", cleanupTemporary);
  $("#modal-backdrop").addEventListener("click", (event) => {
    if (event.target === $("#modal-backdrop")) closeCleanupModal();
  });
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#drawer-backdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeDrawer();
      closeCleanupModal();
    }
  });
  $("#fuzz-content").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;
    await navigator.clipboard.writeText(button.dataset.copy);
    toast("Fuzz artifact hex 已复制");
  });
  $("#drawer-body").addEventListener("click", (event) => {
    const item = event.target.closest("[data-evidence-id]");
    if (item) openEvidence(item.dataset.evidenceId);
  });
}

async function recheckAll() {
  const button = $("#recheck-all");
  setBusy(button, true, "复验中…");
  try {
    const response = await fetch("/api/recheck", { method: "POST" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "复验失败");
    await loadCase();
    toast(body.message);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setBusy(button, false, "全部复验");
  }
}

async function verifyOne(id, button) {
  setBusy(button, true, "复验…");
  try {
    const response = await fetch(`/api/objects/${encodeURIComponent(id)}/verify`, { method: "POST" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "复验失败");
    await loadCase();
    toast(body.message);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setBusy(button, false, "复验");
  }
}

function openEvidence(id) {
  const obj = state.data.objects.find((candidate) => candidate.evidence.some((item) => item.id === id));
  const evidence = obj?.evidence.find((item) => item.id === id);
  if (!evidence) {
    toast("证据记录不存在", true);
    return;
  }
  const relatedSteps = obj.steps.filter((step) => step.evidenceId === id);
  const conclusion = obj.conclusion || {};
  $("#drawer-kicker").textContent = `${evidence.kind.toUpperCase()} / ${obj.name}`;
  $("#drawer-title").textContent = evidence.label;
  $("#drawer-body").innerHTML = `
    <div class="evidence-grid">
      <div class="evidence-cell"><span>EVIDENCE ID</span><strong>${escapeHTML(evidence.id)}</strong></div>
      <div class="evidence-cell"><span>CAPTURED</span><strong>${escapeHTML(formatDate(evidence.createdAt))}</strong></div>
      <div class="evidence-cell"><span>SNAPSHOT</span><strong>${escapeHTML(evidence.snapshotId || "case")}</strong></div>
      <div class="evidence-cell"><span>PARENT</span><strong>${escapeHTML(evidence.parentId || "root")}</strong></div>
    </div>
    <h3 class="drawer-section">原始值 / RAW VALUE</h3>
    <pre class="evidence-value-large">${escapeHTML(evidence.value)}</pre>
    <div class="drawer-section">
      <h3>完整性摘要 / SHA-256</h3>
      <pre class="evidence-value-large">${escapeHTML(evidence.sha256)}</pre>
    </div>
    <div class="drawer-section">
      <h3>回放到处理步骤</h3>
      ${relatedSteps.length ? relatedSteps.map((step) => `<div class="trace-linkage">
        <div><small>STEP ${pad(step.seq)}</small><code>${escapeHTML(step.action)}</code></div>
        <span>→</span>
        <div><small>${escapeHTML(step.status)}</small><code>${escapeHTML(step.outputRef)}</code></div>
      </div>`).join("") : `<div class="empty-state">该证据作为结论引用保留，未绑定单一中间步骤。</div>`}
    </div>
    <div class="drawer-section">
      <h3>结论引用</h3>
      <div class="evidence-cell"><span>${escapeHTML(conclusion.verdict || "unknown")}</span><strong>${conclusion.evidenceIds?.includes(id) ? "该证据已被结论直接引用" : "该证据为对象级保留证据"}</strong></div>
    </div>`;
  $("#drawer-backdrop").hidden = false;
  $("#evidence-drawer").classList.add("open");
  $("#evidence-drawer").setAttribute("aria-hidden", "false");
}

function openRawInput(objectId) {
  const obj = findObject(objectId);
  const raw = obj?.evidence.find((item) => item.kind === "raw_input" && item.label === "原始请求字节")
    || obj?.evidence.find((item) => item.kind === "raw_input");
  if (raw) openEvidence(raw.id);
}

function openAllEvidence() {
  const obj = findObject(state.selectedId);
  if (!obj) return;
  $("#drawer-kicker").textContent = `OBJECT / ${obj.name}`;
  $("#drawer-title").textContent = `全部证据 · ${obj.evidence.length}`;
  $("#drawer-body").innerHTML = `
    <div class="evidence-cell" style="margin-bottom:14px">
      <span>TRACE INVARIANT</span>
      <strong>结论 ${obj.conclusion?.evidenceIds?.length || 0} 条引用 · ${obj.steps.length} 个处理步骤 · ${obj.evidence.length} 条证据</strong>
    </div>
    ${obj.evidence.map((evidence) => `
      <button class="evidence-row ${evidence.kind}" type="button" data-evidence-id="${escapeAttr(evidence.id)}">
        <span class="evidence-icon">${evidenceIcon(evidence.kind)}</span>
        <span class="evidence-label">${escapeHTML(evidence.label)}</span>
        <span class="evidence-value">${escapeHTML(compactValue(evidence.value))}</span>
        <span class="evidence-hash">${escapeHTML(evidence.sha256.slice(0, 10))}</span>
        <span class="evidence-arrow">›</span>
      </button>`).join("")}`;
  $("#drawer-backdrop").hidden = false;
  $("#evidence-drawer").classList.add("open");
  $("#evidence-drawer").setAttribute("aria-hidden", "false");
}

function openCleanupModal() {
  $("#modal-backdrop").hidden = false;
  $("#modal-confirm").focus();
}

function closeCleanupModal() {
  $("#modal-backdrop").hidden = true;
}

async function cleanupTemporary() {
  const button = $("#modal-confirm");
  setBusy(button, true, "清理中…");
  try {
    const response = await fetch("/api/cleanup", { method: "POST" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "清理失败");
    closeCleanupModal();
    await loadCase();
    toast(body.message);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setBusy(button, false, "确认清理");
  }
}

function closeDrawer() {
  $("#evidence-drawer").classList.remove("open");
  $("#evidence-drawer").setAttribute("aria-hidden", "true");
  $("#drawer-backdrop").hidden = true;
}

function setBusy(button, busy, label) {
  if (!button) return;
  button.disabled = busy;
  const original = button.dataset.originalLabel || button.innerHTML;
  button.dataset.originalLabel = original;
  if (busy) {
    button.innerHTML = `<span class="pulse"></span>${escapeHTML(label)}`;
  } else {
    button.innerHTML = original;
  }
}

function toast(message, isError = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", isError);
  element.classList.add("show");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => element.classList.remove("show"), 3800);
}

function findObject(id) {
  return state.data?.objects.find((obj) => obj.id === id);
}

function statusInfo(status) {
  return {
    verified: { label: "已验证", className: "" },
    indeterminate: { label: "未决边界", className: "warn" },
    error: { label: "已隔离", className: "error" },
    pending: { label: "待处理", className: "warn" },
  }[status] || { label: status || "未知", className: "warn" };
}

function kindLabel(kind) {
  return {
    unknown_extension: "未知扩展",
    snapshot: "版本快照",
    exception: "异常隔离",
  }[kind] || kind;
}

function verdictIcon(status) {
  if (status === "verified") return `<svg viewBox="0 0 24 24"><path d="m6 12 4 4 8-8"/></svg>`;
  if (status === "error") return `<svg viewBox="0 0 24 24"><path d="M7 7l10 10M17 7 7 17"/></svg>`;
  return `<svg viewBox="0 0 24 24"><path d="M12 8v5m0 3v.01M10.3 4.6 3.1 17a2 2 0 0 0 1.7 3h14.4a2 2 0 0 0 1.7-3L13.7 4.6a2 2 0 0 0-3.4 0Z"/></svg>`;
}

function evidenceIcon(kind) {
  if (kind === "boundary") return `<svg viewBox="0 0 24 24"><path d="M12 8v5m0 3v.01M10.3 4.6 3.1 17a2 2 0 0 0 1.7 3h14.4a2 2 0 0 0 1.7-3L13.7 4.6a2 2 0 0 0-3.4 0Z"/></svg>`;
  if (kind === "exception") return `<svg viewBox="0 0 24 24"><path d="M7 7l10 10M17 7 7 17"/></svg>`;
  if (kind === "raw_input") return `<svg viewBox="0 0 24 24"><path d="M5 4h14v16H5zM8 8h8M8 12h8M8 16h5"/></svg>`;
  return `<svg viewBox="0 0 24 24"><path d="m12 3 7 4v5c0 4.4-2.9 7.5-7 9-4.1-1.5-7-4.6-7-9V7z"/><path d="m9 12 2 2 4-4"/></svg>`;
}

function pickKeyEvidence(obj) {
  const priorities = [
    "原始请求字节", "签名字段原文", "原始字节 SHA-256", "Canonical string",
    "HMAC-SHA256 重算", "时钟偏差观察", "隔离原因", "内容类型探测", "恒时比较结果",
  ];
  return [...obj.evidence].sort((a, b) => {
    const left = priorities.indexOf(a.label);
    const right = priorities.indexOf(b.label);
    return (left < 0 ? 99 : left) - (right < 0 ? 99 : right);
  });
}

function shortAction(action) {
  return {
    "捕获原始输入": "capture",
    "解析签名信封": "parse",
    "构造 canonical string": "canonical",
    "HMAC-SHA256 比对": "compare",
    "检查 300s 时间窗": "boundary",
    "保留边界证据": "keep",
    "探测内容类型": "sniff",
    "隔离异常并继续": "isolate",
    "写入结论与证据链": "store",
  }[action] || action;
}

function compactValue(value) {
  const compact = String(value).replace(/\s+/g, " ").trim();
  return compact.length > 94 ? `${compact.slice(0, 94)}…` : compact;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    timeZone: "UTC", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  }).format(date) + " UTC";
}

function formatClock(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toISOString().slice(11, 19);
}

function pad(value) {
  return String(value).padStart(2, "0");
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[character]));
}

function escapeAttr(value) {
  return escapeHTML(value).replace(/\n/g, "&#10;");
}

function highlightCode(line) {
  let escaped = escapeHTML(line);
  escaped = escaped.replace(/\b(if|return|time|func|err|nil|true|false)\b/g, '<span class="kw">$1</span>');
  escaped = escaped.replace(/(&quot;[^&]*?&quot;)/g, '<span class="str">$1</span>');
  escaped = escaped.replace(/\b(300|0|1|64)\b/g, '<span class="num">$1</span>');
  escaped = escaped.replace(/\b(hmac\.Equal|verifyHMAC|time\.Unix|now\.Sub)\b/g, '<span class="fn">$1</span>');
  return escaped;
}
