const state = {
  detail: null,
  decision: null,
  busy: false,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const statusLabels = {
  needs_review: "待人工确认",
  confirmed: "已人工确认",
  auto_only: "自动结论 · 未确认",
};

const decisionLabels = {
  confirmed: "差异成立",
  rejected: "判为误报",
  undecidable: "保留为不可判定",
};

document.addEventListener("DOMContentLoaded", () => {
  bindGlobalActions();
  loadCase();
});

async function loadCase() {
  try {
    const response = await fetch("/api/case", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(await apiError(response));
    state.detail = await response.json();
    for (const key of ["evidence", "steps", "findings", "reviews", "followups", "replays"]) {
      if (!Array.isArray(state.detail[key])) state.detail[key] = [];
    }
    renderAll();
  } catch (error) {
    renderLoadFailure(error);
    toast("无法读取案件", `${error.message}。请确认 Go 服务与 SQLite 文件可用后重试。`, "error");
  }
}

function renderAll() {
  renderCase();
  renderMetrics();
  renderFindings();
  renderManual();
  renderDiff();
  renderRaw();
  renderTimeline();
  renderEvidence();
  renderFollowups();
}

function renderCase() {
  const { case: item, findings, evidence, reviews } = state.detail;
  $("#case-id").textContent = item.id;
  $("#crumb-case").textContent = item.id;
  const pill = $("#case-status");
  pill.className = "status-pill " + (item.status === "auto_only" ? "auto-only" : item.status === "confirmed" ? "confirmed" : "");
  pill.innerHTML = `<i></i>${escapeHTML(statusLabels[item.status] || item.status)}`;
  $("#auto-count").textContent = `${findings.length} 项发现`;
  $("#evidence-count").textContent = String(evidence.length);
  $("#case-revision").textContent = `rev ${state.detail.revision}`;
  $("#foot-updated").textContent = timeLabel(state.detail.case.updatedAt) + " +08:00";
  $("#metric-evidence").textContent = pad2(evidence.length);
  $("#metric-findings").textContent = pad2(findings.length);
  $("#metric-reviews").textContent = pad2(Math.min(reviews.length, findings.length));
}

function renderMetrics() {
  const { findings, reviews, replays } = state.detail;
  const latest = reviews[0];
  const reviewState = $("#metric-review-state");
  if (latest) {
    const tone = latest.decision === "confirmed" ? "green" : latest.decision === "rejected" ? "muted" : "amber";
    reviewState.innerHTML = `<span class="dot ${tone}"></span>${escapeHTML(decisionLabels[latest.decision] || latest.decision)}`;
  } else {
    reviewState.innerHTML = `<span class="dot muted"></span>等待独立复核`;
  }
  const latestReplay = replays[0];
  if (latestReplay) {
    $("#metric-replay").textContent = `#${pad2(latestReplay.attempt)}`;
    $("#metric-replay-state").textContent = latestReplay.status === "succeeded" ? "成功" : "失败";
    $("#metric-replay-time").textContent = `${timeLabel(latestReplay.finishedAt)} +08:00`;
  }
  $("#auto-step-count").textContent = String(state.detail.steps.filter((step) => ["decode", "normalize", "extension", "boundary"].includes(step.kind)).length);
}

function renderFindings() {
  const root = $("#auto-findings");
  const findings = state.detail.findings;
  if (!findings.length) {
    root.innerHTML = emptyState("尚未生成自动结论");
    return;
  }
  root.innerHTML = findings.map((finding) => `
    <article class="finding ${escapeAttr(finding.severity)}" id="finding-${escapeAttr(finding.id)}">
      <div class="finding-head">
        <div>
          <span class="finding-id">${escapeHTML(finding.id)} · ${finding.severity === "high" ? "HIGH" : "MEDIUM"}</span>
          <h4>${escapeHTML(finding.title)}</h4>
        </div>
        <div class="confidence">
          <div class="confidence-ring" style="--score:${Number(finding.confidence) || 0}"><span>${Number(finding.confidence) || 0}%</span></div>
          <small>置信度</small>
        </div>
      </div>
      <p>${escapeHTML(finding.detail)}</p>
      <div class="finding-refs">
        <span class="ref-label">EVIDENCE</span>
        ${finding.refs.map((ref) => `<button class="ref-chip" data-ref="${escapeAttr(ref)}">${escapeHTML(ref)}</button>`).join("")}
      </div>
      <div class="finding-foot"><svg><use href="#i-check"/></svg>规则复算通过 · ${formatDateTime(finding.createdAt)}</div>
    </article>
  `).join("");
}

function renderManual() {
  const reviews = state.detail.reviews;
  const latest = reviews[0];
  const stateChip = $("#human-state");
  if (latest) {
    const tone = latest.decision === "confirmed" ? "done" : latest.decision === "undecidable" ? "" : "done";
    stateChip.className = "review-state " + tone;
    stateChip.innerHTML = `<i></i>${escapeHTML(decisionLabels[latest.decision] || latest.decision)}`;
  } else {
    stateChip.className = "review-state";
    stateChip.innerHTML = "<i></i>待复核";
  }

  const history = $("#manual-history");
  if (!latest) {
    history.hidden = true;
    history.innerHTML = "";
  } else {
    history.hidden = false;
    history.innerHTML = `
      <div class="review-record">
        <strong>人工确认 · ${escapeHTML(decisionLabels[latest.decision] || latest.decision)}</strong>
        <p>${latest.note ? escapeHTML(latest.note) : "未填写复核备注。"}</p>
        <small>${escapeHTML(latest.reviewer)} · ${formatDateTime(latest.createdAt)} · ${escapeHTML(latest.id)}</small>
      </div>`;
  }

  $$(".decision-choice").forEach((button) => {
    button.classList.toggle("selected", button.dataset.decision === state.decision);
  });
  $("#save-review").disabled = !state.decision || state.busy;
}

function renderDiff() {
  const root = $("#path-diff");
  const evidence = evidenceMap();
  const raw = evidence.get("EV-RAW")?.content || "";
  const decoded = evidence.get("EV-DECODE")?.content || "";
  const legacy = evidence.get("EV-LEGACY")?.content || "";
  const hardened = evidence.get("EV-HARDENED")?.content || "";
  if (!legacy || !hardened) {
    root.innerHTML = emptyState("缺少规范化输出证据");
    return;
  }
  const lengthDelta = Math.abs(legacy.length - hardened.length);
  root.innerHTML = `
    <div class="canonical-flow">
      <div class="flow-source">
        <span>RAW · ${byteLength(raw)}B</span>
        <code>${escapeHTML(raw)}</code>
      </div>
      <div class="flow-divider"><span>percent-decode ×1 · separator-fold disabled</span><svg><use href="#i-arrow"/></svg></div>
      <div class="result-stack">
        <div class="result-row legacy">
          <div class="result-backend"><b>legacy.Resolve</b><small>lexical clean</small></div>
          <div class="result-path">${pathSegments(legacy, "legacy")}</div>
          <span class="result-flag escape"><svg><use href="#i-alert"/></svg>越过根界</span>
        </div>
        <div class="result-row hardened">
          <div class="result-backend"><b>hardened.Resolve</b><small>root clamp</small></div>
          <div class="result-path">${pathSegments(hardened, "hardened")}</div>
          <span class="result-flag safe"><svg><use href="#i-check"/></svg>根内</span>
        </div>
      </div>
      <div class="diff-divergence">首个分歧位于 <b>/srv</b> 之后 · decoded=${escapeHTML(decoded)}</div>
    </div>`;
  const flag = $(".diff-flag");
  if (flag) flag.innerHTML = `<svg><use href="#i-alert"/></svg>${lengthDelta} 字节长度差`;
  const foot = $(".diff-foot span:nth-child(2)");
  if (foot) foot.innerHTML = `根界策略不同：<code>legacy</code> 词法越界，<code>hardened</code> 钳制在 <code>/srv/www</code>`;
}

function pathSegments(value, mode) {
  const parts = value.split("/").filter(Boolean);
  const escIndex = mode === "legacy" ? 1 : -1;
  return parts.map((part, index) => {
    let cls = "";
    if (index === escIndex) cls = "escape";
    if (part.endsWith(".unk9")) cls += " unknown";
    return `<span class="seg ${cls.trim()}">/${escapeHTML(part)}</span>`;
  }).join("");
}

function renderRaw() {
  const evidence = evidenceMap();
  const raw = evidence.get("EV-RAW");
  if (!raw) {
    $("#raw-code").innerHTML = emptyState("原始证据缺失");
    return;
  }
  const pattern = /(%2e%2e|%2E%2E|\.unk9)/gi;
  let cursor = 0;
  let html = "";
  for (const match of raw.content.matchAll(pattern)) {
    html += `<span class="tok-plain">${escapeHTML(raw.content.slice(cursor, match.index))}</span>`;
    const tokenClass = match[0].toLowerCase().startsWith("%") ? "tok-dot" : "tok-ext";
    html += `<span class="${tokenClass}">${escapeHTML(match[0])}</span>`;
    cursor = match.index + match[0].length;
  }
  html += `<span class="tok-plain">${escapeHTML(raw.content.slice(cursor))}</span><i class="caret"></i>`;
  $("#raw-code").innerHTML = html;
  $("#raw-size").textContent = String(raw.size);
  $("#raw-hash").textContent = raw.sha256;
}

function renderTimeline() {
  const root = $("#timeline");
  const steps = state.detail.steps;
  if (!steps.length) {
    root.innerHTML = emptyState("尚无可追溯的处理步骤");
    return;
  }
  $("#step-count").textContent = String(steps.length);
  const icons = {
    corpus: "i-file",
    recovery: "i-alert",
    replay: "i-replay",
    decode: "i-terminal",
    normalize: "i-layers",
    extension: "i-rules",
    boundary: "i-clock",
  };
  root.innerHTML = steps.map((step) => {
    const icon = icons[step.kind] || "i-check";
    const failed = step.status === "failed";
    const followup = failed ? findFollowup("FU-01") : null;
    return `
      <article class="timeline-item ${escapeAttr(step.status)}" id="step-${escapeAttr(step.id)}" data-step-id="${escapeAttr(step.id)}">
        <div class="timeline-node ${escapeAttr(step.status)}"><svg><use href="#${icon}"/></svg></div>
        <div class="timeline-content">
          <div class="timeline-top">
            <div class="timeline-title-line">
              <span class="step-id">${escapeHTML(step.id)}</span>
              <span class="step-kind">${escapeHTML(step.kind)}</span>
              <h4>${escapeHTML(step.title)}</h4>
            </div>
            <span class="timeline-time">${timeLabel(step.occurredAt)}</span>
          </div>
          <p class="timeline-detail">${escapeHTML(step.detail)}</p>
          ${step.output ? `<div class="timeline-output"><svg><use href="#i-terminal"/></svg><span>${escapeHTML(step.output)}</span></div>` : ""}
          ${failed && followup ? `
            <div class="failure-inline">
              <div class="failure-inline-head"><span><svg><use href="#i-alert"/></svg>失败处置 · ${escapeHTML(followup.id)}</span><span>${escapeHTML(followup.status)}</span></div>
              <p>${escapeHTML(followup.reason)}</p>
              <code>${escapeHTML(followup.commands[0] || "")}</code>
              <button data-copy="${escapeAttr(followup.commands[0] || "")}">复制处置命令</button>
            </div>` : ""}
          <div class="timeline-refs">
            ${step.refs.map((ref) => `<button class="ref-chip" data-ref="${escapeAttr(ref)}">${escapeHTML(ref)}</button>`).join("")}
            <button class="step-open" data-open-step="${escapeAttr(step.id)}">步骤详情 ↗</button>
          </div>
        </div>
      </article>`;
  }).join("");
}

function renderEvidence() {
  const root = $("#evidence-list");
  const evidence = state.detail.evidence;
  if (!evidence.length) {
    root.innerHTML = emptyState("证据索引为空");
    return;
  }
  root.innerHTML = evidence.map((item) => `
    <button class="evidence-item" data-evidence-id="${escapeAttr(item.id)}">
      <span class="ev-icon"><svg><use href="#${item.kind === "log" ? "i-terminal" : item.kind === "corpus" ? "i-file" : "i-layers"}"/></svg></span>
      <span class="ev-copy">
        <span class="ev-title">${escapeHTML(item.label)}</span>
        <span class="ev-meta"><span>${escapeHTML(item.id)}</span><span>${item.size} B</span><span>${escapeHTML(item.kind)}</span></span>
      </span>
      <span class="ev-seal" title="不可变证据"><svg><use href="#i-lock"/></svg></span>
    </button>`).join("");
}

function renderFollowups() {
  const root = $("#followup-list");
  const items = state.detail.followups;
  const open = items.filter((item) => item.status !== "resolved");
  $("#followup-count").innerHTML = `<i></i>${open.length} open`;
  if (!items.length) {
    root.innerHTML = emptyState("没有待执行处置");
    return;
  }
  root.innerHTML = items.map((item) => `
    <article class="followup-item" id="followup-${escapeAttr(item.id)}">
      <div class="followup-line">
        <span class="followup-state ${escapeAttr(item.status)}">${escapeHTML(item.status.toUpperCase())}</span>
        <h4>${escapeHTML(item.id)} · ${escapeHTML(item.title)}</h4>
      </div>
      <p>${escapeHTML(item.reason)}</p>
      ${item.commands[0] ? `<code class="followup-cmd">${escapeHTML(item.commands[0])}<button class="followup-copy" data-copy="${escapeAttr(item.commands[0])}" title="复制命令"><svg><use href="#i-copy"/></svg></button></code>` : ""}
      <div class="followup-actions">
        <span class="followup-owner">${escapeHTML(item.owner)}</span>
        <button class="inline-action" data-followup-detail="${escapeAttr(item.id)}">${item.status === "resolved" ? "查看处置记录" : "查看全部命令"}</button>
      </div>
    </article>`).join("");
}

function bindGlobalActions() {
  $("#export-button").addEventListener("click", () => {
    window.location.assign("/api/export");
  });
  $("#rerun-button").addEventListener("click", rerunReplay);
  $("#health-button").addEventListener("click", checkHealth);
  $("#copy-raw").addEventListener("click", () => {
    const evidence = evidenceMap().get("EV-RAW");
    if (evidence) copyText(evidence.content, "原始输入已复制");
  });
  $("#trace-locate").addEventListener("click", () => {
    locateStep("S-04");
    toast("已定位差异来源", "S-04 legacy.Resolve 首次越过 /srv/www 根界。", "success");
  });
  $("#show-failed").addEventListener("click", () => locateStep("S-01", true));
  $("#copy-boundary").addEventListener("click", copyBoundaryCommand);
  $("#queue-boundary").addEventListener("click", queueBoundaryWork);
  $("#save-review").addEventListener("click", saveReview);

  $$(".decision-choice").forEach((button) => {
    button.addEventListener("click", () => {
      state.decision = button.dataset.decision;
      renderManual();
    });
  });

  $("#dialog-close").addEventListener("click", () => $("#detail-dialog").close());
  $("#detail-dialog").addEventListener("click", (event) => {
    if (event.target === $("#detail-dialog")) $("#detail-dialog").close();
  });

  document.addEventListener("click", handleDelegatedClick);
}

function handleDelegatedClick(event) {
  const refButton = event.target.closest("[data-ref]");
  if (refButton) {
    event.preventDefault();
    handleReference(refButton.dataset.ref);
    return;
  }
  const locateButton = event.target.closest("[data-locate-step]");
  if (locateButton) {
    event.preventDefault();
    locateStep(locateButton.dataset.locateStep, true);
    return;
  }
  const openStep = event.target.closest("[data-open-step]");
  if (openStep) {
    event.preventDefault();
    openStepDialog(openStep.dataset.openStep);
    return;
  }
  const evidenceButton = event.target.closest("[data-evidence-id]");
  if (evidenceButton) {
    event.preventDefault();
    openEvidenceDialog(evidenceButton.dataset.evidenceId);
    return;
  }
  const copyButton = event.target.closest("[data-copy]");
  if (copyButton) {
    event.preventDefault();
    event.stopPropagation();
    copyText(copyButton.dataset.copy, "命令已复制到剪贴板");
    return;
  }
  const followupButton = event.target.closest("[data-followup-detail]");
  if (followupButton) {
    event.preventDefault();
    openFollowupDialog(followupButton.dataset.followupDetail);
    return;
  }
  const markFollowup = event.target.closest("[data-mark-followup]");
  if (markFollowup) {
    event.preventDefault();
    updateFollowupFromDialog(markFollowup.dataset.markFollowup);
    return;
  }
  const retry = event.target.closest("[data-retry-load]");
  if (retry) {
    event.preventDefault();
    loadCase();
  }
}

async function rerunReplay() {
  if (state.busy) return;
  const button = $("#rerun-button");
  state.busy = true;
  setButtonBusy(button, true, "正在重放…");
  setDBState("busy", "写入 SQLite…");
  try {
    const response = await fetch("/api/replay", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: "{}",
    });
    if (!response.ok) throw new Error(await apiError(response));
    const payload = await response.json();
    state.detail = payload.case;
    state.busy = false;
    renderAll();
    setDBState("ok", "SQLite 已同步");
    toast(
      `重放 #${pad2(payload.result.replay.attempt)} 已完成`,
      `${payload.result.extensionSeen} · legacy ${payload.result.legacyPath} / hardened ${payload.result.hardenedPath}`,
      "success",
    );
    openReplayResultDialog(payload.result);
  } catch (error) {
    state.busy = false;
    setDBState("error", "写入失败");
    showActionFailure("恢复重放失败", error.message, [
      `curl -s http://localhost:8080/api/health`,
      `sqlite3 data/pathscope.db "PRAGMA integrity_check;"`,
      `./pathnorm_fuzz -runs=1 artifacts/corpus/recovered/minimized-01`,
    ]);
    toast("重放未写入", "案件数据未改动。请按故障单检查 SQLite 与语料文件。", "error");
  } finally {
    state.busy = false;
    setButtonBusy(button, false);
    renderManual();
  }
}

async function saveReview() {
  if (!state.decision || state.busy) return;
  const button = $("#save-review");
  const note = $("#review-note").value.trim();
  state.busy = true;
  setButtonBusy(button, true, "写入中…");
  try {
    const response = await fetch("/api/reviews", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ decision: state.decision, reviewer: "林岚", note }),
    });
    if (!response.ok) throw new Error(await apiError(response));
    const payload = await response.json();
    state.detail = payload.case;
    state.decision = null;
    $("#review-note").value = "";
    state.busy = false;
    renderAll();
    toast("人工确认已写入", `${payload.review.id} · 只追加到 reviews，不覆盖自动结论。`, "success");
  } catch (error) {
    state.busy = false;
    renderManual();
    showActionFailure("人工确认写入失败", error.message, [
      `curl -s http://localhost:8080/api/health`,
      `sqlite3 data/pathscope.db ".schema reviews"`,
      `ls -l data/pathscope.db data/pathscope.db-wal`,
    ]);
    toast("人工确认未保存", "自动结论保持不变。检查 SQLite 可写状态后可重试。", "error");
  } finally {
    state.busy = false;
    setButtonBusy(button, false);
    renderManual();
  }
}

async function checkHealth() {
  setDBState("busy", "检查中…");
  try {
    const response = await fetch("/api/health", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(await apiError(response));
    const payload = await response.json();
    setDBState("ok", "SQLite 已同步");
    toast("SQLite 健康", `WAL 可写 · ${payload.caseId} · ${payload.sqliteTimeUTC} UTC`, "success");
  } catch (error) {
    setDBState("error", "连接异常");
    showActionFailure("SQLite 健康检查失败", error.message, [
      `curl -s http://localhost:8080/api/health`,
      `sqlite3 data/pathscope.db "PRAGMA integrity_check;"`,
      `ls -l data/pathscope.db data/pathscope.db-wal`,
    ]);
  }
}

async function queueBoundaryWork() {
  const followup = findFollowup("FU-02");
  if (!followup) return;
  const button = $("#queue-boundary");
  setButtonBusy(button, true, "登记中…");
  try {
    const response = await fetch(`/api/followups/${encodeURIComponent(followup.id)}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ status: "in_progress" }),
    });
    if (!response.ok) throw new Error(await apiError(response));
    const payload = await response.json();
    state.detail.followups = state.detail.followups.map((item) => item.id === payload.followup.id ? payload.followup : item);
    renderFollowups();
    $("#boundary-action-note").textContent = `${payload.followup.id} · 已登记执行 · ${payload.followup.owner}`;
    toast("后续操作已登记", "FU-02 已转为 in_progress，并保留 symlink 补采命令。", "success");
  } catch (error) {
    showActionFailure("登记后续操作失败", error.message, [
      `curl -s http://localhost:8080/api/health`,
      `sqlite3 data/pathscope.db "SELECT id,status FROM followups ORDER BY id;"`,
    ]);
  } finally {
    setButtonBusy(button, false);
  }
}

function copyBoundaryCommand() {
  const followup = findFollowup("FU-02");
  if (!followup) return;
  copyText(followup.commands.join("\n"), "根边界补采命令已复制");
}

function copyText(text, message) {
  if (!text) return;
  const complete = () => toast("已复制", message, "success");
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(complete).catch(() => fallbackCopy(text, complete));
  } else {
    fallbackCopy(text, complete);
  }
}

function fallbackCopy(text, complete) {
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  area.remove();
  complete();
}

function handleReference(ref) {
  if (!ref) return;
  if (ref.startsWith("S-")) {
    locateStep(ref, true);
    return;
  }
  if (ref.startsWith("EV-")) {
    openEvidenceDialog(ref);
    return;
  }
  if (ref.startsWith("FU-")) {
    openFollowupDialog(ref);
    return;
  }
  if (ref.startsWith("REPLAY-")) {
    const replay = state.detail.replays.find((item) => item.id === ref);
    if (replay) openReplayDialog(replay);
    return;
  }
  if (ref.startsWith("AUTO-")) {
    const finding = $(`#finding-${ref}`);
    if (finding) {
      finding.scrollIntoView({ behavior: "smooth", block: "center" });
      finding.style.outline = "2px solid #c7a66c";
      finding.style.outlineOffset = "-2px";
      setTimeout(() => { finding.style.outline = ""; }, 1800);
    }
  }
}

function locateStep(stepId, open = false) {
  const element = $(`#step-${stepId}`);
  if (!element) return;
  element.scrollIntoView({ behavior: "smooth", block: "center" });
  element.classList.add("highlight");
  setTimeout(() => element.classList.remove("highlight"), 2600);
  if (open) openStepDialog(stepId);
}

function openStepDialog(stepId) {
  const step = findStep(stepId);
  if (!step) return;
  const evidence = step.evidenceId ? findEvidence(step.evidenceId) : null;
  const body = `
    <section class="dialog-section">
      <span>PROCESSING NOTE</span>
      <p>${escapeHTML(step.detail)}</p>
    </section>
    <section class="dialog-section">
      <span>TRACE METADATA</span>
      <dl class="dialog-kv">
        <dt>step</dt><dd>${escapeHTML(step.id)} · ${escapeHTML(step.kind)}</dd>
        <dt>status</dt><dd>${escapeHTML(step.status)}</dd>
        <dt>occurred</dt><dd>${escapeHTML(step.occurredAt)}</dd>
        <dt>evidence</dt><dd>${escapeHTML(step.evidenceId || "未绑定")}${evidence ? " · " + escapeHTML(evidence.sha256.slice(0, 24)) + "…" : ""}</dd>
        <dt>references</dt><dd>${step.refs.map(escapeHTML).join(" · ") || "—"}</dd>
      </dl>
    </section>
    ${step.command ? `
      <section class="dialog-section">
        <span>COMMAND</span>
        <pre class="dialog-code">${escapeHTML(step.command)}</pre>
      </section>` : ""}
    ${step.output ? `
      <section class="dialog-section">
        <span>RECORDED OUTPUT</span>
        <pre class="dialog-code">${escapeHTML(step.output)}</pre>
      </section>` : ""}
    <div class="dialog-actions">
      ${step.command ? `<button class="btn btn-ghost btn-small" data-copy="${escapeAttr(step.command)}"><svg><use href="#i-copy"/></svg>复制命令</button>` : ""}
      ${step.evidenceId ? `<button class="btn btn-dark btn-small" data-evidence-id="${escapeAttr(step.evidenceId)}">查看证据</button>` : ""}
    </div>`;
  showDialog("STEP DETAIL", `${step.id} · ${step.title}`, body);
}

function openEvidenceDialog(evidenceId) {
  const evidence = findEvidence(evidenceId);
  if (!evidence) return;
  const body = `
    <section class="dialog-section">
      <span>SEALED CONTENT</span>
      <pre class="dialog-code">${escapeHTML(evidence.content)}</pre>
    </section>
    <section class="dialog-section">
      <span>PROVENANCE</span>
      <dl class="dialog-kv">
        <dt>evidence</dt><dd>${escapeHTML(evidence.id)} · ${escapeHTML(evidence.kind)}</dd>
        <dt>origin</dt><dd>${escapeHTML(evidence.origin)}</dd>
        <dt>captured</dt><dd>${escapeHTML(evidence.capturedAt)}</dd>
        <dt>bytes</dt><dd>${evidence.size}</dd>
        <dt>sha-256</dt><dd>${escapeHTML(evidence.sha256)}</dd>
        <dt>immutable</dt><dd>${evidence.immutable ? "yes · append-only store" : "no"}</dd>
      </dl>
    </section>
    <div class="dialog-actions">
      <button class="btn btn-ghost btn-small" data-copy="${escapeAttr(evidence.content)}"><svg><use href="#i-copy"/></svg>复制原始内容</button>
      <button class="btn btn-dark btn-small" data-copy="${escapeAttr(evidence.sha256)}"><svg><use href="#i-fingerprint"/></svg>复制 SHA-256</button>
    </div>`;
  showDialog("EVIDENCE SEAL", `${evidence.id} · ${evidence.label}`, body);
}

function openFollowupDialog(followupId) {
  const item = findFollowup(followupId);
  if (!item) return;
  const body = `
    <section class="dialog-section">
      <span>WHY THIS EXISTS</span>
      <p>${escapeHTML(item.reason)}</p>
    </section>
    <section class="dialog-section">
      <span>RUNBOOK · ${escapeHTML(item.status.toUpperCase())}</span>
      <dl class="dialog-kv">
        <dt>follow-up</dt><dd>${escapeHTML(item.id)} · ${escapeHTML(item.title)}</dd>
        <dt>owner</dt><dd>${escapeHTML(item.owner)}</dd>
        <dt>created</dt><dd>${escapeHTML(item.createdAt)}</dd>
      </dl>
    </section>
    ${item.commands.map((command, index) => `
      <section class="dialog-section">
        <span>COMMAND ${index + 1}</span>
        <pre class="dialog-code">${escapeHTML(command)}</pre>
      </section>`).join("")}
    <div class="dialog-actions">
      <button class="btn btn-ghost btn-small" data-copy="${escapeAttr(item.commands.join("\n"))}"><svg><use href="#i-copy"/></svg>复制全部</button>
      ${item.status !== "resolved" ? `<button class="btn btn-dark btn-small" data-mark-followup="${escapeAttr(item.id)}">登记为执行中</button>` : ""}
    </div>`;
  showDialog("FAILURE RUNBOOK", `${item.id} · ${item.title}`, body);
}

function openReplayDialog(replay) {
  const body = `
    <section class="dialog-section">
      <span>REPLAY RESULT</span>
      <dl class="dialog-kv">
        <dt>replay</dt><dd>${escapeHTML(replay.id)} · attempt ${replay.attempt}</dd>
        <dt>status</dt><dd>${escapeHTML(replay.status)} · exit ${replay.exitCode}</dd>
        <dt>started</dt><dd>${escapeHTML(replay.startedAt)}</dd>
        <dt>finished</dt><dd>${escapeHTML(replay.finishedAt)}</dd>
        <dt>command</dt><dd>${escapeHTML(replay.command)}</dd>
      </dl>
    </section>
    <section class="dialog-section">
      <span>STDOUT</span>
      <pre class="dialog-code">${escapeHTML(replay.stdout || replay.stderr || "No output recorded.")}</pre>
    </section>
    <div class="dialog-actions">
      <button class="btn btn-ghost btn-small" data-copy="${escapeAttr(replay.command)}"><svg><use href="#i-copy"/></svg>复制重放命令</button>
      <button class="btn btn-dark btn-small" data-locate-step="S-02">查看来源步骤</button>
    </div>`;
  showDialog("RECOVERY REPLAY", `${replay.id} · 恢复后重放`, body);
}

function openReplayResultDialog(result) {
  const body = `
    <section class="dialog-section">
      <span>REPLAY RESULT · WRITTEN TO SQLITE</span>
      <dl class="dialog-kv">
        <dt>replay</dt><dd>${escapeHTML(result.replay.id)} · attempt ${result.replay.attempt}</dd>
        <dt>input match</dt><dd>${result.matchedInput ? "yes · SHA-256 matched" : "no"}</dd>
        <dt>decoded</dt><dd>${escapeHTML(result.decoded)}</dd>
        <dt>legacy</dt><dd>${escapeHTML(result.legacyPath)}</dd>
        <dt>hardened</dt><dd>${escapeHTML(result.hardenedPath)}</dd>
        <dt>extension</dt><dd>${escapeHTML(result.extension)} · ${escapeHTML(result.extensionSeen)}</dd>
        <dt>diverged</dt><dd>${result.diverged ? "yes · root boundary differs" : "no"}</dd>
      </dl>
    </section>
    <section class="dialog-section">
      <span>PROCESSING CHAIN</span>
      <pre class="dialog-code">${escapeHTML(result.steps.map((step, i) => `${String(i + 1).padStart(2, "0")}  ${step}`).join("\n"))}</pre>
    </section>
    <div class="dialog-actions">
      <button class="btn btn-ghost btn-small" data-copy="${escapeAttr(result.replay.command)}"><svg><use href="#i-copy"/></svg>复制命令</button>
      <button class="btn btn-dark btn-small" data-open-step="S-02">查看重放来源链</button>
    </div>`;
  showDialog("RECOVERY REPLAY", `重放 #${pad2(result.replay.attempt)} 已完成`, body);
}

function showActionFailure(title, message, commands) {
  const body = `
    <div class="error-banner">
      <svg><use href="#i-alert"/></svg>
      <div><b>${escapeHTML(title)}</b><p>${escapeHTML(message)}</p></div>
    </div>
    <section class="dialog-section">
      <span>ACTIONABLE FOLLOW-UP</span>
      <p>先确认服务与 SQLite 状态，再按顺序执行以下命令；原始证据不会被修改。</p>
    </section>
    ${commands.map((command, index) => `
      <section class="dialog-section">
        <span>RECOVERY COMMAND ${index + 1}</span>
        <pre class="dialog-code">${escapeHTML(command)}</pre>
      </section>`).join("")}
    <div class="dialog-actions">
      <button class="btn btn-ghost btn-small" data-copy="${escapeAttr(commands.join("\n"))}"><svg><use href="#i-copy"/></svg>复制全部</button>
      <button class="btn btn-dark btn-small" data-retry-load>重新读取案件</button>
    </div>`;
  showDialog("FAILURE RUNBOOK", title, body);
}

function showDialog(kicker, title, body) {
  const dialog = $("#detail-dialog");
  $("#dialog-kicker").textContent = kicker;
  $("#dialog-title").textContent = title;
  $("#dialog-body").innerHTML = body;
  if (!dialog.open) dialog.showModal();
}

async function updateFollowupFromDialog(followupId) {
  const item = findFollowup(followupId);
  if (!item) return;
  try {
    const response = await fetch(`/api/followups/${encodeURIComponent(followupId)}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ status: "in_progress" }),
    });
    if (!response.ok) throw new Error(await apiError(response));
    const payload = await response.json();
    state.detail.followups = state.detail.followups.map((entry) => entry.id === followupId ? payload.followup : entry);
    renderFollowups();
    $("#boundary-action-note").textContent = `${payload.followup.id} · 已登记执行 · ${payload.followup.owner}`;
    $("#detail-dialog").close();
    toast("后续操作已登记", `${followupId} 已转为 in_progress。`, "success");
  } catch (error) {
    showActionFailure("登记后续操作失败", error.message, [
      `curl -s http://localhost:8080/api/health`,
      `sqlite3 data/pathscope.db "SELECT id,status FROM followups ORDER BY id;"`,
    ]);
  }
}

function findStep(id) {
  return state.detail?.steps.find((item) => item.id === id);
}

function findEvidence(id) {
  return state.detail?.evidence.find((item) => item.id === id);
}

function findFollowup(id) {
  return state.detail?.followups.find((item) => item.id === id);
}

function evidenceMap() {
  return new Map((state.detail?.evidence || []).map((item) => [item.id, item]));
}

function setDBState(tone, label) {
  const element = $("#db-state");
  element.className = "db-state" + (tone === "ok" ? "" : " " + tone);
  element.innerHTML = `<i></i><span>${escapeHTML(label)}</span>`;
}

function setButtonBusy(button, busy, label = "") {
  if (!button) return;
  if (busy) {
    if (!button.dataset.originalHtml) button.dataset.originalHtml = button.innerHTML;
    button.disabled = true;
    button.classList.add("loading");
    button.innerHTML = `<svg class="spin"><use href="#i-replay"/></svg>${escapeHTML(label)}`;
  } else {
    if (button.dataset.originalHtml) button.innerHTML = button.dataset.originalHtml;
    button.disabled = false;
    button.classList.remove("loading");
  }
}

function toast(title, message, type = "success") {
  const root = $("#toast-region");
  const item = document.createElement("div");
  item.className = `toast ${type}`;
  item.innerHTML = `
    <svg><use href="#${type === "error" ? "i-alert" : "i-check"}"/></svg>
    <div><b>${escapeHTML(title)}</b><span>${escapeHTML(message)}</span></div>`;
  root.appendChild(item);
  setTimeout(() => {
    item.classList.add("leaving");
    setTimeout(() => item.remove(), 220);
  }, 4800);
}

function renderLoadFailure(error) {
  setDBState("error", "读取失败");
  const banner = `
    <div class="error-banner">
      <svg><use href="#i-alert"/></svg>
      <div>
        <b>无法读取来源证据</b>
        <p>${escapeHTML(error.message)}。页面未伪造任何结论。</p>
        <button data-retry-load>重试读取</button>
      </div>
    </div>`;
  $("#auto-findings").innerHTML = banner;
  $("#timeline").innerHTML = banner;
  $("#evidence-list").innerHTML = emptyState("证据索引不可用");
  $("#followup-list").innerHTML = emptyState("处置单不可用");
}

function emptyState(message) {
  return `<div class="empty-state"><svg><use href="#i-file"/></svg><span>${escapeHTML(message)}</span></div>`;
}

function apiError(response) {
  return response.json()
    .then((payload) => payload.error || `HTTP ${response.status}`)
    .catch(() => `HTTP ${response.status} ${response.statusText}`);
}

function timeLabel(value) {
  if (!value) return "—";
  return String(value).slice(11, 16) || "—";
}

function formatDateTime(value) {
  if (!value) return "—";
  return String(value).slice(0, 16).replace("T", " ");
}

function pad2(value) {
  return String(value).padStart(2, "0");
}

function byteLength(value) {
  return new TextEncoder().encode(value).length;
}

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  })[character]);
}

function escapeAttr(value) {
  return escapeHTML(value);
}
