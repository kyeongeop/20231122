const state = {
  report: null,
  drawerConclusion: null,
  busy: false,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const categoryCode = {
  replay: "RP",
  crash: "AS",
  provenance: "PR",
  extension: "EX",
  recovery: "RC",
};

const evidenceCode = {
  original: "BIN",
  fuzzer: "FUZ",
  log: "LOG",
  journal: "JNL",
  bytes: "HEX",
  trace: "TRC",
  manifest: "SUM",
  asan: "ASN",
};

const statusLabel = {
  pending: "待确认",
  confirmed: "已确认",
  rejected: "已驳回",
  undecided: "无法判断",
  failed: "失败",
  reproduced: "已复现",
};

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function pad(value) {
  return String(value ?? 0).padStart(2, "0");
}

function shortHash(value, size = 12) {
  if (!value) return "—";
  return value.length > size ? `${value.slice(0, size)}…` : value;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
  }).format(date) + " UTC";
}

function evidenceById(id) {
  return state.report?.evidence.find((item) => item.id === id);
}

function stepById(id) {
  return state.report?.steps.find((item) => item.id === id);
}

function conclusionById(id) {
  return state.report?.conclusions.find((item) => item.id === id);
}

function manualById(id) {
  return state.report?.manual_checks.find((item) => item.id === id);
}

function stepForReplay(replay) {
  const evidence = evidenceById(replay.evidence_id);
  return evidence ? stepById(evidence.step_id) : null;
}

async function loadReport() {
  const response = await fetch("/api/report", { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error("证据库读取失败");
  return response.json();
}

async function bootstrap() {
  try {
    state.report = await loadReport();
    renderAll();
  } catch (error) {
    showToast(error.message || "页面载入失败，请刷新重试", true);
    $("#heroSummary").textContent = "无法读取证据库。请检查服务是否运行，然后刷新页面。";
  }
}

function renderAll() {
  if (!state.report) return;
  renderHero();
  renderBoundary();
  renderConclusions();
  renderManualChecks();
  renderReplays();
  renderSteps();
  renderUnknownExtension();
  renderEvidence();
  renderReport();
  if (state.drawerConclusion) openTrace(state.drawerConclusion);
}

function renderHero() {
  const { sample, summary } = state.report;
  $("#railCase").textContent = sample.id;
  $("#railIncident").textContent = sample.case_no;
  $("#topCase").textContent = sample.id;
  $("#footCase").textContent = `${sample.id} · 2026`;
  $("#heroCase").textContent = sample.id;
  $("#heroEyebrow").textContent = `${sample.severity.toUpperCase()} SEVERITY · RECOVERED SAMPLE`;
  $("#heroSummary").textContent = sample.summary;
  $("#metaFilename").textContent = sample.filename;
  $("#metaFilename").title = sample.filename;
  $("#metaSize").textContent = `${sample.size} B · ${sample.extension}`;
  $("#metaIncident").textContent = sample.case_no;
  $("#metaHash").textContent = shortHash(sample.sha256, 18);
  $("#metaHash").title = sample.sha256;
  $("#snapshotID").textContent = shortHash(sample.frozen_at.replaceAll(":", "").replaceAll("-", ""), 17);

  const status = summary.status;
  const pill = $("#heroStatus");
  pill.textContent = summary.status_label;
  pill.className = "status-pill " + (status === "confirmed" || status === "reviewed" ? "confirmed" : status === "boundary_blocked" ? "blocked" : "pending");
  $("#heroStatusNote").textContent = summary.manual_pending
    ? `${summary.manual_pending} 项人工确认未签署`
    : summary.auto_undecided
      ? "自动边界仍不可判，需补充协议证据"
      : "自动结论与人工确认均已闭合";
  $("#statAuto").textContent = pad(summary.auto_count);
  $("#statManual").textContent = pad(summary.manual_pending);
  $("#statEvidence").textContent = pad(summary.evidence_count);
  $("#navManualBadge").textContent = summary.manual_pending;
  $("#railStore").textContent = `snapshot · ${summary.evidence_count} objects`;
  $("#exportBtn").href = `/api/export?sample=${encodeURIComponent(sample.id)}`;
}

function renderBoundary() {
  const boundary = state.report.conclusions.find((item) => item.category === "extension" && item.status === "undecided");
  if (!boundary) {
    $("#boundaryBanner").hidden = true;
    return;
  }
  const unknown = state.report.unknown_extensions[0];
  $("#boundaryText").textContent = `${boundary.title}；${boundary.undecidable_reason} 原始 ${unknown.length} B 已保留在 ${unknown.evidence_id}。`;
}

function renderConclusions() {
  const list = $("#autoList");
  const items = state.report.conclusions.filter((item) => item.origin === "automatic");
  $("#autoCount").textContent = pad(items.length);
  $("#reportAutoCount").textContent = `${items.length} 条`;
  list.innerHTML = items.map((item) => {
    const undecided = item.status === "undecided";
    const critical = item.severity === "critical";
    const confidence = Math.round(item.confidence * 100);
    const evidenceStack = item.evidence_ids.slice(0, 4).map((id) => `<span class="evidence-mini" title="${esc(id)}">${esc(id.slice(-3))}</span>`).join("");
    return `
      <article class="conclusion-card ${undecided ? "is-undecided" : ""} ${critical ? "is-critical" : ""}">
        <div class="conclusion-icon">${esc(categoryCode[item.category] || "AU")}</div>
        <div class="conclusion-main">
          <div class="conclusion-title-row">
            <h3 class="conclusion-title">${esc(item.title)}</h3>
            <span class="rule-chip">${esc(item.rule_id)}</span>
          </div>
          <p class="conclusion-detail">${esc(item.detail)}</p>
          <div class="conclusion-meta">
            <span>STEP ${esc(item.step_id)}</span>
            <span>${esc(item.input_ref)}</span>
            <div class="evidence-stack">${evidenceStack}</div>
          </div>
        </div>
        <div class="conclusion-side">
          <span class="finding-state ${undecided ? "undecided" : ""}">${undecided ? "无法判断" : "自动成立"}</span>
          <div class="confidence">
            <div class="confidence-track"><i style="width:${confidence}%"></i></div>
            <span>${confidence}%</span>
          </div>
          <button class="trace-btn" type="button" data-trace="${esc(item.id)}">追溯 <span>↗</span></button>
        </div>
      </article>`;
  }).join("");
}

function renderManualChecks() {
  const list = $("#manualList");
  const items = state.report.manual_checks;
  const resolved = items.filter((item) => item.status !== "pending").length;
  const percent = items.length ? Math.round((resolved / items.length) * 100) : 0;
  $("#manualCount").textContent = `${resolved}/${items.length}`;
  $("#manualProgressText").textContent = `${resolved} / ${items.length} 已签署`;
  $("#manualProgressBar").style.width = `${percent}%`;

  list.innerHTML = items.map((item) => {
    const conclusion = conclusionById(item.conclusion_id);
    return `
      <article class="manual-card" data-check="${esc(item.id)}">
        <div class="manual-top">
          <div>
            <span class="manual-id">${esc(item.id)} · LINKED ${esc(item.conclusion_id)}</span>
            <h3 class="manual-question">${esc(item.question)}</h3>
            <button class="manual-linked" type="button" data-trace="${esc(item.conclusion_id)}">查看自动结论与证据链 <span>↗</span></button>
          </div>
          <span class="manual-status ${esc(item.status)}">${esc(statusLabel[item.status] || item.status)}</span>
        </div>
        <p class="manual-guidance">${esc(item.guidance)}</p>
        <div class="manual-controls">
          <textarea class="review-note" id="note-${esc(item.id)}" placeholder="补充判定依据（写入 SQLite，不覆盖自动结论）">${esc(item.note)}</textarea>
          <div class="review-buttons">
            <button class="review-btn confirm" type="button" data-review="${esc(item.id)}" data-status="confirmed">确认</button>
            <button class="review-btn reject" type="button" data-review="${esc(item.id)}" data-status="rejected">驳回</button>
          </div>
        </div>
        <div class="manual-saved">
          <span>${item.reviewer ? `签署人 ${esc(item.reviewer)}` : "尚未签署 · 自动结论保持原状态"}</span>
          <code>${item.updated_at ? formatTime(item.updated_at) : "—"}</code>
        </div>
      </article>`;
  }).join("");
}

function renderReplays() {
  const list = $("#replayList");
  const items = state.report.replays;
  list.innerHTML = items.map((item) => {
    const stateClass = item.status === "failed" ? "failed" : item.status === "reproduced" ? "" : "boundary";
    const title = stepForReplay(item)?.title || (item.attempt === 1 ? "恢复后重放（首次）" : "恢复后重放");
    return `
      <article class="replay-row">
        <div class="replay-attempt">RUN<strong>${String(item.attempt).padStart(2, "0")}</strong></div>
        <div>
          <h3 class="replay-title">${esc(title)}</h3>
          <p class="replay-note">${esc(item.note)}</p>
          <div class="replay-stamp">
            <span>${esc(item.id)}</span>
            <span>exit=${item.exit_code}</span>
            <span>${item.status === "failed" ? "0/3" : `${item.reproduced}/${item.total}`}</span>
            <span>${item.recovered_from_job ? `job=${esc(item.recovered_from_job)}` : "no job"}</span>
            <span>${formatTime(item.finished_at)}</span>
          </div>
        </div>
        <span class="replay-state ${stateClass}">${esc(statusLabel[item.status] || item.status)}</span>
      </article>`;
  }).join("");
  $("#failureBox").hidden = !items.some((item) => item.status === "failed");
}

function renderSteps() {
  $("#stepList").innerHTML = state.report.steps.map((item) => `
    <div class="timeline-step">
      <span class="step-marker ${esc(item.status)}">${String(item.seq).padStart(2, "0")}</span>
      <div>
        <p class="step-title">${esc(item.title)}</p>
        <div class="step-time">${formatTime(item.finished_at || item.started_at)}</div>
        <span class="step-hash" title="${esc(item.hash || item.command)}">${esc(shortHash(item.hash || item.command, 31))}</span>
      </div>
    </div>`).join("");
}

function groupedHex(hex, group = 2) {
  return (hex.match(new RegExp(`.{1,${group}}`, "g")) || []).join(" ");
}

function renderUnknownExtension() {
  const item = state.report.unknown_extensions[0];
  if (!item) return;
  $("#unknownHex").textContent = groupedHex(item.raw_hex, 2);
  $("#unknownNote").textContent = `扩展注册表未命中；解析器在 0x${item.boundary.toString(16).toUpperCase().padStart(4, "0")} 停止语义归属。${item.length} B 原始片段已单独封存。`;
}

function renderEvidence() {
  const items = state.report.evidence;
  $("#evidenceCount").textContent = pad(items.length);
  $("#evidenceList").innerHTML = items.map((item) => `
    <div class="evidence-row">
      <span class="evidence-type">${esc(evidenceCode[item.kind] || "OBJ")}</span>
      <div style="min-width:0">
        <div class="evidence-label" title="${esc(item.label)}">${esc(item.label)}</div>
        <div class="evidence-meta">${esc(item.id)} · ${item.size} B · ${esc(shortHash(item.sha256, 10))}</div>
      </div>
      <a class="evidence-dl" href="${esc(item.download_url)}" title="下载 ${esc(item.label)}">↓</a>
    </div>`).join("");
}

function renderReport() {
  const { conclusions, manual_checks: checks, sample, generated_at: generatedAt } = state.report;
  const auto = conclusions.filter((item) => item.origin === "automatic");
  $("#reportTime").textContent = `生成于 ${formatTime(generatedAt)}`;
  $("#reportGenerated").textContent = formatTime(generatedAt);
  $("#reportHash").textContent = shortHash(sample.sha256, 32);
  $("#reportHash").title = sample.sha256;
  $("#reportManualCount").textContent = `${checks.length} 项`;

  $("#reportAuto").innerHTML = auto.map((item) => `
    <div class="report-row" data-trace="${esc(item.id)}">
      <span class="report-rule">${esc(item.rule_id)}</span>
      <div>
        <h4 class="report-row-title">${esc(item.title)}</h4>
        <p class="report-row-detail">${esc(item.detail)}</p>
        <div class="report-evidence">${esc(item.step_id)} · ${item.evidence_ids.map(esc).join(" / ")}</div>
      </div>
      <span class="report-state ${item.status === "undecided" ? "undecided" : ""}">${item.status === "undecided" ? "无法判断" : "自动成立"}</span>
    </div>`).join("");

  $("#reportManual").innerHTML = checks.map((item) => {
    const label = statusLabel[item.status] || item.status;
    return `
      <div class="report-check" data-trace="${esc(item.conclusion_id)}">
        <div class="report-check-top">
          <h4 class="report-check-title">${esc(item.question)}</h4>
          <span class="report-state ${item.status === "pending" ? "undecided" : ""}">${esc(label)}</span>
        </div>
        <p class="report-check-guidance">${esc(item.note || item.guidance)}</p>
        <div class="report-check-sign">
          <span class="sign-dot ${esc(item.status)}"></span>
          <span>${item.reviewer ? `${esc(item.reviewer)} · ${formatTime(item.updated_at)}` : "待人工签署 · 与自动结论分栏保存"}</span>
        </div>
      </div>`;
  }).join("");
}

function parseInputRange(inputRef) {
  const match = String(inputRef || "").match(/#0x([0-9a-fA-F]+)-0x([0-9a-fA-F]+)/);
  if (!match) return null;
  return { start: parseInt(match[1], 16), end: parseInt(match[2], 16) };
}

function renderHexDump(hex, highlight) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(hex.slice(i, i + 2).toLowerCase());
  const rows = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const row = bytes.slice(offset, offset + 16);
    const cells = row.map((byte, index) => {
      const absolute = offset + index;
      const mark = highlight && absolute >= highlight.start && absolute < highlight.end;
      return mark ? `<mark>${byte}</mark>` : byte;
    }).join(" ");
    const ascii = row.map((byte, index) => {
      const absolute = offset + index;
      const code = parseInt(byte, 16);
      const char = code >= 32 && code < 127 ? String.fromCharCode(code) : ".";
      const mark = highlight && absolute >= highlight.start && absolute < highlight.end;
      return mark ? `<mark>${esc(char)}</mark>` : esc(char);
    }).join("");
    rows.push(`<span>${offset.toString(16).toUpperCase().padStart(4, "0")}</span>  ${cells.padEnd(47, " ")}  ${ascii}`);
  }
  return rows.join("\n");
}

function openTrace(conclusionId) {
  const item = conclusionById(conclusionId);
  if (!item) return;
  state.drawerConclusion = conclusionId;
  const conclusionStep = stepById(item.step_id);
  const linkedCheck = item.manual_check_id ? manualById(item.manual_check_id) : null;
  const original = evidenceById("E-001");
  const range = parseInputRange(item.input_ref);
  const snippet = original ? renderHexDump(original.preview_hex, range) : "原始字节预览不可用";
  const evidenceRows = item.evidence_ids.map((id) => {
    const evidence = evidenceById(id);
    if (!evidence) return "";
    return `
      <div class="trace-evidence-row">
        <span class="evidence-type">${esc(evidenceCode[evidence.kind] || "OBJ")}</span>
        <div style="min-width:0">
          <div class="evidence-label">${esc(evidence.label)}</div>
          <div class="evidence-meta">${esc(evidence.id)} · ${evidence.size} B · ${esc(shortHash(evidence.sha256, 16))}</div>
        </div>
        <a class="evidence-dl" href="${esc(evidence.download_url)}" title="下载证据">↓</a>
      </div>`;
  }).join("");
  const chain = state.report.steps
    .filter((step) => step.seq <= (conclusionStep?.seq || 7))
    .map((step) => `
      <div class="trace-chain-step ${step.status === "failed" ? "fail" : "done"}">
        <strong>${esc(step.id)} · ${esc(step.title)}</strong>
        <span>${formatTime(step.finished_at)} · ${esc(shortHash(step.hash || step.command, 26))}</span>
      </div>`).join("");
  const reason = item.undecidable_reason
    ? `<div class="trace-section"><h3>不可判定边界</h3><div class="reason-box"><strong>0x${item.boundary.toString(16).toUpperCase().padStart(4, "0")}</strong>${esc(item.undecidable_reason)}</div></div>`
    : "";
  const manual = linkedCheck
    ? `<div class="trace-section"><h3>人工确认</h3><div class="reason-box"><strong>${esc(linkedCheck.question)}</strong>状态：${esc(statusLabel[linkedCheck.status] || linkedCheck.status)}<br>${esc(linkedCheck.note || linkedCheck.guidance)}</div></div>`
    : "";
  $("#drawerBody").innerHTML = `
    <div class="trace-lead">
      <div class="trace-lead-top">
        <span class="trace-id">${esc(item.id)} · ${esc(item.rule_id)}</span>
        <span class="finding-state ${item.status === "undecided" ? "undecided" : ""}">${esc(statusLabel[item.status] || item.status)}</span>
      </div>
      <h3 class="trace-title">${esc(item.title)}</h3>
      <p class="trace-detail">${esc(item.detail)}</p>
      <div class="trace-stat-grid">
        <div><span>AUTO CONFIDENCE</span><code>${Math.round(item.confidence * 100)}%</code></div>
        <div><span>STEP</span><code>${esc(item.step_id)}</code></div>
        <div><span>INPUT RANGE</span><code>${esc(item.input_ref.split("#")[1] || "—")}</code></div>
      </div>
    </div>
    ${reason}
    <div class="trace-section">
      <h3>原始输入切片</h3>
      <div class="hex-trace">${snippet}</div>
      <a class="drawer-link" href="${esc(original?.download_url || "#")}">下载完整原始样本 ↑</a>
    </div>
    <div class="trace-section">
      <h3>证据对象</h3>
      <div class="trace-evidence">${evidenceRows}</div>
    </div>
    <div class="trace-section">
      <h3>处理步骤</h3>
      <div class="trace-chain">${chain}</div>
    </div>
    ${manual}
    <div class="trace-section">
      <h3>规则上下文</h3>
      <div class="reason-box"><strong>${esc(item.rule_id)}</strong>输入引用 ${esc(item.input_ref)}；结论只引用已哈希证据。${conclusionStep ? `处理命令：${esc(conclusionStep.command)}` : ""}</div>
    </div>`;

  const overlay = $("#overlay");
  const drawer = $("#drawer");
  overlay.hidden = false;
  requestAnimationFrame(() => {
    overlay.classList.add("visible");
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
  });
  document.body.style.overflow = "hidden";
}

function closeTrace() {
  const overlay = $("#overlay");
  const drawer = $("#drawer");
  overlay.classList.remove("visible");
  drawer.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
  setTimeout(() => {
    overlay.hidden = true;
    state.drawerConclusion = null;
  }, 220);
}

function showToast(message, isError = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.add("visible");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("visible"), 4200);
}

async function submitReview(checkId, status) {
  if (state.busy) return;
  const reviewer = ($("#reviewerInput")?.value || "on-call@waypoint").trim();
  const note = ($(`#note-${checkId}`)?.value || "").trim();
  if (!reviewer) {
    showToast("请先填写审核人，再保存人工判定", true);
    $("#reviewerInput")?.focus();
    return;
  }
  state.busy = true;
  try {
    const response = await fetch("/api/manual-review", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        sample_id: state.report.sample.id,
        check_id: checkId,
        status,
        reviewer,
        note,
      }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "人工判定保存失败");
    state.report = payload;
    renderAll();
    const label = status === "confirmed" ? "确认" : "驳回";
    showToast(`${checkId} 已${label}；报告已更新，自动结论保持独立`);
  } catch (error) {
    showToast(`${error.message}。请保留当前页面并重试，证据未丢失。`, true);
  } finally {
    state.busy = false;
  }
}

async function runReplay() {
  if (state.busy) return;
  state.busy = true;
  const buttons = $$('[data-action="replay"]');
  buttons.forEach((button) => {
    button.disabled = true;
    button.dataset.label = button.textContent;
    button.textContent = "执行中…";
  });
  try {
    const response = await fetch("/api/replay", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ sample_id: state.report.sample.id }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "重放失败");
    state.report = payload;
    renderAll();
    const lastReplay = state.report.replays.at(-1);
    const lastStep = state.report.steps.at(-1);
    showToast(`补证完成：${lastStep?.id} / ${lastReplay?.id}；结果已写入 SQLite`);
  } catch (error) {
    showToast(`${error.message}。原证据未被覆盖，请检查服务日志后重试。`, true);
  } finally {
    state.busy = false;
    buttons.forEach((button) => {
      button.disabled = false;
      button.textContent = button.dataset.label || "重新执行";
    });
  }
}

function handleAction(action) {
  if (action === "replay") {
    runReplay();
  } else if (action === "jump-manual") {
    $("#manual").scrollIntoView({ behavior: "smooth", block: "start" });
  } else if (action === "jump-report") {
    $("#report").scrollIntoView({ behavior: "smooth", block: "start" });
  } else if (action === "trace-unknown") {
    const extension = state.report.conclusions.find((item) => item.category === "extension");
    if (extension) openTrace(extension.id);
  }
}

function bindEvents() {
  document.addEventListener("click", (event) => {
    const traceButton = event.target.closest("[data-trace]");
    if (traceButton) {
      event.preventDefault();
      openTrace(traceButton.dataset.trace);
      return;
    }
    const reviewButton = event.target.closest("[data-review]");
    if (reviewButton) {
      submitReview(reviewButton.dataset.review, reviewButton.dataset.status);
      return;
    }
    const actionButton = event.target.closest("[data-action]");
    if (actionButton) {
      handleAction(actionButton.dataset.action);
    }
  });

  $("#drawerClose").addEventListener("click", closeTrace);
  $("#overlay").addEventListener("click", closeTrace);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeTrace();
  });
  $("#printBtn").addEventListener("click", () => {
    $("#report").scrollIntoView({ behavior: "smooth", block: "start" });
    showToast("已定位到自动/人工分栏报告");
  });
  $("#reportPrint").addEventListener("click", () => window.print());

  const sections = ["overview", "automatic", "manual", "replay", "report"]
    .map((id) => document.getElementById(id))
    .filter(Boolean);
  const updateNav = () => {
    let current = window.scrollY < 260 ? "overview" : "automatic";
    sections.forEach((section) => {
      if (section.getBoundingClientRect().top <= 180) current = section.id;
    });
    $$(".nav-item").forEach((item) => {
      item.classList.toggle("active", item.dataset.section === current);
    });
  };
  window.addEventListener("scroll", updateNav, { passive: true });
  $$(".nav-item").forEach((item) => item.addEventListener("click", () => {
    $$(".nav-item").forEach((nav) => nav.classList.toggle("active", nav === item));
  }));
  updateNav();
}

bindEvents();
bootstrap();
