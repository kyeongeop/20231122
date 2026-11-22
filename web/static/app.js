(() => {
  "use strict";

  const body = document.body;
  const checkID = body.dataset.checkId;
  const attemptID = body.dataset.attemptId;
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

  const escapeHTML = (value = "") => String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

  const toast = (message) => {
    const region = $("#toast-region");
    if (!region) return;
    const node = document.createElement("div");
    node.className = "toast";
    node.innerHTML = '<span class="status-dot"></span>';
    const copy = document.createElement("span");
    copy.textContent = message;
    node.append(copy);
    region.append(node);
    requestAnimationFrame(() => node.classList.add("show"));
    setTimeout(() => {
      node.classList.remove("show");
      setTimeout(() => node.remove(), 240);
    }, 2800);
  };

  const copyText = async (text, success = "已复制到剪贴板") => {
    try {
      await navigator.clipboard.writeText(text);
      toast(success);
    } catch {
      const area = document.createElement("textarea");
      area.value = text;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.append(area);
      area.select();
      document.execCommand("copy");
      area.remove();
      toast(success);
    }
  };

  const openModal = (name) => {
    const layer = $("#modal-layer");
    if (!layer) return;
    $$(".modal", layer).forEach((modal) => modal.classList.toggle("active", modal.dataset.modal === name));
    layer.setAttribute("aria-hidden", "false");
    body.classList.add("has-overlay");
    setTimeout(() => $(".modal.active input, .modal.active textarea, .modal.active button")?.focus(), 80);
  };

  const closeModals = () => {
    const layer = $("#modal-layer");
    if (!layer) return;
    layer.setAttribute("aria-hidden", "true");
    $$(".modal", layer).forEach((modal) => modal.classList.remove("active"));
    if ($("#drawer-layer")?.getAttribute("aria-hidden") !== "false") body.classList.remove("has-overlay");
  };

  const openDrawer = (kicker, title, html) => {
    const layer = $("#drawer-layer");
    $("#drawer-kicker").textContent = kicker;
    $("#drawer-title").textContent = title;
    $("#drawer-content").innerHTML = html;
    layer.setAttribute("aria-hidden", "false");
    body.classList.add("has-overlay");
  };

  const closeDrawer = () => {
    const layer = $("#drawer-layer");
    if (!layer) return;
    layer.setAttribute("aria-hidden", "true");
    if ($("#modal-layer")?.getAttribute("aria-hidden") !== "false") body.classList.remove("has-overlay");
  };

  const stepDrawer = (row) => {
    const data = row.dataset;
    const evidence = $$(".evidence-chip", row);
    const chips = evidence.length
      ? evidence.map((button) => `<button class="evidence-chip" data-evidence-id="${escapeHTML(button.dataset.evidenceId)}">${escapeHTML(button.dataset.evidenceId)} ↗</button>`).join(" ")
      : '<span class="detail-empty">本步骤未附加证据</span>';
    const statusClass = data.stepStatus === "中途取消" ? "warn" : data.stepStatus === "失败" ? "bad" : "ok";
    const html = `
      <div class="step-detail-stat">
        <span class="status-badge ${statusClass}"><span></span>${escapeHTML(data.stepStatus)}</span>
        <span class="phase-chip">${escapeHTML(data.stepPhase)}</span>
        <span class="detail-mono">${escapeHTML(data.stepTime)}</span>
      </div>
      <p class="detail-summary">${escapeHTML(data.stepSummary)}</p>
      <div class="detail-grid">
        <div class="detail-cell"><span>处理工具</span><strong>${escapeHTML(data.stepTool || "—")}</strong></div>
        <div class="detail-cell"><span>来源关联</span><strong>immutable input</strong></div>
      </div>
      <div class="step-io">
        <div class="detail-cell"><span>步骤输入</span><pre>${escapeHTML(data.stepInput || "—")}</pre></div>
        <div class="detail-cell"><span>步骤输出</span><pre>${escapeHTML(data.stepOutput || "—")}</pre></div>
      </div>
      <div class="detail-label">关联证据 <span>${evidence.length} 项 · 点击查看</span></div>
      <div class="drawer-evidence-row">${chips}</div>
      <div class="detail-trace">
        <span>来源链</span><b>原始输入</b><span>→</span><b>${escapeHTML(data.stepTitle)}</b><span>→</span><b>${escapeHTML(checkID)}</b>
      </div>`;
    openDrawer("PROCESSING STEP", data.stepTitle, html);
  };

  const evidenceDrawer = async (id) => {
    openDrawer("EVIDENCE DETAIL", "正在读取证据…", '<div class="drawer-loading"><span></span>从 SQLite 读取哈希与原始内容</div>');
    try {
      const response = await fetch(`/api/evidence/${encodeURIComponent(id)}/meta`);
      if (!response.ok) throw new Error("证据不存在");
      const item = await response.json();
      const content = item.content || "";
      const preview = content.length > 5000 ? content.slice(0, 5000) + "\n…" : content;
      const html = `
        <div class="evidence-detail-type">
          <span class="evidence-detail-icon">◈</span>
          <div><h3>${escapeHTML(item.label)}</h3><p>${escapeHTML(item.id)} · ${escapeHTML(item.kind)} · ${item.size} B</p></div>
        </div>
        <div class="detail-grid">
          <div class="detail-cell"><span>SHA-256</span><strong title="${escapeHTML(item.sha256)}">${escapeHTML(item.sha256)}</strong></div>
          <div class="detail-cell"><span>写入时间</span><strong>${new Date(item.created_at).toLocaleString("zh-CN", { hour12: false })}</strong></div>
        </div>
        <div class="detail-label">原始内容 <span>${item.retained ? "已保留 · 只读" : "未保留"}</span></div>
        <pre class="detail-code">${escapeHTML(preview)}</pre>
        <div class="detail-trace">
          <span>来源链</span><b>${escapeHTML(item.step_id)}</b><span>→</span><b>${escapeHTML(item.attempt_id)}</b><span>→</span><b>${escapeHTML(item.id)}</b>
        </div>
        <div class="drawer-actions">
          <button class="button ghost small" data-copy-evidence="${escapeHTML(item.id)}">复制内容</button>
          <a class="button dark small" href="/api/evidence/${encodeURIComponent(item.id)}">下载原始证据</a>
        </div>`;
      $("#drawer-title").textContent = item.label;
      $("#drawer-content").innerHTML = html;
      $("#drawer-footer").dataset.evidenceContent = content;
    } catch (error) {
      $("#drawer-title").textContent = "读取失败";
      $("#drawer-content").innerHTML = `<div class="drawer-error"><strong>${escapeHTML(error.message)}</strong><p>请确认证据仍在 SQLite 中，或刷新页面重试。</p><button class="button ghost small" onclick="location.reload()">刷新页面</button></div>`;
    }
  };

  document.addEventListener("click", async (event) => {
    const modalTrigger = event.target.closest("[data-open-modal]");
    if (modalTrigger) {
      openModal(modalTrigger.dataset.openModal);
      return;
    }
    if (event.target.closest("[data-close-modal]")) {
      closeModals();
      return;
    }
    if (event.target.closest("[data-close-drawer]")) {
      closeDrawer();
      return;
    }
    const evidenceTrigger = event.target.closest("[data-evidence-id]");
    if (evidenceTrigger) {
      event.preventDefault();
      event.stopPropagation();
      closeModals();
      await evidenceDrawer(evidenceTrigger.dataset.evidenceId);
      return;
    }
    const copyEvidence = event.target.closest("[data-copy-evidence]");
    if (copyEvidence) {
      await copyText($("#drawer-footer").dataset.evidenceContent || "", "证据内容已复制");
      return;
    }
    const stepRow = event.target.closest(".step-row");
    if (stepRow && !event.target.closest("button, a")) {
      stepDrawer(stepRow);
      return;
    }
    if (event.target.closest("#drawer-layer .drawer-scrim")) {
      closeDrawer();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeModals();
      closeDrawer();
    }
    if ((event.key === "Enter" || event.key === " ") && event.target.classList.contains("step-row")) {
      event.preventDefault();
      stepDrawer(event.target);
    }
  });

  $("#menu-toggle")?.addEventListener("click", () => $("#sidebar")?.classList.toggle("open"));

  $$("[data-code-mode]").forEach((button) => {
    button.addEventListener("click", () => {
      $$("[data-code-mode]").forEach((item) => item.classList.toggle("active", item === button));
      const compare = $(".code-compare");
      if (compare) compare.dataset.mode = button.dataset.codeMode;
    });
  });

  $$("[data-attempt-target]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.attemptTarget;
      $$("[data-attempt-target]").forEach((item) => {
        const active = item === button;
        item.classList.toggle("active", active);
        item.setAttribute("aria-selected", active ? "true" : "false");
      });
      $$("[data-attempt-detail]").forEach((detail) => detail.classList.toggle("active", detail.dataset.attemptDetail === target));
    });
  });

  $("#copy-link")?.addEventListener("click", () => copyText(location.href, "来源检查链接已复制"));
  $("[data-copy-raw]")?.addEventListener("click", () => copyText($("#raw-input-store")?.value || "", "原始输入已复制"));

  $("[data-copy-summary]")?.addEventListener("click", () => {
    const summary = [
      `日志注入来源检查 ${checkID}`,
      `自动结论：${$(".auto-report .report-summary strong")?.textContent?.trim() || "—"}`,
      `人工结论：${$(".human-report-verdict strong")?.textContent?.trim() || "待确认"}`,
      `原始输入 SHA-256：${$(".fact-hero code")?.textContent?.trim() || "—"}`,
      location.href,
    ].join("\n");
    copyText(summary, "检查摘要已复制");
  });

  $("[data-copy-recovery]")?.addEventListener("click", () => {
    copyText(
      'sqlite3 data/tracecheck.db "PRAGMA busy_timeout=5000; PRAGMA integrity_check;" && df -h . && curl -s http://localhost:8080/healthz',
      "恢复检查命令已复制"
    );
  });

  const inputCounter = () => {
    const value = $("#new-check-input")?.value || "";
    const size = new TextEncoder().encode(value).length;
    const label = size > 1024 ? `${(size / 1024).toFixed(1)} KB` : `${size} B`;
    if ($("#input-counter")) $("#input-counter").textContent = label;
  };

  const fillNewCheck = (raw, name = "") => {
    const input = $("#new-check-input");
    if (!input) return;
    input.value = raw;
    if (name && $("#new-check-title-input")) {
      $("#new-check-title-input").value = "日志注入 · 来源检查";
      const source = $("#new-check-source");
      if (source) source.value = $("#source-store")?.value || "manual / workspace";
    }
    inputCounter();
    input.focus();
  };

  $$("[data-retry-input]").forEach((button) => {
    button.addEventListener("click", () => {
      fillNewCheck($("#raw-input-store")?.value || "", $("#input-name-store")?.value || "");
      openModal("new-check");
    });
  });

  $("#load-example")?.addEventListener("click", () => {
    fillNewCheck($("#raw-input-store")?.value || "");
    toast("已载入当前案例的原始输入");
  });

  $("#new-check-file")?.addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 2 << 20) {
      toast("文件超过 2 MB，请拆分后再检查");
      return;
    }
    $("#new-check-input").value = await file.text();
    $("#new-check-title-input").value = file.name.replace(/\.(log|txt|jsonl)$/i, "");
    inputCounter();
  });

  $("#new-check-input")?.addEventListener("input", inputCounter);

  $("#start-check")?.addEventListener("click", async () => {
    const input = $("#new-check-input")?.value || "";
    if (!input.trim()) {
      toast("请输入待检查日志");
      $("#new-check-input")?.focus();
      return;
    }
    const button = $("#start-check");
    button.disabled = true;
    button.textContent = "正在建立来源链…";
    try {
      const response = await fetch("/api/checks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: $("#new-check-title-input")?.value || "日志注入 · 来源检查",
          source: $("#new-check-source")?.value || "manual / workspace",
          input_name: `pasted-log-${new Date().toISOString().slice(0, 19).replaceAll(":", "")}.log`,
          input,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "无法开始检查");
      window.location.href = `/checks/${result.check_id}`;
    } catch (error) {
      toast(error.message);
      button.disabled = false;
      button.innerHTML = "开始检查 <span>→</span>";
    }
  });

  $("#save-confirm")?.addEventListener("click", async () => {
    const selected = $('input[name="human-verdict"]:checked')?.value;
    const reviewer = $("#confirm-reviewer")?.value?.trim();
    const note = $("#confirm-note")?.value?.trim();
    const ticket = $("#confirm-ticket")?.value?.trim();
    if (!reviewer || !note) {
      toast("请填写复核人和判断依据");
      return;
    }
    const button = $("#save-confirm");
    button.disabled = true;
    button.textContent = "正在签名…";
    try {
      const response = await fetch(`/api/checks/${encodeURIComponent(checkID)}/confirm`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          verdict: selected,
          reviewer,
          note: ticket ? `${note}\n关联处置单：${ticket}` : note,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "保存失败");
      toast("人工结论已独立存证");
      setTimeout(() => location.reload(), 500);
    } catch (error) {
      toast(error.message);
      button.disabled = false;
      button.textContent = "保存人工结论";
    }
  });

  $("[data-cancel-current]")?.addEventListener("click", async (event) => {
    if (!attemptID) return;
    const button = event.currentTarget;
    button.disabled = true;
    button.textContent = "正在取消…";
    try {
      const response = await fetch(
        `/api/checks/${encodeURIComponent(checkID)}/attempts/${encodeURIComponent(attemptID)}/cancel`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            actor: "当前操作员",
            reason: "操作员在检查执行途中主动取消；已完成步骤和原始输入保持只读。",
          }),
        }
      );
      if (!response.ok) throw new Error("取消失败，请稍后重试");
      toast("已记录中途取消，现有证据已保留");
      setTimeout(() => location.reload(), 450);
    } catch (error) {
      toast(error.message);
      button.disabled = false;
      button.textContent = "中途取消";
    }
  });

  if (body.dataset.status === "running") {
    const poll = setInterval(async () => {
      try {
        const response = await fetch(`/api/checks/${encodeURIComponent(checkID)}/status`);
        if (!response.ok) return;
        const { status } = await response.json();
        if (status !== "running") {
          clearInterval(poll);
          location.reload();
        }
      } catch {
        // Keep the current evidence view visible; the next poll retries.
      }
    }, 1400);
  }
})();
