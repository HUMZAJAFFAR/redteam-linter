/* ==========================================================================
   RedTeam Linter — console client
   Vanilla ES2020, no build step. All findings arrive already redacted by
   reporter.ReportGenerator; this file only renders them.
   ========================================================================== */

(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const MAX_FILES = 25;
  const MAX_TOTAL = 2 * 1024 * 1024;

  const SAMPLE = `import os
import pickle
import subprocess

API_KEY = "sk_live_51H8xQ2f9Kd0aPz7Tm"

def run_expression(request):
    """Evaluate an expression supplied by the caller."""
    expression = request.args.get("expr")
    return eval(expression)

def ping(host):
    os.system("ping -c 1 " + host)

def archive(name):
    subprocess.call("tar -czf " + name + ".tgz " + name, shell=True)

def restore(blob):
    return pickle.loads(blob)
`;

  const state = {
    mode: "paste",
    files: [],
    payload: null,
    findings: [],
    severity: "ALL",
    query: "",
    openIndex: null,
    loading: false,
    rules: [],
  };

  const el = {
    enginePill: $("#engine-pill"),
    engineText: $("#engine-text"),
    code: $("#code"),
    pasteName: $("#paste-name"),
    editorFile: $("#editor-file"),
    codeStats: $("#code-stats"),
    fileInput: $("#file-input"),
    dropzone: $("#dropzone"),
    filelist: $("#filelist"),
    scanBtn: $("#scan-btn"),
    sampleBtn: $("#sample-btn"),
    clearBtn: $("#clear-btn"),
    copyBtn: $("#copy-btn"),
    exportBtn: $("#export-btn"),
    rulesBody: $("#rules-body"),
    rulesCount: $("#rules-count"),
    rulesBlock: $("#rules-block"),
    findingsBody: $("#findings-body"),
    findingsTable: $("#findings-table"),
    findingsCount: $("#findings-count"),
    resultsSub: $("#results-sub"),
    resultMeta: $("#result-meta"),
    ruleSource: $("#rule-source"),
    emptyState: $("#empty-state"),
    cleanState: $("#clean-state"),
    loadingState: $("#loading-state"),
    loadingText: $("#loading-text"),
    search: $("#search"),
    chips: $("#severity-filters"),
    drawer: $("#drawer"),
    drawerBackdrop: $("#drawer-backdrop"),
    drawerBody: $("#drawer-body"),
    drawerSub: $("#drawer-sub"),
    drawerClose: $("#drawer-close"),
    toasts: $("#toasts"),
  };

  /* ------------------------------------------------------------------ */
  /* Utilities                                                          */
  /* ------------------------------------------------------------------ */

  const escapeHtml = (value) =>
    String(value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[char]));

  const bytes = (count) => {
    if (count < 1024) return `${count} B`;
    if (count < 1024 * 1024) return `${(count / 1024).toFixed(1)} KB`;
    return `${(count / (1024 * 1024)).toFixed(2)} MB`;
  };

  const severityOf = (finding) => String(finding.severity || "INFO").toUpperCase();

  const isMac = /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent);
  const modLabel = isMac ? "⌘" : "Ctrl";
  const scanKbd = $(".btn-kbd");
  if (scanKbd) scanKbd.textContent = `${modLabel} ↵`;

  function toast(message, type = "info", title = "") {
    const icons = { success: "#i-check", error: "#i-alert", info: "#i-shield" };
    const node = document.createElement("div");
    node.className = `toast ${type}`;
    node.innerHTML = `
      <svg aria-hidden="true"><use href="${icons[type] || icons.info}"/></svg>
      <div class="toast-body">${title ? `<strong>${escapeHtml(title)}</strong>` : ""}<span>${escapeHtml(message)}</span></div>`;
    el.toasts.appendChild(node);
    window.setTimeout(() => {
      node.classList.add("is-out");
      window.setTimeout(() => node.remove(), 220);
    }, type === "error" ? 5200 : 3400);
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      try {
        const body = await response.json();
        if (body && body.detail) {
          detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
        }
      } catch (_) { /* non-JSON error body */ }
      throw new Error(detail);
    }
    return response.json();
  }

  /* ------------------------------------------------------------------ */
  /* Boot: health + rules                                               */
  /* ------------------------------------------------------------------ */

  async function boot() {
    try {
      const health = await api("/api/health");
      el.enginePill.classList.add("online");
      el.engineText.textContent = `${health.engine} · ${health.rules} rules`;
      el.enginePill.title = `Engine ${health.engine} · rules from ${health.rule_source}`;
    } catch (error) {
      el.enginePill.classList.add("offline");
      el.engineText.textContent = "engine offline";
      toast("Could not reach the scan API. Is the server running?", "error", "Disconnected");
    }

    try {
      const data = await api("/api/rules");
      state.rules = data.rules || [];
      el.rulesCount.textContent = String(data.count ?? state.rules.length);
      el.ruleSource.textContent = data.source ? `rules: ${data.source}` : "";
      el.rulesBody.innerHTML =
        `<div class="rule-source-line">Loaded from ${escapeHtml(data.source || "built-in")}</div>` +
        state.rules
          .map(
            (rule) => `
            <div class="rule">
              <code>${escapeHtml(rule.name)}</code>
              ${rule.requires_shell_true ? '<span class="rule-flag">shell=True</span>' : ""}
              <span class="rule-cat">${escapeHtml(rule.category || "unknown")}</span>
            </div>`
          )
          .join("");
    } catch (_) {
      el.rulesCount.textContent = "0";
    }

    if (!el.code.value.trim()) {
      el.code.value = "";
      updateCodeStats();
    }
  }

  /* ------------------------------------------------------------------ */
  /* Input: paste                                                       */
  /* ------------------------------------------------------------------ */

  function updateCodeStats() {
    const text = el.code.value;
    const lines = text ? text.split("\n").length : 0;
    const size = new Blob([text]).size;
    el.codeStats.textContent = `${lines} line${lines === 1 ? "" : "s"} · ${bytes(size)}`;
    el.editorFile.textContent = el.pasteName.value.trim() || "target.py";
  }

  function setMode(mode) {
    state.mode = mode;
    $$(".tab").forEach((tab) => {
      const active = tab.dataset.pane === mode;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
    });
    $("#pane-paste").classList.toggle("hidden", mode !== "paste");
    $("#pane-upload").classList.toggle("hidden", mode !== "upload");
    updateScanState();
  }

  /* ------------------------------------------------------------------ */
  /* Input: upload                                                      */
  /* ------------------------------------------------------------------ */

  async function addFiles(fileList) {
    const incoming = Array.from(fileList || []);
    if (!incoming.length) return;

    let total = state.files.reduce((sum, file) => sum + file.size, 0);
    const rejected = [];

    for (const file of incoming) {
      if (state.files.length >= MAX_FILES) {
        rejected.push(`${file.name}: file limit reached`);
        continue;
      }
      if (!/\.py$/i.test(file.name)) {
        rejected.push(`${file.name}: only .py files are scanned`);
        continue;
      }
      if (total + file.size > MAX_TOTAL) {
        rejected.push(`${file.name}: exceeds the 2 MB budget`);
        continue;
      }
      if (state.files.some((existing) => existing.name === file.name)) {
        rejected.push(`${file.name}: already added`);
        continue;
      }
      let content = "";
      try {
        content = await file.text();
      } catch (_) {
        rejected.push(`${file.name}: unreadable`);
        continue;
      }
      state.files.push({
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        name: file.name,
        size: file.size,
        content,
      });
      total += file.size;
    }

    renderFileList();
    updateScanState();
    if (rejected.length) {
      toast(rejected.slice(0, 2).join(" · "), "error", "Some files were skipped");
    }
    if (state.files.length) {
      toast(`${state.files.length} file${state.files.length === 1 ? "" : "s"} ready to scan`, "success");
    }
  }

  function renderFileList() {
    el.filelist.innerHTML = state.files
      .map(
        (file) => `
        <li data-id="${escapeHtml(file.id)}">
          <svg class="file-icon" aria-hidden="true"><use href="#i-file"/></svg>
          <span class="file-name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
          <span class="file-size">${bytes(file.size)}</span>
          <button class="file-remove" type="button" data-remove="${escapeHtml(file.id)}"
                  aria-label="Remove ${escapeHtml(file.name)}">
            <svg aria-hidden="true"><use href="#i-close"/></svg>
          </button>
        </li>`
      )
      .join("");
  }

  /* ------------------------------------------------------------------ */
  /* Scanning                                                           */
  /* ------------------------------------------------------------------ */

  function collectFiles() {
    if (state.mode === "upload") {
      return state.files.map((file) => ({ path: file.name, content: file.content }));
    }
    const content = el.code.value;
    if (!content.trim()) return [];
    return [{ path: el.pasteName.value.trim() || "target.py", content }];
  }

  function updateScanState() {
    const ready = state.mode === "upload" ? state.files.length > 0 : el.code.value.trim().length > 0;
    el.scanBtn.disabled = state.loading || !ready;
    el.scanBtn.classList.toggle("is-busy", state.loading);
  }

  const loadingMessages = [
    "Parsing AST…",
    "Resolving imports and aliases…",
    "Matching sink rules…",
    "Tracing user input…",
    "Masking credentials…",
  ];
  let loadingTimer = null;

  function setLoading(active) {
    state.loading = active;
    updateScanState();
    el.loadingState.classList.toggle("hidden", !active);
    if (active) {
      el.emptyState.classList.add("hidden");
      el.cleanState.classList.add("hidden");
      el.findingsTable.classList.add("hidden");
      let index = 0;
      el.loadingText.textContent = loadingMessages[0];
      loadingTimer = window.setInterval(() => {
        index = (index + 1) % loadingMessages.length;
        el.loadingText.textContent = loadingMessages[index];
      }, 520);
    } else {
      if (loadingTimer) window.clearInterval(loadingTimer);
      loadingTimer = null;
      el.loadingState.classList.add("hidden");
    }
  }

  async function runScan() {
    if (state.loading) return;
    const files = collectFiles();
    if (!files.length) {
      toast(
        state.mode === "upload" ? "Add at least one .py file." : "Paste some Python source first.",
        "error",
        "Nothing to scan"
      );
      return;
    }

    setLoading(true);
    try {
      const payload = await api("/api/scan", { method: "POST", body: JSON.stringify({ files }) });
      state.payload = payload;
      state.findings = Array.isArray(payload.findings) ? payload.findings : [];
      state.severity = "ALL";
      state.query = "";
      el.search.value = "";
      state.openIndex = null;
      closeDrawer();
      renderResults();
      const total = state.findings.length;
      toast(
        total
          ? `${total} finding${total === 1 ? "" : "s"} across ${payload.meta?.files_scanned?.length ?? files.length} file(s)`
          : "No sink or credential matches — review rules before trusting this.",
        total ? "error" : "success",
        total ? "Scan complete" : "Clean scan"
      );
    } catch (error) {
      toast(error.message, "error", "Scan failed");
    } finally {
      setLoading(false);
      renderResults();
    }
  }

  /* ------------------------------------------------------------------ */
  /* Rendering                                                          */
  /* ------------------------------------------------------------------ */

  function breakdown() {
    const summary = state.payload?.summary || {};
    const counts = summary.severity_breakdown || {};
    return {
      total: Number(summary.total_findings ?? state.findings.length) || 0,
      CRITICAL: Number(counts.CRITICAL || 0),
      HIGH: Number(counts.HIGH || 0),
      MEDIUM: Number(counts.MEDIUM || 0),
      LOW: Number(counts.LOW || 0),
      INFO: Number(counts.INFO || 0),
    };
  }

  function renderResults() {
    const counts = breakdown();
    const hasRun = Boolean(state.payload);

    el.findingsCount.textContent = String(counts.total);
    $("#stat-total").textContent = String(counts.total);
    $("#stat-critical").textContent = String(counts.CRITICAL);
    $("#stat-high").textContent = String(counts.HIGH);
    $("#stat-medium").textContent = String(counts.MEDIUM);
    $("#stat-low").textContent = String(counts.LOW);

    $$("#severity-filters .chip").forEach((chip) => {
      const key = chip.dataset.sev;
      const badge = $("[data-count]", chip);
      if (badge) badge.textContent = String(key === "ALL" ? counts.total : counts[key] || 0);
      chip.classList.toggle("is-active", key === state.severity);
    });

    el.copyBtn.disabled = !hasRun;
    el.exportBtn.disabled = !hasRun;

    if (!hasRun) {
      el.emptyState.classList.remove("hidden");
      el.cleanState.classList.add("hidden");
      el.findingsTable.classList.add("hidden");
      el.resultsSub.textContent = "Run a scan to populate the report.";
      el.resultMeta.textContent = "Ready.";
      return;
    }

    const meta = state.payload.meta || {};
    const filesScanned = Array.isArray(meta.files_scanned) ? meta.files_scanned.length : 0;
    const duration = typeof meta.duration_ms === "number" ? `${meta.duration_ms} ms` : "—";
    el.resultsSub.textContent = `${filesScanned} file${filesScanned === 1 ? "" : "s"} scanned · ${duration} · secrets redacted`;
    el.resultMeta.textContent = meta.files_skipped?.length
      ? `Skipped non-Python: ${meta.files_skipped.join(", ")}`
      : `${filesScanned} file${filesScanned === 1 ? "" : "s"} analysed.`;

    renderTable();
  }

  function filteredFindings() {
    const query = state.query.trim().toLowerCase();
    return state.findings.filter((finding) => {
      if (state.severity !== "ALL" && severityOf(finding) !== state.severity) return false;
      if (!query) return true;
      const haystack = [
        finding.file_path,
        finding.line_number,
        finding.sink,
        finding.category,
        finding.matched_snippet,
        finding.description,
        Array.isArray(finding.arguments_passed) ? finding.arguments_passed.join(" ") : "",
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }

  function renderTable() {
    const rows = filteredFindings();
    el.findingsTable.classList.toggle("hidden", rows.length === 0);
    el.cleanState.classList.toggle("hidden", rows.length > 0 || state.findings.length > 0);
    el.emptyState.classList.add("hidden");

    if (!rows.length) {
      if (state.findings.length > 0) {
        // Filters removed everything: show a quiet inline notice instead of the
        // "clean scan" state, which would be misleading.
        el.findingsTable.classList.remove("hidden");
        el.findingsBody.innerHTML = `
          <tr class="no-matches"><td colspan="6">
            <span class="muted">No findings match this filter.</span>
            <button class="ghost-btn" type="button" id="reset-filters" style="height:24px;padding:0 8px;font-size:11px;margin-left:8px">Reset</button>
          </td></tr>`;
        $("#reset-filters")?.addEventListener("click", () => {
          state.severity = "ALL";
          state.query = "";
          el.search.value = "";
          renderResults();
        });
      }
      return;
    }

    el.findingsBody.innerHTML = "";
    rows.forEach((finding) => {
      const index = state.findings.indexOf(finding);
      const severity = severityOf(finding);
      const line = Number(finding.line_number || 0);
      const evidence = String(finding.matched_snippet || finding.secret_value || "—");
      const tainted = Boolean(finding.user_input_reachable);

      const tr = document.createElement("tr");
      tr.dataset.index = String(index);
      tr.tabIndex = 0;
      tr.classList.toggle("is-open", state.openIndex === index);
      tr.innerHTML = `
        <td><span class="sev sev-${escapeHtml(severity)}">${escapeHtml(severity)}</span></td>
        <td><span class="cat-tag">${escapeHtml(finding.category || "—")}</span></td>
        <td class="loc">
          <span class="loc-file">${escapeHtml(finding.file_path || "—")}</span><span class="loc-line">:${line || "?"}</span>
        </td>
        <td>
          <span class="sink-name">${escapeHtml(finding.sink || "—")}</span>
          ${tainted ? '<span class="taint-flag" title="Argument traces to user input">TAINT</span>' : ""}
        </td>
        <td><span class="evidence" title="${escapeHtml(evidence)}">${escapeHtml(evidence)}</span></td>
        <td class="row-go"><svg aria-hidden="true"><use href="#i-chevron"/></svg></td>`;

      const open = () => openDrawer(index);
      tr.addEventListener("click", open);
      tr.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          open();
        }
      });
      el.findingsBody.appendChild(tr);
    });
  }

  /* ------------------------------------------------------------------ */
  /* Detail drawer                                                      */
  /* ------------------------------------------------------------------ */

  let lastFocused = null;

  function openDrawer(index) {
    const finding = state.findings[index];
    if (!finding) return;
    state.openIndex = index;
    lastFocused = document.activeElement;
    $$("#findings-body tr").forEach((row) =>
      row.classList.toggle("is-open", Number(row.dataset.index) === index)
    );

    const severity = severityOf(finding);
    const line = Number(finding.line_number || 0);
    const args = Array.isArray(finding.arguments_passed) ? finding.arguments_passed : [];
    const tainted = Boolean(finding.user_input_reachable);
    const evidence = String(finding.matched_snippet || finding.secret_value || "");

    el.drawerSub.textContent = `${finding.file_path || "unknown"}:${line || "?"}`;
    el.drawerBody.innerHTML = `
      <div class="d-banner ${escapeHtml(severity)}">
        <span class="sev sev-${escapeHtml(severity)}">${escapeHtml(severity)}</span>
        <span>${escapeHtml(finding.description || "No description supplied.")}</span>
      </div>

      <div class="badge-row">
        <span class="mini-badge">${escapeHtml(finding.category || "UNKNOWN")}</span>
        <span class="mini-badge">sink: ${escapeHtml(finding.sink || "—")}</span>
        ${tainted ? '<span class="mini-badge warn">user input reachable</span>' : ""}
        ${finding.shell_true_present ? '<span class="mini-badge warn">shell=True</span>' : ""}
      </div>

      <div class="d-item">
        <span class="d-label">Location</span>
        <span class="d-value mono">${escapeHtml(finding.file_path || "—")}:${line || "?"}</span>
      </div>

      <div class="d-item">
        <span class="d-label">Evidence · redacted</span>
        <pre class="d-code">${escapeHtml(evidence || "No snippet captured.")}</pre>
        <p class="d-hint">Masked server-side: only the first four characters of a sensitive value survive.</p>
      </div>

      <div class="d-item">
        <span class="d-label">Arguments passed (taint bridge)</span>
        ${
          args.length
            ? `<div class="arg-chips">${args
                .map(
                  (arg) =>
                    `<span class="arg-chip ${tainted ? "tainted" : ""}">${escapeHtml(String(arg))}</span>`
                )
                .join("")}</div>`
            : '<span class="d-value muted">No literal arguments — value comes from a variable.</span>'
        }
        <p class="d-hint">Handed to the analyzer as <code>arguments_passed</code> so data-flow can follow the call.</p>
      </div>

      ${
        finding.secret_value
          ? `<div class="d-item">
               <span class="d-label">Credential · redacted</span>
               <span class="d-value mono">${escapeHtml(String(finding.secret_value))}</span>
             </div>`
          : ""
      }

      <div class="d-item">
        <span class="d-label">Raw finding (redacted JSON)</span>
        <div class="d-fallback">${escapeHtml(JSON.stringify(finding, null, 2))}</div>
      </div>
    `;

    el.drawerBackdrop.hidden = false;
    // Force a frame so the transition runs from the off-canvas position.
    requestAnimationFrame(() => {
      el.drawerBackdrop.classList.add("is-open");
      el.drawer.classList.add("is-open");
      el.drawer.setAttribute("aria-hidden", "false");
    });
    el.drawerClose.focus({ preventScroll: true });
  }

  function closeDrawer() {
    if (!el.drawer.classList.contains("is-open")) {
      state.openIndex = null;
      return;
    }
    el.drawer.classList.remove("is-open");
    el.drawer.setAttribute("aria-hidden", "true");
    el.drawerBackdrop.classList.remove("is-open");
    window.setTimeout(() => {
      el.drawerBackdrop.hidden = true;
    }, 300);
    state.openIndex = null;
    $$("#findings-body tr").forEach((row) => row.classList.remove("is-open"));
    if (lastFocused && typeof lastFocused.focus === "function") {
      lastFocused.focus({ preventScroll: true });
      lastFocused = null;
    }
  }

  /* ------------------------------------------------------------------ */
  /* Export / copy                                                      */
  /* ------------------------------------------------------------------ */

  async function exportReport() {
    const files = collectFiles();
    if (!files.length) return;
    el.exportBtn.disabled = true;
    try {
      const response = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ files }),
      });
      if (!response.ok) throw new Error(`Export failed (${response.status})`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "redteam-report.json";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      toast("redteam-report.json downloaded — redacted at export.", "success", "Report saved");
    } catch (error) {
      toast(error.message, "error", "Export failed");
    } finally {
      el.exportBtn.disabled = !state.payload;
    }
  }

  async function copyJson() {
    if (!state.payload) return;
    const text = JSON.stringify(state.payload, null, 2);
    try {
      await navigator.clipboard.writeText(text);
      toast(`${text.length.toLocaleString()} characters of redacted JSON copied.`, "success", "Copied");
    } catch (_) {
      // Clipboard API needs a secure context; fall back to a textarea.
      const area = document.createElement("textarea");
      area.value = text;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        toast("Redacted JSON copied.", "success", "Copied");
      } catch (error) {
        toast("Clipboard blocked by the browser.", "error", "Copy failed");
      }
      area.remove();
    }
  }

  /* ------------------------------------------------------------------ */
  /* Events                                                             */
  /* ------------------------------------------------------------------ */

  $$(".tab").forEach((tab) =>
    tab.addEventListener("click", () => setMode(tab.dataset.pane))
  );

  el.code.addEventListener("input", () => {
    updateCodeStats();
    updateScanState();
  });
  el.pasteName.addEventListener("input", updateCodeStats);

  el.sampleBtn.addEventListener("click", () => {
    setMode("paste");
    el.code.value = SAMPLE;
    el.pasteName.value = "vulnerable_demo.py";
    updateCodeStats();
    updateScanState();
    el.code.focus();
    toast("Loaded a demo file with eval, os.system, shell=True, pickle and a fake key.", "info", "Sample loaded");
  });

  el.clearBtn.addEventListener("click", () => {
    el.code.value = "";
    el.pasteName.value = "target.py";
    state.files = [];
    state.payload = null;
    state.findings = [];
    state.query = "";
    state.severity = "ALL";
    el.search.value = "";
    renderFileList();
    updateCodeStats();
    updateScanState();
    renderResults();
    toast("Workspace cleared.", "info");
  });

  el.scanBtn.addEventListener("click", runScan);
  el.copyBtn.addEventListener("click", copyJson);
  el.exportBtn.addEventListener("click", exportReport);

  el.dropzone.addEventListener("click", () => el.fileInput.click());
  el.dropzone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      el.fileInput.click();
    }
  });
  el.fileInput.addEventListener("change", async (event) => {
    await addFiles(event.target.files);
    el.fileInput.value = "";
  });

  ["dragenter", "dragover"].forEach((type) =>
    el.dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      el.dropzone.classList.add("is-drag");
    })
  );
  ["dragleave", "drop"].forEach((type) =>
    el.dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      if (type === "dragleave" && el.dropzone.contains(event.relatedTarget)) return;
      el.dropzone.classList.remove("is-drag");
    })
  );
  el.dropzone.addEventListener("drop", (event) => addFiles(event.dataTransfer?.files));

  // Block the browser from navigating away when files land outside the zone.
  window.addEventListener("dragover", (event) => event.preventDefault());
  window.addEventListener("drop", (event) => event.preventDefault());

  el.filelist.addEventListener("click", (event) => {
    const button = event.target.closest("[data-remove]");
    if (!button) return;
    state.files = state.files.filter((file) => file.id !== button.dataset.remove);
    renderFileList();
    updateScanState();
  });

  el.chips.addEventListener("click", (event) => {
    const chip = event.target.closest(".chip");
    if (!chip) return;
    state.severity = chip.dataset.sev;
    renderResults();
  });

  let searchTimer = null;
  el.search.addEventListener("input", (event) => {
    window.clearTimeout(searchTimer);
    const value = event.target.value;
    searchTimer = window.setTimeout(() => {
      state.query = value;
      if (state.payload) renderTable();
    }, 90);
  });

  el.drawerClose.addEventListener("click", closeDrawer);
  el.drawerBackdrop.addEventListener("click", closeDrawer);

  $("#help-btn").addEventListener("click", () => {
    toast(`${modLabel}+Enter run scan · / filter · Esc close panel · Enter open row`, "info", "Keyboard");
  });

  document.addEventListener("keydown", (event) => {
    const tag = (event.target.tagName || "").toLowerCase();
    const typing = tag === "input" || tag === "textarea" || event.target.isContentEditable;

    if (event.key === "Escape") {
      if (el.drawer.classList.contains("is-open")) {
        closeDrawer();
        return;
      }
      if (state.query) {
        state.query = "";
        el.search.value = "";
        renderTable();
      }
      return;
    }

    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      runScan();
      return;
    }

    if (event.key === "/" && !typing) {
      event.preventDefault();
      el.search.focus();
      el.search.select();
    }
  });

  /* ------------------------------------------------------------------ */
  /* Init                                                               */
  /* ------------------------------------------------------------------ */

  updateCodeStats();
  updateScanState();
  renderResults();
  boot();
})();
