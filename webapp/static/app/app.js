/* ============================================================================
   RedTeam Linter — console behaviour
   Views: Scan · Findings · Rules · Assistant
   Everything is rendered with DOM APIs and textContent; no HTML string is ever
   built from server data, so the CSP (no inline script, no inline style) is
   satisfiable and a hostile snippet cannot become markup.
   ========================================================================= */

'use strict';

/* ------------------------------- utilities ------------------------------- */

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const TRIAGE_STATES = ['open', 'confirmed', 'false-positive', 'fixed'];
const TRIAGE_LABELS = {
  open: 'Open',
  confirmed: 'Confirmed',
  'false-positive': 'False positive',
  fixed: 'Fixed'
};

const STORE_TRIAGE = 'redteam.triage.v1';
const STORE_NOTIF = 'redteam.notif.v1';

const VIEW_META = {
  scan: { title: 'Scan', subtitle: 'Paste code or drop Python files, then run the linter.' },
  findings: { title: 'Findings', subtitle: 'Filter, group and triage the redacted report.' },
  rules: { title: 'Rules', subtitle: 'The sink table the analyzer is currently running.' },
  assistant: { title: 'Assistant', subtitle: 'Ask about a finding, a sink or how the tool behaves.' },
  notfound: { title: 'Not found', subtitle: 'That view does not exist — pick one from the sidebar.' }
};

const SAMPLE_FALLBACK = [
  'import os',
  'import pickle',
  '',
  'API_KEY = "sk_live_51H8xQ2f9Kd0aPz7Tm"',
  '',
  'def handler(request):',
  '    expr = request.args.get("expr")',
  '    return eval(expr)',
  '',
  'def run(host):',
  '    os.system("ping -c 1 " + host)',
  '',
  'def load(blob):',
  '    return pickle.loads(blob)',
  ''
].join('\n');

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value === true) node.setAttribute(key, '');
    else node.setAttribute(key, String(value));
  }
  for (const child of children.flat(3)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

function icon(name, className) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  if (className) svg.setAttribute('class', className);
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', '#i-' + name);
  svg.append(use);
  return svg;
}

function safeParse(raw, fallback) {
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function readStore(key, fallback) {
  try {
    return safeParse(localStorage.getItem(key), fallback);
  } catch {
    return fallback;
  }
}

function writeStore(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage disabled — triage stays in memory for this session */
  }
}

function relativeTime(stamp) {
  const seconds = Math.max(0, Math.round((Date.now() - stamp) / 1000));
  if (seconds < 45) return 'just now';
  if (seconds < 3600) return Math.round(seconds / 60) + 'm ago';
  if (seconds < 86400) return Math.round(seconds / 3600) + 'h ago';
  return new Date(stamp).toLocaleDateString();
}

function severityClass(severity) {
  const value = String(severity || '').toUpperCase();
  return SEVERITIES.includes(value) ? value.toLowerCase() : 'unknown';
}

/* --------------------------------- state --------------------------------- */

const state = {
  view: 'scan',
  mode: 'paste',
  busy: false,
  files: [],
  scan: null,
  health: null,
  rules: null,
  filters: { severity: 'ALL', triage: 'all', query: '', group: 'none', sort: 'severity' },
  triage: readStore(STORE_TRIAGE, {}),
  notifications: readStore(STORE_NOTIF, []),
  selectedId: null,
  assistant: {
    messages: [],
    contextId: null,
    status: null,
    busy: false
  }
};

/* ------------------------------ notifications ---------------------------- */

function notify({ kind = 'info', title, body }) {
  state.notifications.unshift({
    id: String(Date.now()) + Math.random().toString(16).slice(2),
    kind,
    title,
    body,
    at: Date.now(),
    read: false
  });
  state.notifications = state.notifications.slice(0, 60);
  writeStore(STORE_NOTIF, state.notifications);
  renderNotifications();
}

function renderNotifications() {
  const list = $('#notif-list');
  const empty = $('#notif-empty');
  const badge = $('#bell-badge');
  if (!list || !badge) return;

  list.replaceChildren();
  const unread = state.notifications.filter((item) => !item.read).length;

  badge.hidden = unread === 0;
  badge.textContent = unread > 9 ? '9+' : String(unread);

  empty.hidden = state.notifications.length > 0;

  for (const item of state.notifications) {
    const iconName = item.kind === 'critical' || item.kind === 'error'
      ? 'alert'
      : item.kind === 'success'
        ? 'check'
        : item.kind === 'assistant'
          ? 'spark'
          : 'info';
    const iconClass = ['pop-icon', item.kind === 'critical' || item.kind === 'error' ? 'is-critical' : '', item.kind === 'success' ? 'is-success' : '', 'is-info'].join(' ').trim();
    list.append(
      el('li', { class: 'pop-item' + (item.read ? '' : ' is-unread') },
        el('span', { class: iconClass }, icon(iconName)),
        el('div', {},
          el('div', { class: 'pop-title', text: item.title }),
          item.body ? el('div', { class: 'pop-body', text: item.body }) : null,
          el('div', { class: 'pop-time', text: relativeTime(item.at) })
        )
      )
    );
  }
}

function markAllRead() {
  state.notifications = state.notifications.map((item) => ({ ...item, read: true }));
  writeStore(STORE_NOTIF, state.notifications);
  renderNotifications();
}

function clearNotifications() {
  state.notifications = [];
  writeStore(STORE_NOTIF, state.notifications);
  renderNotifications();
}

function toggleNotifications(force) {
  const panel = $('#notif-panel');
  const button = $('#bell-btn');
  const open = typeof force === 'boolean' ? force : panel.hidden;
  panel.hidden = !open;
  button.setAttribute('aria-expanded', String(open));
  if (open) markAllRead();
}

/* --------------------------------- toasts -------------------------------- */

function toast(message, kind = 'info') {
  const region = $('#toasts');
  if (!region) return;
  const iconName = kind === 'success' ? 'check' : kind === 'error' ? 'alert' : kind === 'warn' ? 'alert' : 'info';
  const node = el('div', { class: 'toast is-' + kind, role: 'status' },
    icon(iconName, 'toast-icon'),
    el('div', { class: 'toast-text', text: message }),
    el('button', { class: 'toast-close', type: 'button', 'aria-label': 'Dismiss' }, icon('close'))
  );
  node.querySelector('.toast-close').addEventListener('click', () => remove());
  region.append(node);

  let removed = false;
  function remove() {
    if (removed) return;
    removed = true;
    node.classList.add('is-leaving');
    setTimeout(() => node.remove(), 200);
  }
  setTimeout(remove, 4800);
}

/* ------------------------------- navigation ------------------------------- */

function showView(name, options = {}) {
  const view = VIEW_META[name] ? name : 'notfound';
  state.view = view;

  $$('.nav-item').forEach((item) => {
    const active = item.dataset.view === view;
    item.classList.toggle('is-active', active);
    if (active) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });

  $$('.view').forEach((section) => section.classList.toggle('is-active', section.id === 'view-' + view));

  $('#view-title').textContent = VIEW_META[view].title;
  $('#view-subtitle').textContent = VIEW_META[view].subtitle;

  if (options.hash !== false) {
    const target = '#/' + view;
    if (location.hash !== target) history.replaceState(null, '', target);
  }
  if (view === 'assistant') {
    const input = $('#chat-input');
    if (input) input.focus({ preventScroll: true });
  }
}

/* --------------------------------- health -------------------------------- */

async function loadHealth() {
  try {
    const response = await fetch('/api/health', { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error('health ' + response.status);
    state.health = await response.json();
    const pill = $('#engine-pill');
    pill.classList.add('is-ok');
    pill.classList.remove('is-bad');
    $('#engine-text').textContent = state.health.engine + ' · ' + state.health.rules + ' rules';
    $('#rule-source').textContent = state.health.rule_source || '';
    const footer = $('#footer-version');
    if (footer) {
      footer.textContent = 'v' + (state.health.version || '0.2.0') + ' · ' + state.health.rules + ' rules';
    }
    const heroRules = $('#hero-rules');
    if (heroRules) heroRules.textContent = String(state.health.rules);
  } catch {
    const pill = $('#engine-pill');
    pill.classList.add('is-bad');
    pill.classList.remove('is-ok');
    $('#engine-text').textContent = 'offline';
  }
}

async function loadRules() {
  try {
    const response = await fetch('/api/rules', { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error('rules ' + response.status);
    state.rules = await response.json();
  } catch {
    state.rules = null;
  }
  renderRules();
}

function renderRules() {
  const grid = $('#rules-grid');
  if (!grid) return;
  grid.replaceChildren();

  const rules = state.rules?.rules || [];
  $('#rules-total').textContent = String(rules.length);
  $('#rules-source').textContent = state.rules?.source || 'unavailable';

  if (!rules.length) {
    grid.append(el('p', { class: 'meta-line', text: 'The rule table could not be loaded.' }));
    return;
  }

  for (const rule of rules) {
    grid.append(
      el('div', { class: 'rule-card' },
        el('div', { class: 'rule-top' },
          el('span', { class: 'rule-name', text: rule.name || 'unnamed' }),
          el('span', { class: 'badge-cat', text: rule.category || 'ANY' })
        ),
        el('p', { class: 'rule-desc', text: rule.description || 'No description provided.' }),
        el('div', { class: 'rule-flags' },
          el('span', { class: 'flag' + (rule.requires_shell_true ? ' is-on' : ''), text: rule.requires_shell_true ? 'needs shell=True' : 'any call' }),
          el('span', { class: 'flag', text: 'yaml rule' })
        )
      )
    );
  }
}

/* ---------------------------------- files -------------------------------- */

function updateCodeStats() {
  const code = $('#code');
  const stats = $('#code-stats');
  if (!code || !stats) return;
  const value = code.value;
  const lines = value ? value.split('\n').length : 0;
  const bytes = new TextEncoder().encode(value).length;
  stats.textContent = lines + ' lines · ' + (bytes < 1024 ? bytes + ' B' : (bytes / 1024).toFixed(1) + ' KB');
  $('#editor-file').textContent = $('#paste-name').value || 'target.py';
  updateScanEnabled();
}

function renderFiles() {
  const list = $('#filelist');
  if (!list) return;
  list.replaceChildren();

  state.files.forEach((file, index) => {
    const size = file.size < 1024 ? file.size + ' B' : (file.size / 1024).toFixed(1) + ' KB';
    const remove = el('button', { class: 'file-remove', type: 'button', 'aria-label': 'Remove ' + file.name }, icon('close'));
    remove.addEventListener('click', () => {
      state.files.splice(index, 1);
      renderFiles();
    });
    list.append(
      el('li', { class: 'file-item' },
        icon('file'),
        el('span', { class: 'file-name', text: file.name }),
        el('span', { class: 'file-size', text: size }),
        remove
      )
    );
  });
}

async function addFiles(fileList) {
  const incoming = Array.from(fileList || []);
  for (const file of incoming) {
    if (!/\.py$/i.test(file.name)) {
      toast(file.name + ' is not a .py file — skipped.', 'warn');
      continue;
    }
    if (file.size > 2 * 1024 * 1024) {
      toast(file.name + ' is larger than 2 MB — skipped.', 'warn');
      continue;
    }
    if (state.files.some((existing) => existing.name === file.name)) {
      toast(file.name + ' is already in the list.', 'warn');
      continue;
    }
    try {
      state.files.push({ name: file.name, content: await file.text(), size: file.size });
    } catch {
      toast('Could not read ' + file.name + '.', 'error');
    }
  }
  renderFiles();
  updateScanEnabled();
}

function resolveDocuments() {
  if (state.mode === 'paste') {
    const content = $('#code').value;
    if (!content.trim()) return [];
    return [{ path: ($('#paste-name').value || 'target.py').trim() || 'target.py', content }];
  }
  return state.files.map((file) => ({ path: file.name, content: file.content }));
}

function updateScanEnabled() {
  const button = $('#scan-btn');
  if (!button) return;
  button.disabled = state.busy || resolveDocuments().length === 0;
}

/* ---------------------------------- scan --------------------------------- */

function decorateFindings(payload) {
  return (payload.findings || []).map((finding, index) => ({
    ...finding,
    id: [finding.file_path, finding.line_number, finding.sink, index].join(':'),
    key: [finding.file_path, finding.line_number, finding.sink].join(':')
  }));
}

function setLoading(active, label) {
  state.busy = active;
  const loading = $('#loading-state');
  if (!loading) return;
  loading.hidden = !active;
  if (label) $('#loading-text').textContent = label;
  if (active) {
    $('#empty-state').hidden = true;
    $('#clean-state').hidden = true;
    $('#no-match-state').hidden = true;
    $('#findings-table').hidden = true;
    $('#grouped-view').hidden = true;
  }
  updateScanEnabled();
  // Findings are rendered only once the busy flag is clear, so re-render on
  // the way out instead of leaving the table empty after a scan.
  if (!active) renderFindings();
}

async function runScan() {
  if (state.busy) return;
  const documents = resolveDocuments();
  if (!documents.length) {
    toast('Add code or a .py file first.', 'warn');
    return;
  }

  setLoading(true, 'Parsing AST…');
  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ files: documents })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(typeof data.detail === 'string' ? data.detail : 'Scan failed (' + response.status + ').');
    }

    state.scan = { payload: data, findings: decorateFindings(data), at: Date.now() };
    state.filters.severity = 'ALL';
    setLoading(false);
    renderAll();
    showView('findings');
    openSummaryOnce();
  } catch (error) {
    toast(error.message, 'error');
    notify({ kind: 'error', title: 'Scan failed', body: error.message });
  } finally {
    setLoading(false);
    updateScanEnabled();
  }
}

function openSummaryOnce() {
  const summary = state.scan?.payload?.summary;
  const total = summary?.total_findings ?? 0;
  const critical = summary?.severity_breakdown?.CRITICAL ?? 0;
  const meta = state.scan?.payload?.meta || {};
  const files = (meta.files_scanned || []).length;

  toast(total + ' finding' + (total === 1 ? '' : 's') + ' across ' + files + ' file' + (files === 1 ? '' : 's') + '.', total ? (critical ? 'warn' : 'info') : 'success');
  notify({
    kind: critical ? 'critical' : total ? 'info' : 'success',
    title: total ? total + ' findings in ' + files + ' file' + (files === 1 ? '' : 's') : 'Scan clean',
    body: total
      ? critical + ' critical · ' + (summary.severity_breakdown.HIGH || 0) + ' high · ' + (summary.severity_breakdown.MEDIUM || 0) + ' medium'
      : 'Nothing matched the active rules.'
  });
}

/* -------------------------------- filtering ------------------------------ */

function counts() {
  const findings = state.scan?.findings || [];
  const bySeverity = { ALL: findings.length };
  SEVERITIES.forEach((severity) => {
    bySeverity[severity] = findings.filter((finding) => finding.severity === severity).length;
  });
  return bySeverity;
}

function triageOf(finding) {
  return state.triage[finding.key] || 'open';
}

function filteredFindings() {
  const findings = state.scan?.findings || [];
  const query = state.filters.query.trim().toLowerCase();
  const severity = state.filters.severity;
  const triage = state.filters.triage;

  const rows = findings.filter((finding) => {
    if (severity !== 'ALL' && finding.severity !== severity) return false;
    if (triage !== 'all' && triageOf(finding) !== triage) return false;
    if (!query) return true;
    const haystack = [
      finding.file_path,
      finding.line_number,
      finding.sink,
      finding.category,
      finding.description,
      finding.matched_snippet,
      finding.secret_value,
      (finding.arguments_passed || []).join(' ')
    ].join(' ').toLowerCase();
    return haystack.includes(query);
  });

  const bySeverity = (a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity);
  const sort = state.filters.sort;
  return rows.sort((a, b) => {
    if (sort === 'location') {
      return String(a.file_path).localeCompare(String(b.file_path)) || (a.line_number || 0) - (b.line_number || 0);
    }
    if (sort === 'sink') {
      return String(a.sink).localeCompare(String(b.sink)) || bySeverity(a, b);
    }
    return bySeverity(a, b) || String(a.file_path).localeCompare(String(b.file_path)) || (a.line_number || 0) - (b.line_number || 0);
  });
}

/* -------------------------------- rendering ------------------------------ */

function renderAll() {
  const tally = counts();

  // summary tiles on the scan view
  $('#sum-total').textContent = String(tally.ALL);
  $('#sum-critical').textContent = String(tally.CRITICAL);
  $('#sum-high').textContent = String(tally.HIGH);
  $('#sum-medium').textContent = String(tally.MEDIUM);
  $('#sum-low').textContent = String(tally.LOW || 0);

  const badge = $('#scan-badge');
  if (state.scan) {
    badge.textContent = tally.ALL + ' finding' + (tally.ALL === 1 ? '' : 's');
  } else {
    badge.textContent = 'no scan yet';
  }

  $('#findings-count').textContent = String(tally.ALL);
  const navCount = $('#nav-findings-count');
  navCount.hidden = tally.ALL === 0;
  navCount.textContent = tally.ALL > 99 ? '99+' : String(tally.ALL);

  $('#open-findings-btn').disabled = !state.scan;
  $('#copy-btn').disabled = !state.scan;
  $('#export-btn').disabled = !state.scan;

  // chips
  $$('#severity-filters .chip').forEach((chip) => {
    const value = chip.dataset.sev;
    const count = chip.querySelector('.chip-count');
    if (count) count.textContent = String(tally[value] ?? 0);
    chip.classList.toggle('is-active', state.filters.severity === value);
  });

  $$('#triage-filters .chip').forEach((chip) => {
    chip.classList.toggle('is-active', state.filters.triage === chip.dataset.triage);
  });

  $$('#group-toggle .seg-btn').forEach((button) => {
    button.classList.toggle('is-active', state.filters.group === button.dataset.group);
  });

  renderMeta();
  renderFindings();
}

function renderMeta() {
  const meta = state.scan?.payload?.meta;
  const summary = state.scan?.payload?.summary;
  const sub = $('#results-sub');
  const foot = $('#result-meta');
  const timing = $('#result-timing');
  const scanMeta = $('#scan-meta');

  if (!state.scan) {
    sub.textContent = 'No scan data yet.';
    foot.textContent = 'Ready.';
    timing.textContent = '';
    scanMeta.textContent = 'Run a scan to see counts, timing and the rule source.';
    return;
  }

  const files = meta?.files_scanned?.length ?? summary?.total_files_scanned ?? 0;
  const skipped = meta?.files_skipped?.length ?? 0;
  const parts = [
    files + ' file' + (files === 1 ? '' : 's') + ' scanned',
    (meta?.duration_ms ?? 0) + ' ms',
    'secrets redacted'
  ];
  if (skipped) parts.push(skipped + ' skipped');
  sub.textContent = parts.join(' · ');

  const shown = filteredFindings().length;
  foot.textContent = shown + ' of ' + (summary?.total_findings ?? 0) + ' shown · ' + files + ' analysed';
  timing.textContent = (meta?.rule_source || '') + ' · ' + (meta?.rules_loaded || 0) + ' rules';
  scanMeta.textContent = files + ' file' + (files === 1 ? '' : 's') + ' · ' + (summary?.total_findings ?? 0) + ' findings · ' + (meta?.duration_ms ?? 0) + ' ms';
}

function locationCell(finding) {
  const wrapper = el('span', { class: 'loc' },
    el('span', { class: 'loc-file', text: finding.file_path || 'unknown' }),
    el('span', { class: 'loc-line', text: ':' + (finding.line_number || '?') })
  );
  if (finding.user_input_reachable) wrapper.append(el('span', { class: 'taint', text: 'TAINT' }));
  return wrapper;
}

function evidenceText(finding) {
  const raw = finding.matched_snippet || finding.secret_value || '—';
  return String(raw).replace(/\s+/g, ' ').trim();
}

function rowFor(finding) {
  const row = el('tr', { tabindex: '0' },
    el('td', { class: 'col-status' },
      el('span', { class: 'status-dot', dataset: { status: triageOf(finding) }, title: TRIAGE_LABELS[triageOf(finding)] })
    ),
    el('td', {},
      el('span', { class: 'sev is-' + severityClass(finding.severity) },
        el('span', { text: finding.severity })
      )
    ),
    el('td', {}, el('span', { class: 'mono', text: finding.sink || '—' })),
    el('td', {}, el('span', { class: 'badge-cat', text: finding.category || 'ANY' })),
    el('td', {}, locationCell(finding)),
    el('td', {}, el('span', { class: 'evidence', text: evidenceText(finding) })),
    el('td', { class: 'col-go' }, icon('chevron', 'chev'))
  );
  row.dataset.id = finding.id;
  row.classList.toggle('is-selected', state.selectedId === finding.id);
  row.addEventListener('click', () => openDetail(finding.id));
  row.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      openDetail(finding.id);
    }
  });
  return row;
}

function groupRow(finding) {
  const row = el('button', { class: 'group-row', type: 'button' },
    el('span', { class: 'sev is-' + severityClass(finding.severity), text: finding.severity }),
    el('span', { class: 'mono', text: finding.sink || '—' }),
    locationCell(finding),
    el('span', { class: 'evidence', text: evidenceText(finding) }),
    icon('chevron', 'chev')
  );
  row.addEventListener('click', () => openDetail(finding.id));
  return row;
}

function renderGrouped(rows) {
  const container = $('#grouped-view');
  container.replaceChildren();

  const mode = state.filters.group;
  const buckets = new Map();

  for (const finding of rows) {
    const key = mode === 'file' ? finding.file_path || 'unknown' : finding.severity;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(finding);
  }

  const keys = Array.from(buckets.keys()).sort((a, b) => {
    if (mode === 'severity') return SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b);
    return String(a).localeCompare(String(b));
  });

  for (const key of keys) {
    const items = buckets.get(key);
    const head = el('div', { class: 'group-head' }, icon(mode === 'file' ? 'file' : 'shield'));
    head.append(
      el('span', { class: 'group-name', text: key }),
      el('span', { class: 'group-meta', text: items.length + ' finding' + (items.length === 1 ? '' : 's') })
    );
    const rowsBox = el('div', { class: 'group-rows' });
    items.forEach((finding) => rowsBox.append(groupRow(finding)));
    container.append(el('section', { class: 'group' }, head, rowsBox));
  }
}

function renderFindings() {
  const table = $('#findings-table');
  const grouped = $('#grouped-view');
  const empty = $('#empty-state');
  const clean = $('#clean-state');
  const noMatch = $('#no-match-state');
  const loading = $('#loading-state');

  if (state.busy) return;

  const total = state.scan?.findings?.length ?? 0;
  const rows = filteredFindings();

  loading.hidden = true;

  if (!state.scan) {
    empty.hidden = false;
    clean.hidden = true;
    noMatch.hidden = true;
    table.hidden = true;
    grouped.hidden = true;
    $('#findings-body').replaceChildren();
    return;
  }

  if (total === 0) {
    empty.hidden = true;
    clean.hidden = false;
    noMatch.hidden = true;
    table.hidden = true;
    grouped.hidden = true;
    $('#findings-body').replaceChildren();
    return;
  }

  if (rows.length === 0) {
    empty.hidden = true;
    clean.hidden = true;
    noMatch.hidden = false;
    table.hidden = true;
    grouped.hidden = true;
    $('#findings-body').replaceChildren();
    return;
  }

  empty.hidden = true;
  clean.hidden = true;
  noMatch.hidden = true;

  if (state.filters.group === 'none') {
    table.hidden = false;
    grouped.hidden = true;
    const body = $('#findings-body');
    body.replaceChildren();
    rows.forEach((finding) => body.append(rowFor(finding)));
  } else {
    table.hidden = true;
    grouped.hidden = false;
    renderGrouped(rows);
  }
}

/* ------------------------------ detail sheet ----------------------------- */

function section(title, ...children) {
  return el('section', { class: 'sheet-section' }, el('h4', { text: title }), ...children);
}

function triageControls(finding) {
  const row = el('div', { class: 'triage-row' });
  for (const status of TRIAGE_STATES) {
    const button = el('button', {
      class: 'triage-btn' + (triageOf(finding) === status ? ' is-active' : ''),
      type: 'button',
      dataset: { status },
      text: TRIAGE_LABELS[status]
    });
    button.addEventListener('click', () => {
      if (status === 'open') delete state.triage[finding.key];
      else state.triage[finding.key] = status;
      writeStore(STORE_TRIAGE, state.triage);
      renderAll();
      openDetail(finding.id);
      notify({ kind: 'info', title: 'Triage updated', body: finding.file_path + ':' + finding.line_number + ' marked ' + TRIAGE_LABELS[status].toLowerCase() });
    });
    row.append(button);
  }
  return row;
}

function sourceView(finding) {
  const context = Array.isArray(finding.source_context) ? finding.source_context : [];
  const wrapper = el('div', { class: 'code-view' });
  if (!context.length) {
    wrapper.append(el('div', { class: 'code-line' }, el('span', { class: 'code-num', text: '—' }), el('span', { class: 'code-text', text: 'No source excerpt available for this finding.' })));
    return wrapper;
  }
  for (const line of context) {
    wrapper.append(
      el('div', { class: 'code-line' + (line.target ? ' is-target' : '') },
        el('span', { class: 'code-num', text: String(line.line) }),
        el('span', { class: 'code-text', text: line.text === '' ? ' ' : line.text })
      )
    );
  }
  return wrapper;
}

function openDetail(id) {
  const finding = (state.scan?.findings || []).find((item) => item.id === id);
  if (!finding) return;
  state.selectedId = id;

  $('#detail-title').replaceChildren(
    el('span', { class: 'sev is-' + severityClass(finding.severity), text: finding.severity }),
    el('span', { text: finding.sink || 'finding' })
  );
  $('#detail-sub').textContent = (finding.file_path || 'unknown') + ':' + (finding.line_number || '?');

  const body = $('#detail-body');
  body.replaceChildren();

  body.append(section('Triage', triageControls(finding)));

  if (finding.description) body.append(section('Why it matters', el('p', { text: finding.description })));

  body.append(
    section('Evidence (masked)',
      el('div', { class: 'argchips' },
        el('div', { class: 'argchip', text: evidenceText(finding) })
      )
    )
  );

  const args = Array.isArray(finding.arguments_passed) ? finding.arguments_passed : [];
  const argBox = el('div', { class: 'argchips' });
  if (args.length) {
    args.forEach((argument) => argBox.append(el('div', { class: 'argchip', text: String(argument) })));
  } else {
    argBox.append(el('div', { class: 'argchip is-empty', text: 'No arguments recorded — this finding came from a credential pattern.' }));
  }
  body.append(section('Arguments passed · taint bridge', argBox));

  body.append(section('Source (values masked)', sourceView(finding)));

  const kv = el('div', { class: 'kv' },
    el('span', { class: 'kv-key', text: 'File' }), el('span', { class: 'kv-val', text: finding.file_path || '—' }),
    el('span', { class: 'kv-key', text: 'Line' }), el('span', { class: 'kv-val', text: String(finding.line_number || '?') }),
    el('span', { class: 'kv-key', text: 'Category' }), el('span', { class: 'kv-val', text: finding.category || '—' }),
    el('span', { class: 'kv-key', text: 'Rule' }), el('span', { class: 'kv-val', text: finding.rule_id || finding.sink || '—' }),
    el('span', { class: 'kv-key', text: 'Taint' }), el('span', { class: 'kv-val', text: finding.user_input_reachable ? 'argument traces to user input' : 'no direct taint signal' }),
    el('span', { class: 'kv-key', text: 'shell=True' }), el('span', { class: 'kv-val', text: finding.shell_true_present ? 'present' : 'not present' })
  );
  body.append(section('Metadata', kv));

  const actions = el('div', { class: 'sheet-actions' });
  const copy = el('button', { class: 'btn btn-ghost', type: 'button' }, icon('copy'), el('span', { text: 'Copy finding JSON' }));
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(finding, null, 2));
      toast('Finding JSON copied.', 'success');
    } catch {
      toast('Clipboard blocked by the browser.', 'error');
    }
  });

  const ask = el('button', { class: 'btn btn-primary', type: 'button' }, icon('spark'), el('span', { text: 'Ask assistant' }));
  ask.addEventListener('click', () => {
    state.assistant.contextId = finding.id;
    renderChatContext();
    showView('assistant');
    const input = $('#chat-input');
    input.value = 'Explain this finding and how to fix it.';
    input.focus();
  });

  actions.append(copy, ask);
  body.append(section('Actions', actions));

  $('#detail-backdrop').hidden = false;
  const sheet = $('#detail');
  sheet.classList.add('is-open');
  sheet.setAttribute('aria-hidden', 'false');
  renderFindings();
  $('#detail-close').focus({ preventScroll: true });
}

function closeDetail() {
  const sheet = $('#detail');
  if (!sheet.classList.contains('is-open')) return;
  sheet.classList.remove('is-open');
  sheet.setAttribute('aria-hidden', 'true');
  $('#detail-backdrop').hidden = true;
  state.selectedId = null;
  renderFindings();
}

/* ------------------------------ focus trap ------------------------------- */

function trapFocus(container) {
  if (!container) return;
  const selector = 'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';
  container.addEventListener('keydown', (event) => {
    if (event.key !== 'Tab') return;
    const items = $$(selector, container).filter((node) => node.offsetParent !== null);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
}

/* -------------------------------- assistant ------------------------------ */

function addMessage(role, text, meta) {
  state.assistant.messages.push({ role, text, meta: meta || '' });
  renderChat();
}

function renderChat() {
  const log = $('#chat-log');
  if (!log) return;
  log.replaceChildren();

  for (const message of state.assistant.messages) {
    log.append(
      el('div', { class: 'msg ' + (message.role === 'user' ? 'is-user' : 'is-bot') },
        el('span', { class: 'msg-role', text: message.role === 'user' ? 'you' : 'assistant' }),
        el('div', { class: 'msg-bubble', text: message.text }),
        message.meta ? el('span', { class: 'msg-meta', text: message.meta }) : null
      )
    );
  }
  log.scrollTop = log.scrollHeight;
}

function renderChatContext() {
  const box = $('#chat-context');
  const finding = (state.scan?.findings || []).find((item) => item.id === state.assistant.contextId);
  if (!finding) {
    state.assistant.contextId = null;
    box.hidden = true;
    return;
  }
  box.hidden = false;
  $('#chat-context-text').textContent = finding.severity + ' · ' + finding.sink + ' · ' + finding.file_path + ':' + finding.line_number;
}

function assistantPayload(finding) {
  if (!finding) return null;
  return {
    file_path: finding.file_path,
    line_number: finding.line_number,
    severity: finding.severity,
    category: finding.category,
    sink: finding.sink,
    description: finding.description,
    user_input_reachable: Boolean(finding.user_input_reachable),
    shell_true_present: Boolean(finding.shell_true_present)
  };
}

async function askAssistant(question) {
  const text = String(question || '').trim();
  if (!text || state.assistant.busy) return;

  const finding = (state.scan?.findings || []).find((item) => item.id === state.assistant.contextId) || null;
  addMessage('user', text);
  state.assistant.busy = true;
  $('#chat-send').disabled = true;

  const pending = el('div', { class: 'msg is-bot', id: 'chat-pending' },
    el('span', { class: 'msg-role', text: 'assistant' }),
    el('div', { class: 'msg-bubble', text: 'Thinking…' })
  );
  $('#chat-log').append(pending);
  $('#chat-log').scrollTop = $('#chat-log').scrollHeight;

  try {
    const response = await fetch('/api/assistant', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ question: text, finding: assistantPayload(finding) })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'Assistant failed (' + response.status + ').');

    const mode = data.mode === 'llm' ? 'model: ' + data.model : 'local knowledge base';
    addMessage('assistant', data.answer, mode + ' · ' + (data.duration_ms ?? 0) + ' ms');
    if (data.fallback_reason) toast('Provider unreachable — answered offline.', 'warn');
    notify({ kind: 'assistant', title: 'Assistant replied', body: text.slice(0, 90) });
  } catch (error) {
    pending.remove();
    addMessage('assistant', 'I could not answer that: ' + error.message);
    toast(error.message, 'error');
  } finally {
    state.assistant.busy = false;
    $('#chat-send').disabled = false;
  }
}

async function loadAssistantStatus() {
  try {
    const response = await fetch('/api/assistant/status', { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error('status ' + response.status);
    state.assistant.status = await response.json();
  } catch {
    state.assistant.status = null;
  }
  const badge = $('#assistant-mode');
  const disclaimer = $('#assistant-disclaimer');
  if (state.assistant.status) {
    const mode = state.assistant.status.mode;
    badge.textContent = mode === 'llm' ? 'model · ' + state.assistant.status.model : 'local';
    disclaimer.textContent = state.assistant.status.disclaimer;
  } else {
    badge.textContent = 'offline';
    if (disclaimer) disclaimer.textContent = 'Assistant status unavailable.';
  }
}

/* ------------------------------ export / copy ---------------------------- */

async function copyJson() {
  if (!state.scan) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(state.scan.payload, null, 2));
    toast('Redacted report copied to the clipboard.', 'success');
    notify({ kind: 'success', title: 'Report copied', body: 'JSON payload copied to the clipboard.' });
  } catch {
    toast('Clipboard blocked by the browser.', 'error');
  }
}

async function exportReport() {
  const documents = resolveDocuments();
  if (!documents.length) return;
  $('#export-btn').disabled = true;
  try {
    const response = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ files: documents })
    });
    if (!response.ok) throw new Error('Export failed (' + response.status + ').');
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = el('a', { href: url, download: 'redteam-report.json' });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    toast('Redacted report downloaded.', 'success');
    notify({ kind: 'success', title: 'Report exported', body: 'redteam-report.json downloaded with masked evidence.' });
  } catch (error) {
    toast(error.message, 'error');
    notify({ kind: 'error', title: 'Export failed', body: error.message });
  } finally {
    $('#export-btn').disabled = !state.scan;
  }
}

/* ---------------------------------- events ------------------------------- */

function bindEvents() {
  $$('.nav-item').forEach((item) => {
    item.addEventListener('click', () => showView(item.dataset.view));
  });

  window.addEventListener('hashchange', () => {
    const requested = location.hash.replace('#/', '');
    const next = VIEW_META[requested] ? requested : 'notfound';
    if (next !== state.view) showView(next, { hash: false });
  });

  // input tabs
  $$('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      state.mode = tab.dataset.pane;
      $$('.tab').forEach((other) => {
        const active = other === tab;
        other.classList.toggle('is-active', active);
        other.setAttribute('aria-selected', String(active));
      });
      $('#pane-paste').classList.toggle('is-hidden', state.mode !== 'paste');
      $('#pane-upload').classList.toggle('is-hidden', state.mode !== 'upload');
      updateScanEnabled();
    });
  });

  $('#code').addEventListener('input', updateCodeStats);
  $('#paste-name').addEventListener('input', updateCodeStats);

  const dropzone = $('#dropzone');
  const fileInput = $('#file-input');
  dropzone.addEventListener('click', () => fileInput.click());
  dropzone.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      fileInput.click();
    }
  });
  fileInput.addEventListener('change', async () => {
    await addFiles(fileInput.files);
    fileInput.value = '';
  });
  ['dragenter', 'dragover'].forEach((type) => {
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      dropzone.classList.add('is-drag');
    });
  });
  ['dragleave', 'drop'].forEach((type) => {
    dropzone.addEventListener(type, (event) => {
      event.preventDefault();
      dropzone.classList.remove('is-drag');
    });
  });
  dropzone.addEventListener('drop', async (event) => {
    if (event.dataTransfer?.files?.length) await addFiles(event.dataTransfer.files);
  });

  $('#scan-btn').addEventListener('click', runScan);
  $('#clear-btn').addEventListener('click', () => {
    $('#code').value = '';
    state.files = [];
    renderFiles();
    updateCodeStats();
    toast('Target cleared.', 'info');
  });

  $('#sample-btn').addEventListener('click', async () => {
    let content = SAMPLE_FALLBACK;
    let name = 'vulnerable_demo.py';
    try {
      const response = await fetch('/samples/vulnerable_target.py');
      if (response.ok) {
        content = await response.text();
        name = 'vulnerable_target.py';
      }
    } catch {
      /* offline: fall back to the embedded fixture */
    }
    state.mode = 'paste';
    $$('.tab').forEach((tab) => {
      const active = tab.dataset.pane === 'paste';
      tab.classList.toggle('is-active', active);
      tab.setAttribute('aria-selected', String(active));
    });
    $('#pane-paste').classList.remove('is-hidden');
    $('#pane-upload').classList.add('is-hidden');
    $('#code').value = content;
    $('#paste-name').value = name;
    updateCodeStats();
    toast('Sample loaded — run the scan.', 'info');
  });

  $$('#severity-filters .chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      state.filters.severity = chip.dataset.sev;
      renderAll();
    });
  });

  $$('#triage-filters .chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      state.filters.triage = chip.dataset.triage;
      renderAll();
    });
  });

  $$('#group-toggle .seg-btn').forEach((button) => {
    button.addEventListener('click', () => {
      state.filters.group = button.dataset.group;
      renderAll();
    });
  });

  $('#search').addEventListener('input', (event) => {
    state.filters.query = event.target.value;
    renderAll();
  });

  $('#sort-select').addEventListener('change', (event) => {
    state.filters.sort = event.target.value;
    renderAll();
  });

  $('#reset-filters').addEventListener('click', () => {
    state.filters = { severity: 'ALL', triage: 'all', query: '', group: 'none', sort: 'severity' };
    $('#search').value = '';
    $('#sort-select').value = 'severity';
    renderAll();
  });

  $('#copy-btn').addEventListener('click', copyJson);
  $('#export-btn').addEventListener('click', exportReport);
  $('#open-findings-btn').addEventListener('click', () => showView('findings'));

  $('#bell-btn').addEventListener('click', (event) => {
    event.stopPropagation();
    toggleNotifications();
  });
  $('#notif-mark-read').addEventListener('click', markAllRead);
  $('#notif-clear').addEventListener('click', clearNotifications);
  // Any element can navigate: hero buttons, footer links, empty-state actions.
  document.addEventListener('click', (event) => {
    const goto = event.target.closest('[data-goto]');
    if (goto) {
      showView(goto.dataset.goto);
      return;
    }
    const docLink = event.target.closest('[data-doc]');
    if (docLink) {
      const target = document.getElementById('doc-' + docLink.dataset.doc);
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      $$('.doc-btn').forEach((button) => button.classList.toggle('is-active', button === docLink));
    }
  });

  document.addEventListener('click', (event) => {
    const panel = $('#notif-panel');
    if (panel.hidden) return;
    if (panel.contains(event.target) || $('#bell-btn').contains(event.target)) return;
    toggleNotifications(false);
  });

  $('#help-btn').addEventListener('click', () => {
    const dialog = $('#help-dialog');
    if (typeof dialog.showModal === 'function') dialog.showModal();
    else dialog.setAttribute('open', '');
  });
  $('#help-close').addEventListener('click', () => $('#help-dialog').close());

  $('#detail-close').addEventListener('click', closeDetail);
  $('#detail-backdrop').addEventListener('click', closeDetail);

  $('#chat-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const input = $('#chat-input');
    const value = input.value;
    input.value = '';
    askAssistant(value);
  });
  $('#chat-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      $('#chat-form').requestSubmit();
    }
  });
  $$('#chat-suggestions .suggestion').forEach((button) => {
    button.addEventListener('click', () => {
      const input = $('#chat-input');
      input.value = button.textContent;
      $('#chat-form').requestSubmit();
    });
  });
  $('#chat-context-clear').addEventListener('click', () => {
    state.assistant.contextId = null;
    renderChatContext();
  });

  document.addEventListener('keydown', (event) => {
    const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(event.target.tagName);

    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      runScan();
      return;
    }
    if (event.key === 'Escape') {
      closeDetail();
      toggleNotifications(false);
      const dialog = $('#help-dialog');
      if (dialog.open) dialog.close();
      return;
    }
    if (typing) return;

    if (event.key === '/') {
      event.preventDefault();
      if (state.view !== 'findings') showView('findings');
      $('#search').focus();
      return;
    }
    if (event.key === 't' && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const order = ['none', 'file', 'severity'];
      state.filters.group = order[(order.indexOf(state.filters.group) + 1) % order.length];
      renderAll();
      return;
    }
    if (event.altKey && ['1', '2', '3', '4'].includes(event.key)) {
      event.preventDefault();
      showView(['scan', 'findings', 'rules', 'assistant'][Number(event.key) - 1]);
    }
  });
}

/* ----------------------------------- boot -------------------------------- */

async function boot() {
  bindEvents();
  trapFocus($('#detail'));
  updateCodeStats();
  renderNotifications();
  renderChat();
  renderChatContext();
  renderAll();

  if (!state.assistant.messages.length) {
    addMessage(
      'assistant',
      'I explain findings from the redacted report and can walk you through sinks, redaction, triage and rules. Open a finding and choose “Ask assistant” to give me its context.'
    );
  }

  const requested = location.hash.replace('#/', '');
  showView(VIEW_META[requested] ? requested : 'scan', { hash: false });

  await Promise.all([loadHealth(), loadRules(), loadAssistantStatus()]);
}

document.addEventListener('DOMContentLoaded', boot);
