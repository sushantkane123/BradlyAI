/* BradlyAI SOC Operations Console — client-facing analyst workspace. */
const API_ROOT = '/api/v1';

const state = {
  page: 'overview',
  hours: 24,
  alerts: [],
  l1Stats: null,
  audit: [],
  health: null,
  integrationHealth: null,
  wazuhHealth: null,
  cases: [],
  errors: {},
  loading: true,
  token: sessionStorage.getItem('bradly_access_token') || '',
  user: JSON.parse(sessionStorage.getItem('bradly_user') || 'null'),
  alertFilters: { severity: 'ALL', status: 'ALL', query: '' },
  caseFilters: { status: 'ALL', query: '' },
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  }[char]));
}

function normalise(value) {
  return String(value ?? '').trim();
}

function displayStatus(value, fallback = 'Unknown') {
  const text = normalise(value).replace(/_/g, ' ');
  return text ? text.replace(/\b\w/g, letter => letter.toUpperCase()) : fallback;
}

function severityClass(value) {
  const item = normalise(value).toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(item) ? item : 'unknown';
}

function statusClass(value) {
  return normalise(value).toLowerCase().replace(/[^a-z0-9]+/g, '_');
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
}

function relativeTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return 'now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

function parseConfidence(value) {
  const number = Number.parseFloat(String(value ?? '').replace('%', ''));
  if (Number.isNaN(number)) return null;
  return number > 1 ? number / 100 : number;
}

function formatConfidence(value) {
  const confidence = parseConfidence(value);
  return confidence === null ? '—' : `${Math.round(confidence * 100)}%`;
}

function formatPercent(value) {
  const numeric = Number(value || 0);
  return `${Math.round((numeric > 1 ? numeric / 100 : numeric) * 100)}%`;
}

function apiHeaders() {
  const headers = { Accept: 'application/json' };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  return headers;
}

async function request(path, options = {}) {
  const response = await fetch(`${API_ROOT}${path}`, {
    ...options,
    headers: { ...apiHeaders(), ...(options.headers || {}) },
  });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      message = typeof body.detail === 'string' ? body.detail : message;
    } catch (_) { /* Response was not JSON. */ }
    throw new Error(message);
  }
  return response.status === 204 ? null : response.json();
}

async function loadResource(name, path) {
  try {
    const data = await request(path);
    state.errors[name] = null;
    return data;
  } catch (error) {
    state.errors[name] = error.message;
    return null;
  }
}

async function loadWorkspace() {
  state.loading = true;
  render();
  const hours = Number(state.hours);
  const [alerts, l1Stats, audit, health, wazuhHealth, integrationHealth, cases] = await Promise.all([
    loadResource('alerts', '/alerts?limit=500'),
    loadResource('l1Stats', `/l1/stats?since_hours=${hours}`),
    loadResource('audit', `/l1/audit?since_hours=${hours}&limit=100`),
    loadResource('health', '/health'),
    loadResource('wazuhHealth', '/l1/wazuh/health'),
    loadResource('integrationHealth', '/integration/wazuh/health'),
    loadResource('cases', '/cases?limit=100'),
  ]);
  state.alerts = Array.isArray(alerts) ? alerts : [];
  state.l1Stats = l1Stats || { total_decisions: 0, closed: 0, escalated: 0, shadow_decisions: 0, auto_close_rate: 0, override_rate: 0, avg_close_confidence: 0, by_source: {}, primary_signal_breakdown: {} };
  state.audit = Array.isArray(audit?.entries) ? audit.entries : [];
  state.health = health;
  state.wazuhHealth = wazuhHealth;
  state.integrationHealth = integrationHealth;
  state.cases = Array.isArray(cases) ? cases : [];
  state.loading = false;
  updateChrome();
  render();
}

function updateChrome() {
  $('#nav-alert-count').textContent = String(state.alerts.filter(alert => !['closed', 'resolved', 'auto_closed'].includes(statusClass(alert.status))).length);
  const caseCount = $('#nav-case-count');
  if (caseCount) caseCount.textContent = String(state.cases.filter(item => ['open', 'in_progress', 'escalated'].includes(statusClass(item.status))).length);
  const serviceHealthy = state.health && ['healthy', 'ok', 'alive', 'ready'].includes(String(state.health.status).toLowerCase());
  const connection = $('#connection-state');
  connection.innerHTML = `<span class="status-dot ${serviceHealthy ? 'healthy' : 'unhealthy'}"></span><span>${serviceHealthy ? 'Service healthy' : 'Service unavailable'}</span>`;
  const avatar = $('#user-avatar');
  const name = $('#user-name');
  if (state.user) {
    const initials = (state.user.username || state.user.email || 'SO').split(/[\s@._-]/).filter(Boolean).slice(0, 2).map(part => part[0]).join('').toUpperCase();
    avatar.textContent = initials || 'SO';
    name.textContent = state.user.username || 'Analyst';
  } else {
    avatar.textContent = 'SO';
    name.textContent = 'Sign in';
  }
}

function errorNotice(keys) {
  const messages = keys.map(key => state.errors[key]).filter(Boolean);
  if (!messages.length) return '';
  return `<div class="error-panel"><span aria-hidden="true">!</span><div><strong>Some data could not be loaded.</strong>${escapeHtml(messages[0])}${messages.length > 1 ? ` (${messages.length} sources affected)` : ''}</div></div>`;
}

function pageHeader(title, description, meta = '') {
  return `<div class="page-header"><div><h1>${escapeHtml(title)}</h1><p>${escapeHtml(description)}</p></div><div class="header-meta">${meta}</div></div>`;
}

function metricCard(label, value, note, style = '') {
  return `<article class="metric-card ${style}"><div class="metric-label"><span>${escapeHtml(label)}</span></div><div class="metric-value">${escapeHtml(value)}</div><div class="metric-note">${escapeHtml(note)}</div></article>`;
}

function emptyState(title, message, action = '') {
  return `<div class="empty-state"><div><div class="empty-icon" aria-hidden="true">○</div><h3>${escapeHtml(title)}</h3><p>${escapeHtml(message)}</p>${action}</div></div>`;
}

function alertRows(alerts, limit = alerts.length) {
  if (!alerts.length) return `<tr><td colspan="7">${emptyState('No alerts found', 'Change the filters or connect an alert source to begin triage.')}</td></tr>`;
  return alerts.slice(0, limit).map(alert => {
    const severity = severityClass(alert.severity);
    return `<tr class="alert-row" data-alert-id="${escapeHtml(alert.id)}" tabindex="0">
      <td><span class="severity ${severity}">${escapeHtml(displayStatus(alert.severity))}</span></td>
      <td><span class="entity-title">${escapeHtml(alert.title || alert.id)}</span><span class="entity-subtitle">${escapeHtml(alert.id)}</span></td>
      <td><span class="entity-title">${escapeHtml(alert.endpoint || '—')}</span><span class="entity-subtitle">${escapeHtml(alert.ip || 'No IP')}</span></td>
      <td>${alert.mitre ? `<span class="entity-subtitle">${escapeHtml(alert.mitre)}</span>` : '—'}</td>
      <td><span class="status-badge ${statusClass(alert.status)}">${escapeHtml(displayStatus(alert.status))}</span></td>
      <td><span class="confidence">${escapeHtml(formatConfidence(alert.ai_confidence))}</span></td>
      <td title="${escapeHtml(formatDate(alert.timestamp))}">${escapeHtml(relativeTime(alert.timestamp))}</td>
    </tr>`;
  }).join('');
}

function renderOverview() {
  const alerts = state.alerts;
  const stats = state.l1Stats || {};
  const openAlerts = alerts.filter(alert => !['closed', 'resolved', 'auto_closed'].includes(statusClass(alert.status)));
  const critical = openAlerts.filter(alert => severityClass(alert.severity) === 'critical').length;
  const high = openAlerts.filter(alert => severityClass(alert.severity) === 'high').length;
  const breached = state.cases.filter(item => item.sla_breached).length;
  const decisionEntries = state.audit.slice(0, 5);
  const bySeverity = ['critical', 'high', 'medium', 'low'].map(severity => ({ severity, count: alerts.filter(alert => severityClass(alert.severity) === severity).length }));
  const maxSeverity = Math.max(1, ...bySeverity.map(item => item.count));
  const l1Mode = stats.current_mode ? `${displayStatus(stats.current_mode)} mode` : 'Policy mode unavailable';
  return `${pageHeader('Security overview', 'Prioritize investigation work, review automated decisions, and monitor service health.', `<span>Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>`)}
    ${errorNotice(['alerts', 'l1Stats', 'health'])}
    <section class="metric-grid" aria-label="Security operations metrics">
      ${metricCard('Open alerts', String(openAlerts.length), `${alerts.length} received in workspace`, 'info')}
      ${metricCard('Critical alerts', String(critical), high ? `${high} high severity alerts` : 'No high severity alerts', critical ? 'critical' : '')}
      ${metricCard('L1 auto-close rate', formatPercent(stats.auto_close_rate), l1Mode, 'positive')}
      ${metricCard('Escalated to L2', String(stats.escalated || 0), `${stats.total_decisions || 0} L1 decisions`, 'attention')}
      ${metricCard('SLA breaches', String(breached), state.errors.cases ? 'Sign in to view case SLA status' : `${state.cases.length} cases in queue`, breached ? 'critical' : '')}
      ${metricCard('Override rate', formatPercent(stats.override_rate), 'Analyst feedback signal', '')}
    </section>
    <section class="dashboard-grid">
      <div class="stack">
        <section class="panel">
          <div class="panel-header"><h2>Priority alert queue</h2><button class="text-button" data-go-page="alerts">View all alerts</button></div>
          <div class="table-wrap"><table class="data-table"><thead><tr><th>Severity</th><th>Alert</th><th>Asset</th><th>MITRE</th><th>Status</th><th>Confidence</th><th>Age</th></tr></thead><tbody>${alertRows([...openAlerts].sort((a, b) => ['critical','high','medium','low'].indexOf(severityClass(a.severity)) - ['critical','high','medium','low'].indexOf(severityClass(b.severity))), 7)}</tbody></table></div>
        </section>
        <section class="panel"><div class="panel-header"><h2>Alert distribution by severity</h2><span class="entity-subtitle">Current workspace</span></div><div class="panel-body"><div class="bar-list">${bySeverity.map(item => `<div class="bar-item"><span>${displayStatus(item.severity)}</span><div class="bar-track"><div class="bar-fill ${item.severity}" style="width:${Math.max(0, item.count / maxSeverity * 100)}%"></div></div><span class="bar-value">${item.count}</span></div>`).join('')}</div></div></section>
      </div>
      <div class="stack">
        <section class="panel"><div class="panel-header"><h2>Recent L1 decisions</h2><span class="entity-subtitle">${escapeHtml(l1Mode)}</span></div><div class="panel-body"><div class="decision-list">${decisionEntries.length ? decisionEntries.map(entry => {
          const decision = String(entry.decision || 'Unknown').toUpperCase();
          return `<div class="decision-row"><span class="decision-line ${decision.includes('CLOSE') ? 'close' : 'escalate'}"></span><div><strong>${escapeHtml(entry.alert_title || entry.alert_id || 'Security alert')}</strong><span>${escapeHtml(displayStatus(decision))} · ${escapeHtml(formatConfidence(entry.confidence))}</span></div><time>${escapeHtml(relativeTime(entry.timestamp))}</time></div>`;
        }).join('') : emptyState('No L1 decisions yet', 'New decisions will appear here after alerts are processed.')}</div></div></section>
        <section class="panel"><div class="panel-header"><h2>Integration health</h2><button class="text-button" data-go-page="integrations">Manage integrations</button></div><div class="panel-body">${healthRows().slice(0, 3).join('')}</div></section>
      </div>
    </section>`;
}

function filteredAlerts() {
  const { severity, status, query } = state.alertFilters;
  const lowerQuery = query.toLowerCase().trim();
  return state.alerts.filter(alert => {
    if (severity !== 'ALL' && severityClass(alert.severity).toUpperCase() !== severity) return false;
    if (status !== 'ALL' && statusClass(alert.status).toUpperCase() !== status) return false;
    if (!lowerQuery) return true;
    return [alert.id, alert.title, alert.endpoint, alert.ip, alert.mitre].some(value => String(value || '').toLowerCase().includes(lowerQuery));
  });
}

function renderAlerts() {
  const alerts = filteredAlerts();
  const filter = state.alertFilters;
  return `${pageHeader('Alerts', 'Search, filter, and investigate security alerts in the active workspace.', `${alerts.length} of ${state.alerts.length} alerts`)}
    ${errorNotice(['alerts'])}
    <section class="panel">
      <div class="panel-body">
        <div class="toolbar">
          <label class="search-box"><input id="alert-search" type="search" value="${escapeHtml(filter.query)}" placeholder="Search alert, asset, IP, or MITRE technique" aria-label="Search alerts"></label>
          <select class="select-control" id="severity-filter" aria-label="Filter by severity"><option value="ALL">All severity</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select>
          <select class="select-control" id="status-filter" aria-label="Filter by status"><option value="ALL">All status</option><option value="OPEN">Open</option><option value="IN_PROGRESS">In progress</option><option value="ESCALATED">Escalated</option><option value="CLOSED">Closed</option></select>
          <button class="button secondary small" id="clear-alert-filters">Clear filters</button>
        </div>
        <div class="filter-group" aria-label="Quick severity filters">
          ${['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(value => `<button class="filter-pill ${filter.severity === value ? 'active' : ''}" data-severity-filter="${value}">${value === 'ALL' ? 'All alerts' : displayStatus(value)}</button>`).join('')}
        </div>
      </div>
      <div class="table-wrap"><table class="data-table"><thead><tr><th>Severity</th><th>Alert</th><th>Asset</th><th>MITRE</th><th>Status</th><th>Confidence</th><th>Age</th></tr></thead><tbody>${alertRows(alerts)}</tbody></table></div>
    </section>`;
}

function filteredCases() {
  const { status, query } = state.caseFilters;
  const search = query.toLowerCase().trim();
  return state.cases.filter(item => {
    if (status !== 'ALL' && statusClass(item.status).toUpperCase() !== status) return false;
    if (!search) return true;
    return [item.id, item.title, item.assignee, item.priority, item.severity].some(value => String(value || '').toLowerCase().includes(search));
  });
}

function renderCases() {
  if (!state.user) {
    return `${pageHeader('Cases', 'Manage investigation ownership, evidence, status, and SLA commitments.', 'Authentication required')}
      <section class="panel">${emptyState('Sign in to access case management', 'Cases are tenant-scoped. Sign in with an analyst account to view, create, assign, and update investigations.', '<p style="margin-top:16px"><button class="button" id="cases-sign-in">Sign in</button></p>')}</section>`;
  }
  const cases = filteredCases();
  const active = state.cases.filter(item => ['open', 'in_progress', 'escalated'].includes(statusClass(item.status)));
  const priorityCases = active.filter(item => ['P1', 'P2'].includes(String(item.priority || '').toUpperCase()));
  const breaches = active.filter(item => Number(item.sla_breached) === 1);
  const unassigned = active.filter(item => !item.assignee).length;
  return `${pageHeader('Cases', 'Track active investigations, ownership, evidence, and SLA risk.', `${active.length} active cases`)}
    ${errorNotice(['cases'])}
    <section class="metric-grid" aria-label="Case management metrics">
      ${metricCard('Active cases', String(active.length), `${state.cases.length} total cases`, 'info')}
      ${metricCard('P1 / P2 priority', String(priorityCases.length), 'Immediate analyst attention', priorityCases.length ? 'critical' : '')}
      ${metricCard('SLA breaches', String(breaches.length), breaches.length ? 'Review and escalate now' : 'No current breaches', breaches.length ? 'critical' : 'positive')}
      ${metricCard('Unassigned cases', String(unassigned), 'Assign an accountable analyst', unassigned ? 'attention' : '')}
      ${metricCard('Resolved / closed', String(state.cases.filter(item => ['resolved', 'closed'].includes(statusClass(item.status))).length), 'Historical case record', 'positive')}
      ${metricCard('Tenant', state.user.tenant_id || 'Default', 'Current authenticated workspace', '')}
    </section>
    <section class="panel"><div class="panel-body"><div class="toolbar"><label class="search-box"><input id="case-search" type="search" value="${escapeHtml(state.caseFilters.query)}" placeholder="Search case ID, title, assignee, or priority" aria-label="Search cases"></label><select class="select-control" id="case-status-filter" aria-label="Filter cases by status"><option value="ALL">All status</option><option value="OPEN">Open</option><option value="IN_PROGRESS">In progress</option><option value="ESCALATED">Escalated</option><option value="RESOLVED">Resolved</option><option value="CLOSED">Closed</option></select><button class="button" id="new-case">+ New case</button></div><div class="filter-group">${['ALL', 'OPEN', 'IN_PROGRESS', 'ESCALATED', 'RESOLVED', 'CLOSED'].map(value => `<button class="filter-pill ${state.caseFilters.status === value ? 'active' : ''}" data-case-status="${value}">${value === 'ALL' ? 'All cases' : displayStatus(value)}</button>`).join('')}</div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Priority</th><th>Case</th><th>Severity</th><th>Status</th><th>Assignee</th><th>SLA</th><th>Age</th></tr></thead><tbody>${cases.length ? cases.map(item => `<tr class="case-row" data-case-id="${escapeHtml(item.id)}" tabindex="0"><td><strong>${escapeHtml(item.priority || 'P3')}</strong></td><td><span class="entity-title">${escapeHtml(item.title || item.id)}</span><span class="entity-subtitle">${escapeHtml(item.id)}</span></td><td><span class="severity ${severityClass(item.severity)}">${escapeHtml(displayStatus(item.severity))}</span></td><td><span class="status-badge ${statusClass(item.status)}">${escapeHtml(displayStatus(item.status))}</span></td><td>${escapeHtml(item.assignee || 'Unassigned')}</td><td>${Number(item.sla_breached) === 1 ? '<span class="health-state unhealthy">Breached</span>' : escapeHtml(item.sla_due_at ? formatDate(item.sla_due_at) : '—')}</td><td title="${escapeHtml(formatDate(item.created_at))}">${escapeHtml(relativeTime(item.created_at))}</td></tr>`).join('') : `<tr><td colspan="7">${emptyState('No cases found', 'Create a case from an alert or adjust the current filters.')}</td></tr>`}</tbody></table></div></section>`;
}

function openCaseCreateModal(alert = null) {
  if (!state.user) return openLogin();
  const root = $('#modal-root');
  const title = alert ? `Investigate: ${alert.title || alert.id}` : '';
  const severity = String(alert?.severity || 'MEDIUM').toUpperCase();
  root.innerHTML = `<form class="modal" id="case-create-form"><h2>Create case</h2><p>${alert ? `Create an investigation linked to alert ${escapeHtml(alert.id)}.` : 'Create a manually tracked SOC investigation.'}</p><div class="field"><label for="case-title">Case title</label><input id="case-title" name="title" value="${escapeHtml(title)}" required maxlength="500"></div><div class="field"><label for="case-severity">Severity</label><select id="case-severity" class="select-control" name="severity"><option ${severity === 'CRITICAL' ? 'selected' : ''}>CRITICAL</option><option ${severity === 'HIGH' ? 'selected' : ''}>HIGH</option><option ${severity === 'MEDIUM' ? 'selected' : ''}>MEDIUM</option><option ${severity === 'LOW' ? 'selected' : ''}>LOW</option></select></div><div class="field"><label for="case-priority">Priority</label><select id="case-priority" class="select-control" name="priority"><option>P1</option><option>P2</option><option selected>P3</option><option>P4</option><option>P5</option></select></div><div class="field"><label for="case-assignee">Assignee <span class="entity-subtitle">Optional</span></label><input id="case-assignee" name="assignee" value="${escapeHtml(state.user.username || '')}" maxlength="100"></div><div class="field"><label for="case-description">Investigation summary <span class="entity-subtitle">Optional</span></label><input id="case-description" name="description" value="${escapeHtml(alert?.title || '')}" maxlength="1000"></div><div class="modal-error" id="case-create-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="cancel-case-create">Cancel</button><button type="submit" class="button">Create case</button></div></form>`;
  root.classList.add('open'); root.setAttribute('aria-hidden', 'false');
  $('#cancel-case-create').addEventListener('click', closeModal);
  $('#case-create-form').addEventListener('submit', async event => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const error = $('#case-create-error'); error.textContent = '';
    try {
      const created = await request('/cases', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: form.get('title'), severity: form.get('severity'), priority: form.get('priority'), assignee: form.get('assignee') || null, description: form.get('description') || null, alert_id: alert?.id || null }) });
      closeModal(); toast(`Case ${created.id} created`, 'success'); await loadWorkspace(); setPage('cases'); openCase(created.id);
    } catch (failure) { error.textContent = failure.message; }
  });
}

async function openCase(caseId) {
  if (!state.user) return openLogin();
  const item = state.cases.find(caseItem => String(caseItem.id) === String(caseId));
  const detail = await loadResource('caseDetail', `/cases/${encodeURIComponent(caseId)}`);
  const caseItem = detail || item;
  if (!caseItem) return toast('Case details could not be loaded', 'error');
  const drawer = $('#alert-drawer');
  drawer.innerHTML = `<div class="drawer-header"><div><span class="severity ${severityClass(caseItem.severity)}">${escapeHtml(caseItem.priority || 'P3')} · ${escapeHtml(displayStatus(caseItem.severity))}</span><h2 id="drawer-title">${escapeHtml(caseItem.title || caseItem.id)}</h2><span class="entity-subtitle">${escapeHtml(caseItem.id)}</span></div><button class="icon-button" id="close-drawer" aria-label="Close case detail">×</button></div><div class="drawer-body"><section><h3 class="section-title">Case control</h3><div class="detail-grid"><div><dt>Status</dt><dd><select class="select-control" id="case-status-select"><option ${caseItem.status === 'OPEN' ? 'selected' : ''}>OPEN</option><option ${caseItem.status === 'IN_PROGRESS' ? 'selected' : ''}>IN_PROGRESS</option><option ${caseItem.status === 'ESCALATED' ? 'selected' : ''}>ESCALATED</option><option ${caseItem.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option><option ${caseItem.status === 'CLOSED' ? 'selected' : ''}>CLOSED</option></select></dd></div><div><dt>Assignee</dt><dd>${escapeHtml(caseItem.assignee || 'Unassigned')}</dd></div><div><dt>SLA due</dt><dd>${escapeHtml(caseItem.sla_due_at ? formatDate(caseItem.sla_due_at) : '—')}${Number(caseItem.sla_breached) === 1 ? ' · Breached' : ''}</dd></div><div><dt>Linked alerts</dt><dd>${escapeHtml((caseItem.linked_alerts || []).join(', ') || 'None')}</dd></div></div><div class="drawer-actions"><button class="button small" id="save-case-status">Update status</button><button class="button secondary small" id="add-case-note">Add note</button><button class="button secondary small" id="add-case-evidence">Add evidence</button></div></section><section><h3 class="section-title">Investigation notes</h3>${(caseItem.notes || []).length ? `<ol class="timeline">${caseItem.notes.map(note => `<li><time>${escapeHtml(formatDate(note.at))} · ${escapeHtml(note.author || 'system')}</time>${escapeHtml(note.note || '')}</li>`).join('')}</ol>` : '<div class="drawer-note">No notes have been added to this case.</div>'}</section><section><h3 class="section-title">Evidence</h3>${(caseItem.evidence || []).length ? caseItem.evidence.map(evidence => `<div class="audit-item"><strong>${escapeHtml(displayStatus(evidence.type))}</strong><span>${escapeHtml(evidence.value)}${evidence.source ? ` · ${escapeHtml(evidence.source)}` : ''}</span></div>`).join('') : '<div class="drawer-note">No evidence has been recorded yet.</div>'}</section></div>`;
  drawer.classList.add('open'); drawer.setAttribute('aria-hidden', 'false'); showScrim(true);
  $('#close-drawer').addEventListener('click', closeDrawer);
  $('#save-case-status').addEventListener('click', async () => {
    try { await request(`/cases/${encodeURIComponent(caseItem.id)}/status`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: $('#case-status-select').value }) }); toast('Case status updated', 'success'); await loadWorkspace(); openCase(caseItem.id); } catch (failure) { toast(failure.message, 'error'); }
  });
  $('#add-case-note').addEventListener('click', () => openCaseNoteModal(caseItem.id));
  $('#add-case-evidence').addEventListener('click', () => openCaseEvidenceModal(caseItem.id));
}

function openCaseNoteModal(caseId) {
  const root = $('#modal-root');
  root.innerHTML = `<form class="modal" id="case-note-form"><h2>Add investigation note</h2><p>Notes are retained in the case audit timeline.</p><div class="field"><label for="case-note">Note</label><input id="case-note" name="note" required maxlength="4000" placeholder="Document investigation findings or analyst handoff"></div><div class="modal-error" id="case-note-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="cancel-case-note">Cancel</button><button type="submit" class="button">Add note</button></div></form>`;
  root.classList.add('open'); root.setAttribute('aria-hidden', 'false');
  $('#cancel-case-note').addEventListener('click', closeModal);
  $('#case-note-form').addEventListener('submit', async event => { event.preventDefault(); const form = new FormData(event.currentTarget); try { await request(`/cases/${encodeURIComponent(caseId)}/notes`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ note: form.get('note'), note_type: 'comment' }) }); closeModal(); toast('Note added', 'success'); await loadWorkspace(); openCase(caseId); } catch (failure) { $('#case-note-error').textContent = failure.message; } });
}

function openCaseEvidenceModal(caseId) {
  const root = $('#modal-root');
  root.innerHTML = `<form class="modal" id="case-evidence-form"><h2>Add evidence</h2><p>Record an observable artifact with its source for investigation traceability.</p><div class="field"><label for="evidence-type">Evidence type</label><select id="evidence-type" class="select-control" name="type"><option>IP</option><option>DOMAIN</option><option>HASH</option><option>URL</option><option>HOST</option><option>LOG</option><option>OTHER</option></select></div><div class="field"><label for="evidence-value">Value</label><input id="evidence-value" name="value" required maxlength="4000" placeholder="IOC, log reference, hostname, or hash"></div><div class="field"><label for="evidence-source">Source <span class="entity-subtitle">Optional</span></label><input id="evidence-source" name="source" maxlength="250" placeholder="Wazuh, Sentinel, analyst, etc."></div><div class="modal-error" id="case-evidence-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="cancel-case-evidence">Cancel</button><button type="submit" class="button">Add evidence</button></div></form>`;
  root.classList.add('open'); root.setAttribute('aria-hidden', 'false');
  $('#cancel-case-evidence').addEventListener('click', closeModal);
  $('#case-evidence-form').addEventListener('submit', async event => { event.preventDefault(); const form = new FormData(event.currentTarget); try { await request(`/cases/${encodeURIComponent(caseId)}/evidence`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ evidence_type: form.get('type'), value: form.get('value'), source: form.get('source') || null }) }); closeModal(); toast('Evidence added', 'success'); await loadWorkspace(); openCase(caseId); } catch (failure) { $('#case-evidence-error').textContent = failure.message; } });
}

function integrationStatus(status, configured = true) {
  if (!configured) return { label: 'Not configured', style: 'warning' };
  if (status) return { label: 'Healthy', style: 'healthy' };
  return { label: 'Unavailable', style: 'unhealthy' };
}

function healthRows() {
  const app = integrationStatus(Boolean(state.health && ['healthy', 'ok', 'alive', 'ready'].includes(String(state.health.status).toLowerCase())));
  const wazuhConfigured = Boolean(state.wazuhHealth?.available || state.wazuhHealth?.enabled);
  const wazuh = integrationStatus(Boolean(state.wazuhHealth?.available || state.wazuhHealth?.dry_run), wazuhConfigured || Boolean(state.wazuhHealth));
  const connector = integrationStatus(Boolean(state.integrationHealth && String(state.integrationHealth.status).toLowerCase() === 'operational'));
  return [
    { icon: 'B', name: 'BradlyAI API', detail: state.health?.status || 'Service status unavailable', status: app },
    { icon: 'W', name: 'Wazuh connector', detail: state.wazuhHealth?.warning || (state.wazuhHealth?.dry_run ? 'Dry-run safety mode' : 'Connection status unavailable'), status: wazuh },
    { icon: 'L1', name: 'L1 decision engine', detail: state.l1Stats?.current_mode ? `${displayStatus(state.l1Stats.current_mode)} mode · ${Math.round((state.l1Stats.threshold || 0) * 100)}% threshold` : 'Decision engine status unavailable', status: connector },
  ].map(item => `<div class="health-row"><span class="health-icon">${escapeHtml(item.icon)}</span><div><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.detail)}</span></div><span class="health-state ${item.status.style}">${escapeHtml(item.status.label)}</span></div>`);
}

function integrationCard(icon, name, summary, values, stateInfo) {
  return `<article class="integration-card"><div class="integration-card-header"><span class="integration-icon">${escapeHtml(icon)}</span><div><h2>${escapeHtml(name)}</h2><span class="health-state ${stateInfo.style}">${escapeHtml(stateInfo.label)}</span></div></div><p>${escapeHtml(summary)}</p><dl>${values.map(([term, description]) => `<dt>${escapeHtml(term)}</dt><dd>${escapeHtml(description)}</dd>`).join('')}</dl></article>`;
}

function renderIntegrations() {
  const apiStatus = integrationStatus(Boolean(state.health && ['healthy', 'ok', 'alive', 'ready'].includes(String(state.health.status).toLowerCase())));
  const wazuhConfigured = Boolean(state.wazuhHealth?.available || state.wazuhHealth?.enabled);
  const wazuhStatus = integrationStatus(Boolean(state.wazuhHealth?.available || state.wazuhHealth?.dry_run), wazuhConfigured || Boolean(state.wazuhHealth));
  const incoming = integrationStatus(Boolean(state.integrationHealth && String(state.integrationHealth.status).toLowerCase() === 'operational'));
  const notification = integrationStatus(false, false);
  const cases = integrationStatus(Boolean(state.cases.length), Boolean(state.user));
  return `${pageHeader('Integration health', 'Verify the health, safety mode, and connectivity of operational integrations.', '<span>Review before enabling automated actions</span>')}
    ${errorNotice(['health', 'wazuhHealth', 'integrationHealth', 'cases'])}
    <section class="integration-grid">
      ${integrationCard('B', 'BradlyAI API', 'Core API availability and application readiness.', [['State', state.health?.status || 'Unknown'], ['Environment', state.health?.environment || 'Not reported']], apiStatus)}
      ${integrationCard('W', 'Wazuh Manager', state.wazuhHealth?.warning || 'Two-way Wazuh workflow and safe-close policy.', [['Enabled', state.wazuhHealth?.enabled ? 'Yes' : 'No'], ['Dry run', state.wazuhHealth?.dry_run ? 'Enabled' : 'Disabled'], ['Close mode', state.wazuhHealth?.close_mode || 'Not configured']], wazuhStatus)}
      ${integrationCard('L1', 'Wazuh ingestion', 'Inbound Wazuh alert pipeline status.', [['State', state.integrationHealth?.status || 'Unknown'], ['Events ingested', String(state.integrationHealth?.events_ingested ?? '—')], ['Rules active', String(state.integrationHealth?.detection_rules_active ?? '—')]], incoming)}
      ${integrationCard('N', 'Notifications', 'Slack, Teams, PagerDuty, email, and webhook delivery.', [['State', 'Configure per client'], ['Recommended mode', 'Escalations only']], notification)}
      ${integrationCard('C', 'Case management', state.user ? 'Authenticated case queue and SLA workflow.' : 'Sign in to view tenant-scoped cases and SLA status.', [['Visible cases', state.user ? String(state.cases.length) : 'Sign-in required'], ['SLA breaches', state.user ? String(state.cases.filter(item => item.sla_breached).length) : '—']], cases)}
      ${integrationCard('I', 'Threat intelligence', 'Optional enrichment sources are intentionally disabled until configured.', [['Recommended', 'GreyNoise / VirusTotal'], ['Policy', 'Per-client approval']], integrationStatus(false, false))}
    </section>
    <section class="panel" style="margin-top:18px"><div class="panel-header"><h2>Safe activation checklist</h2></div><div class="panel-body"><div class="bar-list"><div class="bar-item"><span>Inbound webhook</span><div class="bar-track"><div class="bar-fill ${state.wazuhHealth?.available ? 'low' : 'high'}" style="width:${state.wazuhHealth?.available ? '100' : '45'}%"></div></div><span class="bar-value">${state.wazuhHealth?.available ? 'Ready' : 'Review'}</span></div><div class="bar-item"><span>Action policy</span><div class="bar-track"><div class="bar-fill ${state.wazuhHealth?.dry_run ? 'medium' : 'low'}" style="width:100%"></div></div><span class="bar-value">${state.wazuhHealth?.dry_run ? 'Dry run' : 'Active'}</span></div><div class="bar-item"><span>Client notifications</span><div class="bar-track"><div class="bar-fill medium" style="width:35%"></div></div><span class="bar-value">Configure</span></div></div></div></section>`;
}

function render() {
  const content = $('#app-content');
  if (state.loading) {
    content.innerHTML = `<div class="empty-state"><div class="loading">Loading SOC workspace</div></div>`;
    return;
  }
  const contentByPage = { overview: renderOverview, alerts: renderAlerts, cases: renderCases, integrations: renderIntegrations };
  content.innerHTML = (contentByPage[state.page] || renderOverview)();
  $('#page-name').textContent = ({ overview: 'Overview', alerts: 'Alerts', cases: 'Cases', integrations: 'Integrations' })[state.page] || 'Overview';
  bindPageEvents();
}

function bindPageEvents() {
  $$('[data-go-page]').forEach(button => button.addEventListener('click', () => setPage(button.dataset.goPage)));
  $$('.alert-row').forEach(row => {
    row.addEventListener('click', () => openAlert(row.dataset.alertId));
    row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openAlert(row.dataset.alertId); } });
  });
  const search = $('#alert-search');
  if (search) search.addEventListener('input', event => { state.alertFilters.query = event.target.value; render(); });
  const severity = $('#severity-filter');
  if (severity) { severity.value = state.alertFilters.severity; severity.addEventListener('change', event => { state.alertFilters.severity = event.target.value; render(); }); }
  const status = $('#status-filter');
  if (status) { status.value = state.alertFilters.status; status.addEventListener('change', event => { state.alertFilters.status = event.target.value; render(); }); }
  $$('#app-content [data-severity-filter]').forEach(button => button.addEventListener('click', () => { state.alertFilters.severity = button.dataset.severityFilter; render(); }));
  const clear = $('#clear-alert-filters');
  if (clear) clear.addEventListener('click', () => { state.alertFilters = { severity: 'ALL', status: 'ALL', query: '' }; render(); });

  const signIn = $('#cases-sign-in');
  if (signIn) signIn.addEventListener('click', openLogin);
  const newCase = $('#new-case');
  if (newCase) newCase.addEventListener('click', () => openCaseCreateModal());
  const caseSearch = $('#case-search');
  if (caseSearch) caseSearch.addEventListener('input', event => { state.caseFilters.query = event.target.value; render(); });
  const caseStatus = $('#case-status-filter');
  if (caseStatus) { caseStatus.value = state.caseFilters.status; caseStatus.addEventListener('change', event => { state.caseFilters.status = event.target.value; render(); }); }
  $$('#app-content [data-case-status]').forEach(button => button.addEventListener('click', () => { state.caseFilters.status = button.dataset.caseStatus; render(); }));
  $$('.case-row').forEach(row => {
    row.addEventListener('click', () => openCase(row.dataset.caseId));
    row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openCase(row.dataset.caseId); } });
  });
}

async function openAlert(alertId) {
  const baseAlert = state.alerts.find(item => String(item.id) === String(alertId));
  if (!baseAlert) return;
  const drawer = $('#alert-drawer');
  const [detail, audit] = await Promise.all([
    loadResource('alertDetail', `/alerts/${encodeURIComponent(alertId)}`),
    loadResource('alertAudit', `/l1/audit?since_hours=8760&limit=1000`),
  ]);
  const alert = detail || baseAlert;
  const entries = (audit?.entries || state.audit).filter(item => String(item.alert_id) === String(alert.id)).slice(0, 8);
  drawer.innerHTML = `<div class="drawer-header"><div><span class="severity ${severityClass(alert.severity)}">${escapeHtml(displayStatus(alert.severity))}</span><h2 id="drawer-title">${escapeHtml(alert.title || alert.id)}</h2><span class="entity-subtitle">${escapeHtml(alert.id)}</span></div><button class="icon-button" id="close-drawer" aria-label="Close alert detail">×</button></div><div class="drawer-body"><div class="drawer-actions"><button class="button secondary small" id="copy-alert-id">Copy alert ID</button><button class="button secondary small" id="create-case-from-alert" ${state.user ? '' : 'disabled title="Sign in to create a case"'}>Create case</button></div><section><h3 class="section-title">Alert summary</h3><dl class="detail-grid"><div><dt>Status</dt><dd><span class="status-badge ${statusClass(alert.status)}">${escapeHtml(displayStatus(alert.status))}</span></dd></div><div><dt>Confidence</dt><dd>${escapeHtml(formatConfidence(alert.ai_confidence))}</dd></div><div><dt>Asset</dt><dd>${escapeHtml(alert.endpoint || '—')}</dd></div><div><dt>Source IP</dt><dd>${escapeHtml(alert.ip || '—')}</dd></div><div><dt>MITRE ATT&CK</dt><dd>${escapeHtml(alert.mitre || 'Not mapped')}</dd></div><div><dt>Observed</dt><dd>${escapeHtml(formatDate(alert.timestamp))}</dd></div></dl></section><section><h3 class="section-title">Investigation timeline</h3>${Array.isArray(alert.storyline) && alert.storyline.length ? `<ol class="timeline">${alert.storyline.map(item => `<li><time>${escapeHtml(item.time || '')}</time>${escapeHtml(item.event || '')}</li>`).join('')}</ol>` : `<div class="drawer-note">No timeline evidence has been recorded for this alert.</div>`}</section><section><h3 class="section-title">L1 decision evidence</h3>${entries.length ? entries.map(entry => `<div class="audit-item"><strong>${escapeHtml(displayStatus(entry.decision))} · ${escapeHtml(formatConfidence(entry.confidence))}</strong><span>${escapeHtml(entry.reason || entry.primary_signal || 'Decision recorded')} · ${escapeHtml(formatDate(entry.timestamp))}</span></div>`).join('') : `<div class="drawer-note">No L1 decision evidence is associated with this alert yet.</div>`}</section></div>`;
  drawer.classList.add('open');
  drawer.setAttribute('aria-hidden', 'false');
  showScrim(true);
  $('#close-drawer').addEventListener('click', closeDrawer);
  $('#copy-alert-id').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(String(alert.id)); toast('Alert ID copied', 'success'); } catch (_) { toast('Could not copy alert ID', 'error'); }
  });
  const createCase = $('#create-case-from-alert');
  if (createCase) createCase.addEventListener('click', () => openCaseCreateModal(alert));
}

function closeDrawer() {
  const drawer = $('#alert-drawer');
  drawer.classList.remove('open');
  drawer.setAttribute('aria-hidden', 'true');
  showScrim(false);
}

function showScrim(show) {
  const scrim = $('#scrim');
  scrim.hidden = !show;
}

function openLogin() {
  const root = $('#modal-root');
  root.innerHTML = `<form class="modal" id="login-form"><h2>Sign in to BradlyAI</h2><p>Use your tenant analyst account. Credentials are sent only to this BradlyAI instance.</p><div class="field"><label for="login-user">Username</label><input id="login-user" name="username" autocomplete="username" required></div><div class="field"><label for="login-password">Password</label><input id="login-password" name="password" type="password" autocomplete="current-password" required></div><div class="field"><label for="login-mfa">MFA code <span class="entity-subtitle">Optional when MFA is not enabled</span></label><input id="login-mfa" name="mfa" inputmode="numeric" autocomplete="one-time-code"></div><div class="modal-error" id="login-error"></div><div class="modal-actions"><button type="button" class="button secondary" id="close-login">Cancel</button><button type="submit" class="button">Sign in</button></div></form>`;
  root.classList.add('open'); root.setAttribute('aria-hidden', 'false');
  $('#close-login').addEventListener('click', closeModal);
  $('#login-form').addEventListener('submit', async event => {
    event.preventDefault();
    const error = $('#login-error'); error.textContent = '';
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch(`${API_ROOT}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ username: form.get('username'), password: form.get('password'), mfa_code: form.get('mfa') || null }) });
      if (!response.ok) { const body = await response.json().catch(() => ({})); throw new Error(body.detail || 'Sign-in failed'); }
      const body = await response.json();
      state.token = body.access_token; state.user = body.user;
      sessionStorage.setItem('bradly_access_token', state.token); sessionStorage.setItem('bradly_user', JSON.stringify(state.user));
      closeModal(); updateChrome(); toast('Signed in successfully', 'success'); await loadWorkspace();
    } catch (failure) { error.textContent = failure.message; }
  });
}

function openAccountMenu() {
  if (!state.user) return openLogin();
  const root = $('#modal-root');
  root.innerHTML = `<div class="modal"><h2>${escapeHtml(state.user.username || 'Analyst')}</h2><p>${escapeHtml(state.user.email || 'Authenticated session')}</p><div class="drawer-note">Tenant: ${escapeHtml(state.user.tenant_id || 'Default')}<br>Role-based access is enforced by the API.</div><div class="modal-actions"><button type="button" class="button secondary" id="close-account">Close</button><button type="button" class="button" id="sign-out">Sign out</button></div></div>`;
  root.classList.add('open'); root.setAttribute('aria-hidden', 'false');
  $('#close-account').addEventListener('click', closeModal);
  $('#sign-out').addEventListener('click', () => { state.token = ''; state.user = null; sessionStorage.removeItem('bradly_access_token'); sessionStorage.removeItem('bradly_user'); closeModal(); updateChrome(); toast('Signed out', 'success'); loadWorkspace(); });
}

function closeModal() { const root = $('#modal-root'); root.classList.remove('open'); root.setAttribute('aria-hidden', 'true'); root.innerHTML = ''; }
function toast(message, type = '') { const node = document.createElement('div'); node.className = `toast ${type}`; node.textContent = message; $('#toast-region').append(node); setTimeout(() => node.remove(), 3600); }
function setPage(page) { state.page = page; $$('.nav-item[data-page]').forEach(item => { const active = item.dataset.page === page; item.classList.toggle('active', active); item.setAttribute('aria-current', active ? 'page' : 'false'); }); closeMobileNav(); render(); window.scrollTo({ top: 0, behavior: 'smooth' }); }
function openMobileNav() { $('#sidebar').classList.add('open'); showScrim(true); }
function closeMobileNav() { $('#sidebar').classList.remove('open'); if (!$('#alert-drawer').classList.contains('open')) showScrim(false); }

function bindGlobalEvents() {
  $$('.nav-item[data-page]').forEach(button => button.addEventListener('click', () => setPage(button.dataset.page)));
  $('#refresh-button').addEventListener('click', loadWorkspace);
  $('#time-range').addEventListener('change', event => { state.hours = Number(event.target.value); loadWorkspace(); });
  $('#auth-button').addEventListener('click', openAccountMenu);
  $('#open-nav').addEventListener('click', openMobileNav);
  $('#close-nav').addEventListener('click', closeMobileNav);
  $('#scrim').addEventListener('click', () => { closeDrawer(); closeMobileNav(); });
  $('#modal-root').addEventListener('click', event => { if (event.target === $('#modal-root')) closeModal(); });
  document.addEventListener('keydown', event => { if (event.key === 'Escape') { closeDrawer(); closeModal(); closeMobileNav(); } });
}

bindGlobalEvents();
updateChrome();
loadWorkspace();
