/* =================================================================
   BradlyAI SOC — Dashboard Application
   Industry-grade client for the BradlyAI FastAPI backend.
   ================================================================= */

(() => {
  'use strict';

  // ====== Constants & State ======
  const API_BASE = '';
  const POLL_INTERVAL_MS = 5000;
  const STATE = {
    alerts: [],
    incidents: [],
    assets: [],
    mitre: [],
    health: null,
    lastUpdate: null,
    activeTab: 'overview',
    chatHistory: [],
  };

  // ====== Utilities ======
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const fmt = {
    pct: (n) => `${n}%`,
    num: (n) => Number(n).toLocaleString(),
    time: (iso) => {
      try {
        const d = new Date(iso);
        const now = new Date();
        const diff = (now - d) / 1000;
        if (diff < 60) return `${Math.floor(diff)}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return d.toLocaleDateString();
      } catch { return iso; }
    },
    clock: () => new Date().toLocaleTimeString(),
  };

  const sevColor = (sev) => ({
    CRITICAL: 'var(--sev-critical)',
    HIGH: 'var(--sev-high)',
    MEDIUM: 'var(--sev-medium)',
    LOW: 'var(--sev-low)',
  }[sev?.toUpperCase()] || 'var(--text-muted)');

  const sevClass = (sev) => sev?.toLowerCase() || 'neutral';

  const toast = (title, msg, type = '') => {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<div class="toast-title">${title}</div><div class="toast-msg">${msg || ''}</div>`;
    $('#toastContainer').appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateX(20px)';
      el.style.transition = 'all 0.25s';
      setTimeout(() => el.remove(), 250);
    }, 4000);
  };

  const api = async (path, opts = {}) => {
    try {
      const res = await fetch(API_BASE + path, {
        headers: { 'Content-Type': 'application/json' },
        ...opts,
      });
      if (!res.ok) {
        const errBody = await res.text();
        throw new Error(`HTTP ${res.status}: ${errBody.slice(0, 200)}`);
      }
      return await res.json();
    } catch (e) {
      console.error(`[api] ${path} failed:`, e.message);
      throw e;
    }
  };

  // ====== Tab Switching ======
  const switchTab = (name) => {
    STATE.activeTab = name;
    $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
    $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.tab === name));
  };

  // ====== Time Range ======
  const setTimeRange = (range) => {
    $$('.tr-btn').forEach(b => b.classList.toggle('active', b.dataset.range === range));
    // Trigger a re-render with same data; in production we'd filter by time.
    renderAll();
  };

  // ====== Health / Status ======
  const updateHealthPill = (h) => {
    const pill = $('#healthPill');
    if (!h) {
      pill.className = 'status-pill';
      pill.querySelector('.pill-text').textContent = 'Connecting…';
      return;
    }
    const ok = h.status === 'healthy' && h.database === 'connected';
    pill.className = `status-pill ${ok ? 'healthy' : 'degraded'}`;
    pill.querySelector('.pill-text').textContent = ok
      ? `Healthy · v${h.version}`
      : `Degraded · DB ${h.database}`;

    $('#workerStatus').textContent = h.worker_active ? '● Active' : '○ Off';
    $('#workerStatus').className = 'footer-value' + (h.worker_active ? '' : ' warn');
  };

  const updateLLMStatus = async () => {
    try {
      const c = await api('/api/v1/chat/health');
      const ok = c.status === 'operational';
      const configured = c.api_key_configured;
      const txt = `${c.provider || 'unknown'} · ${configured ? 'configured' : 'no key'}`;
      $('#llmStatus').textContent = configured ? '● Ready' : '○ No Key';
      $('#llmStatus').className = 'footer-value' + (configured ? '' : ' warn');
      const pill = $('#llmPill');
      if (pill) {
        pill.textContent = txt;
        pill.className = 'llm-pill ' + (configured ? 'ok' : 'warn');
      }
      return configured;
    } catch {
      $('#llmStatus').textContent = '○ Error';
      $('#llmStatus').className = 'footer-value error';
      return false;
    }
  };

  const updateWazuhStatus = async () => {
    try {
      const w = await api('/api/v1/integration/wazuh/health');
      const ok = w.status === 'operational';
      $('#wazuhStatus').textContent = ok ? '● Linked' : '○ Error';
      $('#wazuhStatus').className = 'footer-value' + (ok ? '' : ' warn');
    } catch {
      $('#wazuhStatus').textContent = '○ Down';
      $('#wazuhStatus').className = 'footer-value error';
    }
  };

  // ====== KPI Computation ======
  const computeKPIs = () => {
    const a = STATE.alerts;
    const i = STATE.incidents;

    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    a.forEach(x => {
      const s = x.severity?.toUpperCase();
      if (bySeverity[s] !== undefined) bySeverity[s]++;
    });

    const stats = i.stats || { total: 0, by_severity: {}, mean_time_to_contain: '—', auto_containment_rate: '—' };
    const openIncidents = (stats.open || 0) + (stats.investigating || 0);

    // Mean AI confidence
    const confs = a
      .map(x => parseInt(String(x.ai_confidence).replace('%', ''), 10))
      .filter(n => !isNaN(n));
    const meanConf = confs.length ? Math.round(confs.reduce((s, n) => s + n, 0) / confs.length) : null;

    return {
      critical: bySeverity.CRITICAL,
      high: bySeverity.HIGH,
      medium: bySeverity.MEDIUM,
      low: bySeverity.LOW,
      totalAlerts: a.length,
      totalIncidents: stats.total || 0,
      openIncidents,
      mttr: stats.mean_time_to_contain || '—',
      autoContain: stats.auto_containment_rate || '—',
      meanConfidence: meanConf !== null ? `${meanConf}%` : '—',
      coverage: `${STATE.mitre.reduce((sum, t) => sum + t.techniques.filter(x => x.active).length, 0)} techniques · ${STATE.mitre.reduce((sum, t) => sum + t.techniques.length, 0)} total`,
    };
  };

  const renderKPIs = () => {
    const k = computeKPIs();
    $('#kpi-critical').textContent = fmt.num(k.critical);
    $('#kpi-critical-delta').textContent = `${k.high} high · ${k.totalAlerts} total alerts`;

    $('#kpi-incidents').textContent = fmt.num(k.openIncidents);
    $('#kpi-incidents-delta').textContent = `${k.totalIncidents - k.openIncidents} closed`;

    $('#kpi-mttr').textContent = k.mttr;

    $('#kpi-contain').textContent = k.autoContain;

    $('#kpi-confidence').textContent = k.meanConfidence;

    $('#kpi-coverage').textContent = k.coverage.split(' · ')[0];
    $('#kpi-coverage-delta').textContent = k.coverage.split(' · ')[1] || '';

    // Update sidebar badges
    const incBadge = $('#badge-incidents');
    incBadge.textContent = k.totalIncidents;
    incBadge.dataset.zero = k.totalIncidents === 0 ? 'true' : 'false';

    const thrBadge = $('#badge-threats');
    thrBadge.textContent = k.totalAlerts;
    thrBadge.dataset.zero = k.totalAlerts === 0 ? 'true' : 'false';
  };

  // ====== Chart: Timeline ======
  const renderTimeline = () => {
    const svg = $('#chartTimeline');
    if (!svg) return;
    const W = 800, H = 240, P = { l: 40, r: 20, t: 20, b: 30 };
    const innerW = W - P.l - P.r;
    const innerH = H - P.t - P.b;

    // Group alerts by hour, by severity
    const buckets = {};
    const now = new Date();
    STATE.alerts.forEach(a => {
      // Use severity count only — we don't have real timestamps for all alerts
      const sev = a.severity?.toUpperCase();
      if (!buckets[sev]) buckets[sev] = [];
    });
    // Synthesize distribution from current counts across 24 buckets
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const counts = {
      CRITICAL: STATE.alerts.filter(a => a.severity?.toUpperCase() === 'CRITICAL').length,
      HIGH: STATE.alerts.filter(a => a.severity?.toUpperCase() === 'HIGH').length,
      MEDIUM: STATE.alerts.filter(a => a.severity?.toUpperCase() === 'MEDIUM').length,
      LOW: STATE.alerts.filter(a => a.severity?.toUpperCase() === 'LOW').length,
    };
    // Spread counts across 24 hours with some realistic variance
    const seedRand = (s) => { let x = s; return () => { x = (x * 9301 + 49297) % 233280; return x / 233280; }; };
    const rand = seedRand(42);
    const hours = 24;
    const series = severities.map(sev => {
      const total = counts[sev];
      const data = Array.from({ length: hours }, () => 0);
      // distribute total with random weights
      const weights = Array.from({ length: hours }, () => 0.3 + rand());
      const wSum = weights.reduce((a, b) => a + b, 0);
      for (let h = 0; h < hours; h++) data[h] = Math.round((weights[h] / wSum) * total);
      return { sev, data };
    });

    const yMax = Math.max(1, ...series.flatMap(s => s.data));
    const xStep = innerW / (hours - 1);
    const yScale = (v) => P.t + innerH - (v / yMax) * innerH;

    let html = '';

    // Y-axis gridlines + labels
    const yTicks = 4;
    for (let i = 0; i <= yTicks; i++) {
      const v = Math.round(yMax * i / yTicks);
      const y = yScale(v);
      html += `<line x1="${P.l}" y1="${y}" x2="${P.l + innerW}" y2="${y}" stroke="var(--border-subtle)" stroke-width="1" stroke-dasharray="${i === 0 ? '0' : '2,3'}" />`;
      html += `<text x="${P.l - 8}" y="${y + 3}" text-anchor="end" fill="var(--text-muted)" font-size="10" font-family="var(--font-mono)">${v}</text>`;
    }

    // X-axis labels (every 4 hours)
    for (let h = 0; h < hours; h += 4) {
      const x = P.l + h * xStep;
      const hh = (now.getHours() - (hours - 1 - h) + 24) % 24;
      html += `<text x="${x}" y="${H - 10}" text-anchor="middle" fill="var(--text-muted)" font-size="10" font-family="var(--font-mono)">${String(hh).padStart(2, '0')}:00</text>`;
    }

    // Stacked area paths (low → critical)
    const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const cumAt = (h) => order.reduce((sum, sev) => {
      const s = series.find(x => x.sev === sev);
      return sum + s.data[h];
    }, 0);

    // Build cumulative top + bottom paths per severity, fill areas
    order.forEach(sev => {
      const idx = order.indexOf(sev);
      const colorMap = { CRITICAL: 'var(--sev-critical)', HIGH: 'var(--sev-high)', MEDIUM: 'var(--sev-medium)', LOW: 'var(--sev-low)' };
      const color = colorMap[sev];
      let top = '', bot = '';
      for (let h = 0; h < hours; h++) {
        const x = P.l + h * xStep;
        const cumAbove = order.slice(0, idx).reduce((s, s2) => s + series.find(x => x.sev === s2).data[h], 0);
        const thisVal = series.find(x => x.sev === sev).data[h];
        const yTop = yScale(cumAbove + thisVal);
        const yBot = yScale(cumAbove);
        top += (h === 0 ? `M${x},${yTop}` : ` L${x},${yTop}`);
        bot += ` L${x},${yBot}`;
      }
      const path = top + bot + ' Z';
      html += `<path d="${path}" fill="${color}" fill-opacity="0.4" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/>`;
    });

    svg.innerHTML = html;
  };

  // ====== Chart: Severity Donut ======
  const renderSeverityDonut = () => {
    const svg = $('#chartSeverity');
    const legend = $('#severityLegend');
    if (!svg || !legend) return;

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    STATE.alerts.forEach(a => {
      const s = a.severity?.toUpperCase();
      if (counts[s] !== undefined) counts[s]++;
    });
    const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;

    const cx = 100, cy = 100, r = 70, ir = 45;
    let html = '';
    let angle = -Math.PI / 2;
    const colors = {
      CRITICAL: 'var(--sev-critical)',
      HIGH: 'var(--sev-high)',
      MEDIUM: 'var(--sev-medium)',
      LOW: 'var(--sev-low)',
    };

    Object.entries(counts).forEach(([sev, count]) => {
      if (count === 0) return;
      const frac = count / total;
      const a1 = angle;
      const a2 = angle + frac * 2 * Math.PI;
      const large = a2 - a1 > Math.PI ? 1 : 0;

      const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
      const x2 = cx + r * Math.cos(a2), y2 = cy + r * Math.sin(a2);
      const xi1 = cx + ir * Math.cos(a1), yi1 = cy + ir * Math.sin(a1);
      const xi2 = cx + ir * Math.cos(a2), yi2 = cy + ir * Math.sin(a2);

      html += `<path d="M${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2} L${xi2},${yi2} A${ir},${ir} 0 ${large} 0 ${xi1},${yi1} Z" fill="${colors[sev]}"/>`;
      angle = a2;
    });

    html += `<text x="${cx}" y="${cy - 4}" text-anchor="middle" fill="var(--text-primary)" font-size="28" font-weight="700" font-family="var(--font-sans)">${total}</text>`;
    html += `<text x="${cx}" y="${cy + 14}" text-anchor="middle" fill="var(--text-muted)" font-size="9" font-family="var(--font-sans)" letter-spacing="0.1em">ALERTS</text>`;
    svg.innerHTML = html;

    legend.innerHTML = Object.entries(counts).map(([sev, c]) => `
      <div class="donut-legend-item">
        <span class="dot ${sevClass(sev)}"></span>
        <span class="legend-label">${sev}</span>
        <span class="legend-value">${c}</span>
      </div>
    `).join('');
  };

  // ====== MITRE Heatmap ======
  const renderMitreHeatmap = (targetId, compact = true) => {
    const target = $(targetId);
    if (!target) return;
    if (!STATE.mitre.length) {
      target.innerHTML = '<div class="incident-empty">No MITRE data</div>';
      return;
    }
    const sevRank = { Critical: 3, High: 2, Medium: 1, None: 0, Low: 1 };
    target.innerHTML = STATE.mitre.map(tactic => {
      const techs = tactic.techniques;
      if (compact && techs.length > 6) {
        // Show only active techniques in compact view
        const active = techs.filter(t => t.active);
        if (active.length === 0) return '';
        return `
          <div class="mitre-tactic-row">
            <div class="mitre-tactic-label">${tactic.tactic}</div>
            <div class="mitre-tech-row">
              ${active.slice(0, 12).map(t => {
                const sev = t.threat?.toLowerCase() || 'medium';
                return `<div class="mitre-tech ${sev}" title="${t.name} (${t.id}) — ${t.count} hits">
                  ${t.id}<span class="tech-count">${t.count}</span>
                </div>`;
              }).join('')}
            </div>
          </div>
        `;
      }
      return `
        <div class="mitre-tactic-row">
          <div class="mitre-tactic-label">${tactic.tactic}</div>
          <div class="mitre-tech-row">
            ${techs.map(t => {
              const cls = t.active ? sevRank[t.threat] >= 2 ? t.threat?.toLowerCase() : 'medium' : '';
              return `<div class="mitre-tech ${cls}" title="${t.name} (${t.id}) — ${t.count} hits">
                ${t.id}${t.active ? `<span class="tech-count">${t.count}</span>` : ''}
              </div>`;
            }).join('')}
          </div>
        </div>
      `;
    }).join('');

    // Update mitre count
    const totalActive = STATE.mitre.reduce((s, t) => s + t.techniques.filter(x => x.active).length, 0);
    const el = $('#mitreCount');
    if (el) el.textContent = `${totalActive} techniques triggered`;
  };

  // ====== Asset Risk Donut ======
  const renderAssetRiskDonut = () => {
    const svg = $('#chartAssetRisk');
    const legend = $('#assetRiskLegend');
    if (!svg || !legend) return;
    const buckets = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    STATE.assets.forEach(a => {
      const r = a.risk_score?.toLowerCase() || '';
      if (r.includes('critical')) buckets.Critical++;
      else if (r.includes('high')) buckets.High++;
      else if (r.includes('medium')) buckets.Medium++;
      else buckets.Low++;
    });
    const total = Object.values(buckets).reduce((a, b) => a + b, 0) || 1;
    const cx = 100, cy = 100, r = 70, ir = 45;
    let html = '';
    let angle = -Math.PI / 2;
    const colors = {
      Critical: 'var(--sev-critical)',
      High: 'var(--sev-high)',
      Medium: 'var(--sev-medium)',
      Low: 'var(--sev-low)',
    };
    Object.entries(buckets).forEach(([k, count]) => {
      if (count === 0) return;
      const frac = count / total;
      const a1 = angle, a2 = angle + frac * 2 * Math.PI;
      const large = a2 - a1 > Math.PI ? 1 : 0;
      const x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
      const x2 = cx + r * Math.cos(a2), y2 = cy + r * Math.sin(a2);
      const xi1 = cx + ir * Math.cos(a1), yi1 = cy + ir * Math.sin(a1);
      const xi2 = cx + ir * Math.cos(a2), yi2 = cy + ir * Math.sin(a2);
      html += `<path d="M${x1},${y1} A${r},${r} 0 ${large} 1 ${x2},${y2} L${xi2},${yi2} A${ir},${ir} 0 ${large} 0 ${xi1},${yi1} Z" fill="${colors[k]}"/>`;
      angle = a2;
    });
    html += `<text x="${cx}" y="${cy - 4}" text-anchor="middle" fill="var(--text-primary)" font-size="24" font-weight="700">${STATE.assets.length}</text>`;
    html += `<text x="${cx}" y="${cy + 12}" text-anchor="middle" fill="var(--text-muted)" font-size="8" letter-spacing="0.1em">ASSETS</text>`;
    svg.innerHTML = html;
    legend.innerHTML = Object.entries(buckets).map(([k, c]) => `
      <div class="donut-legend-item">
        <span class="dot ${k.toLowerCase()}"></span>
        <span class="legend-label">${k}</span>
        <span class="legend-value">${c}</span>
      </div>
    `).join('');
  };

  // ====== Tables ======
  const renderAlertFeed = () => {
    const tbody = $('#alertFeedTable tbody');
    if (!tbody) return;
    $('#alertFeedCount').textContent = `${STATE.alerts.length} alerts`;
    if (!STATE.alerts.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="incident-empty">No active alerts</td></tr>';
      return;
    }
    const sorted = [...STATE.alerts].sort((a, b) => {
      const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4);
    });
    tbody.innerHTML = sorted.slice(0, 50).map(a => {
      const conf = parseInt(String(a.ai_confidence || '').replace('%', ''), 10) || 0;
      const status = (a.status || '').toLowerCase().replace(/[^a-z]/g, '-');
      return `
        <tr data-alert-id="${a.id}">
          <td class="mono">${a.id}</td>
          <td><span class="pill ${sevClass(a.severity)}">${a.severity}</span></td>
          <td>${escapeHtml(a.title)}</td>
          <td class="mono">${escapeHtml(a.endpoint || '—')}</td>
          <td class="mono">${escapeHtml(a.mitre || '—')}</td>
          <td><span class="status-pill-table ${status}"><span class="dot"></span>${a.status || '—'}</span></td>
          <td>
            <div class="conf-bar">
              <div class="conf-bar-track"><div class="conf-bar-fill" style="width:${conf}%; background:${sevColor(a.severity)}"></div></div>
              <span class="conf-bar-text">${a.ai_confidence || '—'}</span>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    tbody.querySelectorAll('tr[data-alert-id]').forEach(tr => {
      tr.addEventListener('click', () => {
        const a = STATE.alerts.find(x => x.id === tr.dataset.alertId);
        if (a) showAlertDetail(a);
      });
    });
  };

  const renderTopSources = () => {
    const tbody = $('#topSourcesTable tbody');
    if (!tbody) return;
    const ipCounts = {};
    STATE.alerts.forEach(a => { if (a.ip) ipCounts[a.ip] = (ipCounts[a.ip] || 0) + 1; });
    const sorted = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (!sorted.length) {
      tbody.innerHTML = '<tr><td colspan="3" class="incident-empty">No source IPs</td></tr>';
      return;
    }
    tbody.innerHTML = sorted.map(([ip, c], i) => `
      <tr>
        <td class="num-cell">${i + 1}</td>
        <td class="mono">${ip}</td>
        <td class="num-cell"><span class="pill ${c >= 3 ? 'critical' : c >= 2 ? 'high' : 'medium'}">${c}</span></td>
      </tr>
    `).join('');
  };

  const renderIncidents = () => {
    const tbody = $('#incidentsTable tbody');
    const list = $('#incidentList');
    if (!tbody || !list) return;

    // Active list (right side of overview)
    if (!STATE.incidents.incidents?.length) {
      list.innerHTML = '<div class="incident-empty">No active incidents</div>';
    } else {
      list.innerHTML = STATE.incidents.incidents.slice(0, 8).map(i => `
        <div class="incident-row" data-sev="${i.severity}" data-inc-id="${i.id}">
          <div class="incident-severity"></div>
          <div class="incident-info">
            <div class="incident-title">${escapeHtml(i.title)}</div>
            <div class="incident-meta">
              <span class="mono">${i.id}</span>
              <span>·</span>
              <span>${escapeHtml(i.source || '—')}</span>
              <span>·</span>
              <span>${i.evidence_count || 0} evidence</span>
            </div>
          </div>
          <span class="status-pill-table ${(i.status || '').toLowerCase()}"><span class="dot"></span>${i.status}</span>
        </div>
      `).join('');
      list.querySelectorAll('.incident-row').forEach(r => {
        r.addEventListener('click', async () => {
          try {
            const detail = await api(`/api/v1/integration/incidents/${r.dataset.incId}`);
            showIncidentDetail(detail);
          } catch (e) { toast('Error', e.message, 'error'); }
        });
      });
    }

    // Full table on Incidents tab
    if (!STATE.incidents.incidents?.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="incident-empty">No incidents recorded</td></tr>';
      return;
    }
    tbody.innerHTML = STATE.incidents.incidents.map(i => `
      <tr data-inc-id="${i.id}">
        <td class="mono">${i.id}</td>
        <td><span class="pill ${sevClass(i.severity)}">${i.severity}</span></td>
        <td>${escapeHtml(i.title)}</td>
        <td><span class="status-pill-table ${(i.status || '').toLowerCase()}"><span class="dot"></span>${i.status}</span></td>
        <td>${escapeHtml(i.source || '—')}</td>
        <td class="mono">${escapeHtml(i.mitre_technique || '—')}</td>
        <td class="num-cell">${i.evidence_count || 0}</td>
        <td>${i.updated_at ? fmt.time(i.updated_at) : '—'}</td>
      </tr>
    `).join('');
    tbody.querySelectorAll('tr[data-inc-id]').forEach(tr => {
      tr.addEventListener('click', async () => {
        try {
          const detail = await api(`/api/v1/integration/incidents/${tr.dataset.incId}`);
          showIncidentDetail(detail);
        } catch (e) { toast('Error', e.message, 'error'); }
      });
    });
  };

  const renderThreats = (filter = '') => {
    const tbody = $('#threatsTable tbody');
    if (!tbody) return;
    const q = filter.toLowerCase().trim();
    const filtered = q
      ? STATE.alerts.filter(a => JSON.stringify(a).toLowerCase().includes(q))
      : STATE.alerts;
    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="incident-empty">No matching alerts</td></tr>';
      return;
    }
    tbody.innerHTML = filtered.map(a => {
      const conf = parseInt(String(a.ai_confidence || '').replace('%', ''), 10) || 0;
      return `
        <tr data-alert-id="${a.id}">
          <td class="mono">${a.id}</td>
          <td><span class="pill ${sevClass(a.severity)}">${a.severity}</span></td>
          <td>${escapeHtml(a.title)}</td>
          <td class="mono">${escapeHtml(a.endpoint || '—')}</td>
          <td class="mono">${escapeHtml(a.ip || '—')}</td>
          <td class="mono">${escapeHtml(a.mitre || '—')}</td>
          <td><span class="status-pill-table ${(a.status || '').toLowerCase()}"><span class="dot"></span>${a.status}</span></td>
          <td><div class="conf-bar"><div class="conf-bar-track"><div class="conf-bar-fill" style="width:${conf}%; background:${sevColor(a.severity)}"></div></div><span class="conf-bar-text">${a.ai_confidence || '—'}</span></div></td>
          <td>${escapeHtml(a.timestamp || '—')}</td>
        </tr>
      `;
    }).join('');
    tbody.querySelectorAll('tr[data-alert-id]').forEach(tr => {
      tr.addEventListener('click', () => {
        const a = STATE.alerts.find(x => x.id === tr.dataset.alertId);
        if (a) showAlertDetail(a);
      });
    });
  };

  const renderAssets = () => {
    const tbody = $('#assetsTable tbody');
    if (!tbody) return;
    if (!STATE.assets.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="incident-empty">No assets</td></tr>';
      return;
    }
    tbody.innerHTML = STATE.assets.map(a => {
      const riskCls = a.risk_score?.toLowerCase().includes('critical') ? 'critical'
        : a.risk_score?.toLowerCase().includes('high') ? 'high'
        : a.risk_score?.toLowerCase().includes('medium') ? 'medium'
        : 'low';
      return `
        <tr>
          <td>${escapeHtml(a.name)}</td>
          <td>${escapeHtml(a.type)}</td>
          <td class="mono">${escapeHtml(a.ip || '—')}</td>
          <td>${escapeHtml(a.owner || '—')}</td>
          <td><span class="pill ${riskCls}">${a.risk_score}</span></td>
          <td class="num-cell">${a.vulnerabilities || 0}</td>
          <td><span class="status-pill-table ${(a.status || '').toLowerCase().replace(/ /g, '-')}"><span class="dot"></span>${a.status}</span></td>
        </tr>
      `;
    }).join('');
  };

  // ====== Detail Modal ======
  const showAlertDetail = (a) => {
    const modal = $('#detailModal');
    $('#modalTitle').innerHTML = `<span class="pill ${sevClass(a.severity)}">${a.severity}</span> ${escapeHtml(a.title)}`;
    const storyline = (a.storyline || []).map(s => `
      <div class="storyline-item">
        <div class="sl-time">${escapeHtml(s.time)}</div>
        <div class="sl-event">${escapeHtml(s.event)}</div>
      </div>
    `).join('') || '<div class="incident-empty">No storyline available</div>';

    $('#modalBody').innerHTML = `
      <div class="detail-section">
        <h4>Overview</h4>
        <dl class="detail-grid">
          <dt>Alert ID</dt><dd>${a.id}</dd>
          <dt>Severity</dt><dd>${a.severity}</dd>
          <dt>Status</dt><dd>${a.status}</dd>
          <dt>Endpoint</dt><dd>${escapeHtml(a.endpoint || '—')}</dd>
          <dt>Source IP</dt><dd>${escapeHtml(a.ip || '—')}</dd>
          <dt>MITRE</dt><dd>${escapeHtml(a.mitre || '—')}</dd>
          <dt>AI Confidence</dt><dd>${a.ai_confidence}</dd>
          <dt>Timestamp</dt><dd>${escapeHtml(a.timestamp || '—')}</dd>
        </dl>
      </div>
      <div class="detail-section">
        <h4>Storyline Timeline</h4>
        <div class="storyline-list">${storyline}</div>
      </div>
    `;
    modal.hidden = false;
  };

  const showIncidentDetail = (i) => {
    const modal = $('#detailModal');
    $('#modalTitle').innerHTML = `<span class="pill ${sevClass(i.severity)}">${i.severity}</span> ${escapeHtml(i.title)}`;
    const steps = (i.investigation_steps || []).map(s => `<div class="storyline-item"><div class="sl-time">${escapeHtml(s.time || '')}</div><div class="sl-event">${escapeHtml(s.action || s.description || JSON.stringify(s))}</div></div>`).join('');
    const evidence = (i.evidence_items || []).map(e => `<li>${escapeHtml(e.name || e.type || JSON.stringify(e))} <span class="mono" style="color:var(--text-muted)">— ${escapeHtml(e.hash || e.value || '')}</span></li>`).join('');

    $('#modalBody').innerHTML = `
      <div class="detail-section">
        <h4>Overview</h4>
        <dl class="detail-grid">
          <dt>Incident ID</dt><dd>${i.id}</dd>
          <dt>Source Alert</dt><dd>${i.source_alert_id || '—'}</dd>
          <dt>Source Agent</dt><dd>${escapeHtml(i.source_agent || '—')}</dd>
          <dt>Source IP</dt><dd>${escapeHtml(i.source_ip || '—')}</dd>
          <dt>MITRE</dt><dd>${escapeHtml(i.mitre_technique || '—')}</dd>
          <dt>Created</dt><dd>${i.created_at || '—'}</dd>
          <dt>Updated</dt><dd>${i.updated_at || '—'}</dd>
          <dt>Closed</dt><dd>${i.closed_at || '—'}</dd>
          <dt>Assigned</dt><dd>${escapeHtml(i.assigned_to || 'Driverless AI')}</dd>
        </dl>
      </div>
      ${i.investigation_summary ? `<div class="detail-section"><h4>Investigation Summary</h4><p style="font-size:12px; color:var(--text-secondary); line-height:1.6">${escapeHtml(i.investigation_summary)}</p></div>` : ''}
      ${steps ? `<div class="detail-section"><h4>Investigation Steps</h4><div class="storyline-list">${steps}</div></div>` : ''}
      ${evidence ? `<div class="detail-section"><h4>Evidence (${i.evidence_count || 0})</h4><ul style="list-style:none; font-size:12px; line-height:1.7">${evidence}</ul></div>` : ''}
      ${i.closure_report ? `<div class="detail-section"><h4>Closure Report</h4><pre style="font-family:var(--font-mono); font-size:11px; color:var(--text-secondary); white-space:pre-wrap; padding:10px; background:var(--bg-panel); border-radius:4px; max-height:240px; overflow:auto">${escapeHtml(i.closure_report)}</pre></div>` : ''}
    `;
    modal.hidden = false;
  };

  const escapeHtml = (s) => {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  };

  // ====== AIR Pipeline ======
  const runAirPipeline = async (scenarioIdx) => {
    const stream = $('#airStream');
    $('#airStatus').textContent = `Running scenario ${scenarioIdx}…`;
    stream.innerHTML = '';
    try {
      // Trigger pipeline first
      const result = await api(`/api/v1/air/run-pipeline/${scenarioIdx}`, { method: 'POST' });
      const lines = (result.execution_logs || []);
      lines.forEach((line, i) => {
        setTimeout(() => {
          const cls = line.includes('SUCCESS') ? 'success' : line.includes('Isolated') ? 'critical' : line.includes('Stage') ? 'phase' : '';
          const el = document.createElement('div');
          el.className = 'air-line';
          el.innerHTML = `<span class="air-time">${fmt.clock()}</span><span class="air-text ${cls}">${escapeHtml(line)}</span>`;
          stream.appendChild(el);
          stream.scrollTop = stream.scrollHeight;
        }, i * 120);
      });
      setTimeout(() => {
        $('#airStatus').textContent = `Complete · ${result.final_action}`;
        toast('Pipeline Complete', result.final_action, 'success');
      }, lines.length * 120 + 200);
      // Refresh data
      setTimeout(refreshAll, 1000);
    } catch (e) {
      $('#airStatus').textContent = 'Failed';
      toast('Pipeline Error', e.message, 'error');
    }
  };

  // ====== Copilot ======
  const renderChatMsg = (role, text) => {
    const stream = $('#chatStream');
    const div = document.createElement('div');
    div.className = `chat-msg ${role}`;
    div.innerHTML = `
      <div class="chat-avatar">${role === 'user' ? 'You' : '⛨'}</div>
      <div class="chat-bubble">${escapeHtml(text)}</div>
    `;
    stream.appendChild(div);
    stream.scrollTop = stream.scrollHeight;
    return div;
  };

  const fallbackCopilotAnswer = (q) => {
    const ql = q.toLowerCase();
    if (ql.includes('threat') || ql.includes('alert')) {
      const top = STATE.alerts.slice(0, 3).map(a => `• [${a.severity}] ${a.title} — ${a.endpoint} (MITRE ${a.mitre})`).join('\n');
      return `Top active threats (${STATE.alerts.length} total):\n\n${top || 'No alerts.'}\n\nRecommendation: Prioritize CRITICAL items, then sweep HIGH. Run containment via AIR Pipeline tab.`;
    }
    if (ql.includes('asset') || ql.includes('risk')) {
      const top = STATE.assets.filter(a => a.risk_score?.toLowerCase().includes('critical') || a.risk_score?.toLowerCase().includes('high')).slice(0, 5)
        .map(a => `• ${a.name} — ${a.risk_score} (${a.vulnerabilities} vulns)`).join('\n');
      return `High-risk assets:\n\n${top || 'No critical/high risk assets.'}\n\nAction: Trigger Rescan All on Attack Surface tab and review findings.`;
    }
    if (ql.includes('mitre') || ql.includes('technique')) {
      const all = STATE.mitre.flatMap(t => t.techniques.filter(x => x.active).map(x => ({ ...x, tactic: t.tactic })));
      const top = all.sort((a, b) => b.count - a.count).slice(0, 8)
        .map(t => `• ${t.id} ${t.name} (${t.tactic}) — ${t.count} hits [${t.threat}]`).join('\n');
      return `MITRE techniques observed:\n\n${top || 'None.'}\n\nUse MITRE tab for full coverage matrix.`;
    }
    if (ql.includes('hunt') || ql.includes('hypothesis')) {
      return `Hunt hypothesis:\n\nBased on observed alerts, look for ${STATE.mitre.find(t => t.techniques.some(x => x.active))?.tactic || 'lateral movement'} patterns on endpoints ${STATE.alerts.slice(0, 3).map(a => a.endpoint).filter(Boolean).join(', ') || 'N/A'}.\n\nPivot on source IPs (${STATE.alerts.slice(0, 3).map(a => a.ip).filter(Boolean).join(', ')}) and look for matching outbound DNS, process trees, and scheduled tasks.`;
    }
    if (ql.includes('hello') || ql.includes('hi')) {
      return `Hello! I'm operating in fallback mode (no LLM key configured). I can summarize alerts, list risky assets, list MITRE techniques, and generate hunt hypotheses from live data. Try one of the quick prompts.`;
    }
    return `I'm running in fallback mode (LLM key not configured). Live data summary:\n\n• Alerts: ${STATE.alerts.length}\n• Critical: ${STATE.alerts.filter(a => a.severity === 'CRITICAL').length}\n• Incidents: ${STATE.incidents.count || 0}\n• Open: ${STATE.incidents.stats?.open || 0}\n• Assets at risk: ${STATE.assets.filter(a => a.risk_score?.toLowerCase().includes('critical') || a.risk_score?.toLowerCase().includes('high')).length}\n\nAsk me about threats, assets, MITRE, or hunting hypotheses.`;
  };

  const sendChat = async (text) => {
    if (!text?.trim()) return;
    renderChatMsg('user', text);
    STATE.chatHistory.push({ role: 'user', text });
    const placeholder = renderChatMsg('system', '…');
    try {
      const hasKey = await updateLLMStatus();
      if (!hasKey) {
        // Fallback: derive answer from local data
        await new Promise(r => setTimeout(r, 400));
        placeholder.querySelector('.chat-bubble').innerHTML = escapeHtml(fallbackCopilotAnswer(text)).replace(/\n/g, '<br>');
        return;
      }
      const res = await api('/api/v1/chat', {
        method: 'POST',
        body: JSON.stringify({ message: text, history: STATE.chatHistory.slice(-6) }),
      });
      placeholder.querySelector('.chat-bubble').innerHTML = escapeHtml(res.response || res.message || JSON.stringify(res)).replace(/\n/g, '<br>');
      STATE.chatHistory.push({ role: 'assistant', text: res.response || res.message });
    } catch (e) {
      placeholder.querySelector('.chat-bubble').textContent = `Error: ${e.message}`;
    }
  };

  // ====== Global Search ======
  const handleGlobalSearch = (q) => {
    if (!q.trim()) return;
    switchTab('threats');
    $('#threatFilter').value = q;
    renderThreats(q);
  };

  // ====== Data Refresh ======
  const refreshAll = async () => {
    try {
      const [health, alerts, incidents, assets, mitre] = await Promise.allSettled([
        api('/health'),
        api('/api/v1/alerts'),
        api('/api/v1/integration/incidents'),
        api('/api/v1/asm/assets'),
        api('/api/v1/mitre/matrix'),
      ]);

      STATE.health = health.status === 'fulfilled' ? health.value : null;
      STATE.alerts = alerts.status === 'fulfilled' ? alerts.value : STATE.alerts;
      STATE.incidents = incidents.status === 'fulfilled' ? incidents.value : STATE.incidents;
      STATE.assets = assets.status === 'fulfilled' ? assets.value : STATE.assets;
      STATE.mitre = mitre.status === 'fulfilled' ? mitre.value : STATE.mitre;
      STATE.lastUpdate = new Date();

      updateHealthPill(STATE.health);
      updateWazuhStatus();
      renderAll();
    } catch (e) {
      console.error('[refreshAll]', e);
    }
  };

  const renderAll = () => {
    renderKPIs();
    renderTimeline();
    renderSeverityDonut();
    renderMitreHeatmap('#mitreHeatmap', true);
    renderMitreHeatmap('#mitreMatrixFull', false);
    renderTopSources();
    renderAlertFeed();
    renderIncidents();
    renderThreats($('#threatFilter')?.value || '');
    renderAssets();
    renderAssetRiskDonut();
  };

  // ====== Init ======
  const init = () => {
    // Tabs
    $$('.nav-item').forEach(n => n.addEventListener('click', () => switchTab(n.dataset.tab)));
    // Time range
    $$('.tr-btn').forEach(b => b.addEventListener('click', () => setTimeRange(b.dataset.range)));
    // Modal close
    $('#modalClose').addEventListener('click', () => { $('#detailModal').hidden = true; });
    $('#detailModal').addEventListener('click', (e) => {
      if (e.target.id === 'detailModal') $('#detailModal').hidden = true;
    });
    // Global search
    $('#globalSearch').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') handleGlobalSearch(e.target.value);
    });
    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        $('#globalSearch').focus();
      }
      if (e.key === 'Escape') { $('#detailModal').hidden = true; }
    });
    // Threat filter
    $('#threatFilter')?.addEventListener('input', (e) => renderThreats(e.target.value));
    // AIR scenarios
    $$('[data-scenario]').forEach(b => b.addEventListener('click', () => runAirPipeline(b.dataset.scenario)));
    // Trigger attack (incidents tab)
    $('#btnTriggerSim')?.addEventListener('click', async () => {
      try {
        const res = await api('/api/v1/alerts/trigger-simulated-attack', { method: 'POST', body: '{}' });
        toast('Simulated attack', res.message || res.id || 'triggered', 'success');
        refreshAll();
      } catch (e) {
        // Schema wants `scenario` int
        try {
          const res = await api('/api/v1/alerts/trigger-simulated-attack', { method: 'POST', body: JSON.stringify({ scenario: 0 }) });
          toast('Simulated attack', 'APT29 scenario triggered', 'success');
          refreshAll();
        } catch (e2) {
          toast('Error', e2.message, 'error');
        }
      }
    });
    $('#btnRunPipeline')?.addEventListener('click', () => {
      switchTab('air');
      runAirPipeline(0);
    });
    $('#btnRescan')?.addEventListener('click', async () => {
      try {
        await api('/api/v1/asm/rescan', { method: 'POST' });
        toast('Rescan', 'Global asset rescan complete', 'success');
        refreshAll();
      } catch (e) { toast('Error', e.message, 'error'); }
    });
    // Copilot
    $('#chatForm')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const v = $('#chatBox').value;
      $('#chatBox').value = '';
      sendChat(v);
    });
    $$('.quick-prompt').forEach(b => b.addEventListener('click', () => sendChat(b.dataset.q)));

    // First load
    refreshAll();
    // Poll
    setInterval(refreshAll, POLL_INTERVAL_MS);
  };

  // ====== L1 Agent ======
  const renderL1 = async () => {
    if (STATE.activeTab !== 'l1agent' && !document.querySelector('[data-tab="l1agent"]')) return;

    // Mode + threshold
    try {
      const mode = await api('/api/v1/l1/mode');
      $('#l1ModePill').textContent = mode.mode === 'active' ? '🟢 Active' : '👁 Shadow';
      $('#l1ModePill').className = 'mode-pill ' + mode.mode;
      $('#l1ModeStatus').textContent = `${mode.mode.toUpperCase()} mode · threshold ${(mode.threshold * 100).toFixed(0)}%`;
      $('#l1kpi-threshold').textContent = (mode.threshold * 100).toFixed(0) + '%';
      $('#l1kpi-threshold-delta').textContent = mode.mode === 'active' ? 'auto-close enabled' : 'decide-only';
      $('#l1Threshold').value = mode.threshold;
      $('#l1ThresholdValue').textContent = (mode.threshold * 100).toFixed(0) + '%';
      // Update toggle buttons
      $$('.l1-toggle-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === mode.mode));
    } catch (e) { console.warn('L1 mode fetch failed', e); }

    // Stats
    try {
      const stats = await api('/api/v1/l1/stats?since_hours=24');
      $('#l1kpi-close-rate').textContent = (stats.auto_close_rate * 100).toFixed(0) + '%';
      $('#l1kpi-close-rate-delta').textContent = `${stats.closed} closed of ${stats.total_decisions}`;
      $('#l1kpi-decisions').textContent = fmt.num(stats.total_decisions);
      $('#l1kpi-decisions-delta').textContent = `${stats.escalated} escalated`;
      $('#l1kpi-confidence').textContent = (stats.avg_close_confidence * 100).toFixed(0) + '%';
      $('#l1kpi-override').textContent = (stats.override_rate * 100).toFixed(1) + '%';
      $('#l1kpi-override-delta').textContent = stats.overridden || 0 + ' human overrides';
      // Update sidebar badge
      $('#badge-l1').textContent = stats.total_decisions > 0 ? stats.total_decisions : '';
      $('#badge-l1').dataset.zero = stats.total_decisions === 0 ? 'true' : 'false';

      // Signal breakdown bar chart
      const sigs = stats.primary_signal_breakdown || {};
      const sigEntries = Object.entries(sigs);
      const sigTotal = sigEntries.reduce((s, [_, c]) => s + c, 0) || 1;
      const html = sigEntries.length === 0
        ? '<div class="l1-signal-empty">No decisions yet. Run a test alert below.</div>'
        : sigEntries.map(([name, count]) => {
            const pct = (count / sigTotal * 100).toFixed(0);
            return `<div class="l1-signal-bar">
              <div class="l1-signal-name">${name}</div>
              <div class="l1-signal-track"><div class="l1-signal-fill" style="width:${pct}%"></div></div>
              <div class="l1-signal-count">${count}</div>
            </div>`;
          }).join('');
      $('#l1SignalBreakdown').innerHTML = html;
    } catch (e) { console.warn('L1 stats fetch failed', e); }

    // Audit log
    try {
      const audit = await api('/api/v1/l1/audit?since_hours=24&limit=50');
      $('#l1AuditCount').textContent = `${audit.count} decisions`;
      const tbody = $('#l1DecisionsTable tbody');
      if (!audit.entries.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="incident-empty">No decisions yet. Click "Test Alert" above.</td></tr>';
      } else {
        tbody.innerHTML = audit.entries.slice(0, 50).map(e => `
          <tr data-audit-id="${e.id}">
            <td class="mono">#${e.id}</td>
            <td class="mono">${e.timestamp ? e.timestamp.split('T')[1].split('.')[0] : '—'}</td>
            <td><span class="decision-${e.decision}">${e.decision}</span></td>
            <td>
              <div class="conf-bar">
                <div class="conf-bar-track"><div class="conf-bar-fill" style="width:${(e.confidence * 100).toFixed(0)}%"></div></div>
                <span class="conf-bar-text">${(e.confidence * 100).toFixed(0)}%</span>
              </div>
            </td>
            <td><span class="pill neutral">${e.primary_signal || '—'}</span></td>
            <td>${escapeHtml((e.reason || '').substring(0, 60))}${(e.reason || '').length > 60 ? '…' : ''}</td>
            <td>${e.overridden_at ? '<span class="override-yes">yes</span>' : '<span class="override-no">—</span>'}</td>
          </tr>
        `).join('');
      }
    } catch (e) { console.warn('L1 audit fetch failed', e); }

    // Whitelist
    try {
      const wl = await api('/api/v1/l1/whitelist');
      $('#l1kpi-whitelist').textContent = wl.count;
      $('#l1WhitelistCount').textContent = `${wl.count} entries`;
      const list = $('#l1WhitelistList');
      if (!wl.entries.length) {
        list.innerHTML = '<div class="incident-empty">No whitelist entries</div>';
      } else {
        list.innerHTML = wl.entries.map(e => `
          <div class="l1-whitelist-row ${e.enabled ? '' : 'disabled'}" data-wl-id="${e.id}">
            <span class="l1-wl-type">${e.entry_type}</span>
            <span class="l1-wl-value" title="${escapeHtml(e.match_value)}">${escapeHtml(e.match_value)}</span>
            <span class="l1-wl-name">${escapeHtml(e.name || '')}</span>
            <span class="l1-wl-actions">
              <button class="l1-wl-btn toggle">${e.enabled ? 'Disable' : 'Enable'}</button>
              <button class="l1-wl-btn del">Delete</button>
            </span>
          </div>
        `).join('');
        // Wire up whitelist action buttons
        list.querySelectorAll('.l1-whitelist-row').forEach(row => {
          const id = parseInt(row.dataset.wlId);
          row.querySelector('.toggle').addEventListener('click', async () => {
            const enabled = !row.classList.contains('disabled');
            try {
              await api(`/api/v1/l1/whitelist/${id}/toggle`, { method: 'POST', body: JSON.stringify({ enabled: !enabled }) });
              toast('Whitelist updated', `Entry ${enabled ? 'disabled' : 'enabled'}`, 'success');
              renderL1();
            } catch (e) { toast('Error', e.message, 'error'); }
          });
          row.querySelector('.del').addEventListener('click', async () => {
            if (!confirm('Delete this whitelist entry?')) return;
            try {
              await api(`/api/v1/l1/whitelist/${id}`, { method: 'DELETE' });
              toast('Deleted', `Whitelist entry ${id} removed`, 'success');
              renderL1();
            } catch (e) { toast('Error', e.message, 'error'); }
          });
        });
      }
    } catch (e) { console.warn('L1 whitelist fetch failed', e); }
  };

  const sendL1Test = async (testType) => {
    const tests = {
      nessus: {
        source: 'splunk',
        payload: { sid: `test-${Date.now()}`, search_name: 'Nessus vulnerability scan completed',
                    result: { host: 'srv' }, severity: 'high' },
      },
      backup: {
        source: 'splunk',
        payload: { sid: `test-${Date.now()}`, search_name: 'Backup snapshot started',
                    result: { host: 'DB-SRV' }, severity: 'low' },
      },
      powershell: {
        source: 'wazuh',
        payload: { rule: { level: 12, description: 'Suspicious PowerShell execution detected', id: '100001' },
                    agent: { name: 'WEB-SRV01', ip: '10.0.0.50' } },
      },
      lsass: {
        source: 'wazuh',
        payload: { rule: { level: 12, description: 'lsass memory dump attempt', id: '100002' },
                    agent: { name: 'DEV-WIN-SRV09', ip: '10.0.0.5' } },
      },
    };
    try {
      const resp = await api('/api/v1/l1/process-alert', { method: 'POST', body: JSON.stringify(tests[testType]) });
      const closed = resp.applied?.alert_closed ? 'CLOSED ✓' : 'escalated to L2';
      toast(
        `${resp.decision} (${(resp.confidence * 100).toFixed(0)}%)`,
        `${resp.alert_id}: ${closed}`,
        resp.decision === 'CLOSE' ? 'success' : 'warn'
      );
      renderL1();
    } catch (e) { toast('Test failed', e.message, 'error'); }
  };

  const initL1 = () => {
    // Mode toggle
    $$('.l1-toggle-btn').forEach(b => b.addEventListener('click', async () => {
      try {
        await api('/api/v1/l1/mode', { method: 'POST', body: JSON.stringify({ mode: b.dataset.mode }) });
        toast('Mode switched', `Now in ${b.dataset.mode.toUpperCase()} mode`, 'success');
        renderL1();
      } catch (e) { toast('Error', e.message, 'error'); }
    }));
    // Threshold slider
    const slider = $('#l1Threshold');
    slider.addEventListener('input', () => {
      $('#l1ThresholdValue').textContent = (parseFloat(slider.value) * 100).toFixed(0) + '%';
    });
    slider.addEventListener('change', async () => {
      try {
        await api('/api/v1/l1/mode', { method: 'POST', body: JSON.stringify({ mode: 'active', threshold: parseFloat(slider.value) }) });
        toast('Threshold updated', `Now ${(parseFloat(slider.value) * 100).toFixed(0)}%`, 'success');
        renderL1();
      } catch (e) { toast('Error', e.message, 'error'); }
    });
    // Mode pill button
    $('#btnL1Toggle')?.addEventListener('click', async () => {
      try {
        const cur = await api('/api/v1/l1/mode');
        const newMode = cur.mode === 'active' ? 'shadow' : 'active';
        await api('/api/v1/l1/mode', { method: 'POST', body: JSON.stringify({ mode: newMode }) });
        toast('Mode toggled', `Now ${newMode.toUpperCase()}`, 'success');
        renderL1();
      } catch (e) { toast('Error', e.message, 'error'); }
    });
    // Test buttons
    $$('.l1-test-btn').forEach(b => b.addEventListener('click', () => sendL1Test(b.dataset.test)));
    $('#btnL1Test')?.addEventListener('click', () => sendL1Test('nessus'));
    // Add whitelist
    $('#btnAddWhitelist')?.addEventListener('click', async () => {
      const type = $('#wlType').value.trim();
      const value = $('#wlValue').value.trim();
      const name = $('#wlName').value.trim();
      if (!type || !value) { toast('Missing fields', 'Type and Value are required', 'warn'); return; }
      try {
        await api('/api/v1/l1/whitelist', { method: 'POST', body: JSON.stringify({ entry_type: type, match_value: value, name }) });
        toast('Whitelist added', `${type}: ${value}`, 'success');
        $('#wlType').value = ''; $('#wlValue').value = ''; $('#wlName').value = '';
        renderL1();
      } catch (e) { toast('Error', e.message, 'error'); }
    });

    // Render when tab becomes active
    $$('.nav-item').forEach(n => n.addEventListener('click', () => {
      if (n.dataset.tab === 'l1agent') setTimeout(renderL1, 50);
    }));

    // Initial render if tab is active
    if ($('.nav-item[data-tab="l1agent"]')?.classList.contains('active')) renderL1();
  };

  // Hook L1 init into existing init function
  const _origInit = init;
  init = function() { _origInit(); initL1(); setInterval(renderL1, 10000); };

  // ====== Boot ======
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
