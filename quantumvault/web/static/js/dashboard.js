/**
 * QUANTUMVAULT — Security Operations Center Frontend Engine
 * 100% Offline-Compatible, Zero External Dependencies, XSS-Safe DOM Rendering
 */

const API_BASE = '/api/v1';

function getOperatorToken() {
  const meta = document.querySelector('meta[name="qv-operator-token"]');
  return meta ? meta.getAttribute('content') : '';
}

function escapeHtml(value) {
  const str = String(value ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function apiFetch(path, options = {}) {
  const headers = Object.assign(
    { 'X-Operator-Token': getOperatorToken() },
    options.headers || {}
  );
  const res = await fetch(`${API_BASE}${path}`, Object.assign({ credentials: 'same-origin' }, options, { headers }));
  if (!res.ok) {
    let errText = `HTTP ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) errText = String(errJson.detail);
    } catch (_) {}
    throw new Error(errText);
  }
  return res.json();
}

const appState = {
  activeTab: 'nodes',
  events: [],
  filteredEvents: [],
  currentEventIndex: 0,
  isPlayingEvents: false,
  playInterval: null,
  clusterNodes: [],
  scenarios: [],
  demoStatus: null,
  demoViewIndex: 0,
  injectorPresets: [],
  currentPresetId: 'v6',
};

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  loadInitialStatus();
  loadClusterTab();
  loadThreatRadarTab();
  loadPQMessagingTab();
  loadInjectorTab();
  loadSecurityLabTab();
  loadJudgeDemoTab();
});

function initNavigation() {
  document.querySelectorAll('.nav-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
}

function switchTab(tabId) {
  appState.activeTab = tabId;
  document.querySelectorAll('.nav-tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === `tab-${tabId}`);
  });
}

async function loadInitialStatus() {
  try {
    const data = await apiFetch('/status');
    document.getElementById('header-epoch').innerText = `Epoch ${data.cluster_epoch}`;
    document.getElementById('header-key-ver').innerText = `Key ${data.active_key_version}`;
    document.getElementById('header-status-badge').innerText = data.backend_status.toUpperCase();
    document.getElementById('header-operator').innerText = `${data.operator} (${data.role})`;

    const auditBadge = document.getElementById('header-audit-badge');
    auditBadge.innerText = data.audit_verified ? 'VERIFIED' : 'TAMPERED';
    auditBadge.style.color = data.audit_verified ? 'var(--emerald-success)' : 'var(--crimson-alert)';

    const pills = document.getElementById('env-pills-container');
    pills.innerHTML = '';
    Object.values(data.environment_badges || {}).forEach(label => {
      const div = document.createElement('div');
      div.className = 'env-pill active';
      div.textContent = `● ${label}`;
      pills.appendChild(div);
    });

    const incEl = document.getElementById('header-latest-incident');
    if (data.latest_incident) {
      incEl.textContent = `Latest Incident: ${data.latest_incident.incident_id} (${data.latest_incident.rule_id} / ${data.latest_incident.severity.toUpperCase()}) | Revocations: ${data.revoked_entities_count}`;
    } else {
      incEl.textContent = `No Active Incidents | Revocations: ${data.revoked_entities_count}`;
    }
  } catch (e) {
    console.error('Failed to load initial status:', e);
  }
}

// ==============================================================================
// TAB 1: NODES & REVOCATION
// ==============================================================================
async function loadClusterTab() {
  await Promise.all([refreshClusterNodes(), loadDevices(), loadIntegrityStatus()]);
}

function updateKeyLifecycleUI(activeVer, graceActive = false) {
  const actEl = document.getElementById('lifecycle-active-pill');
  const graceEl = document.getElementById('lifecycle-grace-pill');
  if (actEl && activeVer) actEl.innerText = `ACTIVE: ${activeVer}`;
  if (graceEl) graceEl.innerText = graceActive ? 'GRACE_PERIOD: ACTIVE' : 'GRACE_PERIOD';
}

function renderPropagationBars(latencies, probes) {
  const container = document.getElementById('propagation-bars-container');
  if (!container) return;
  container.innerHTML = '';
  const entries = Object.entries(latencies || {});
  if (!entries.length) return;
  const maxVal = Math.max(1.0, ...entries.map(([, v]) => (v > 0 ? v : 0)));
  entries.forEach(([nodeId, ms]) => {
    const probeMs = probes && probes[nodeId] !== undefined ? probes[nodeId] : -1;
    const isOffline = ms < 0;
    const widthPct = isOffline ? 100 : Math.max(8, Math.min(100, Math.round((ms / maxVal) * 100)));
    const row = document.createElement('div');
    row.innerHTML = `
      <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
        <span>${escapeHtml(nodeId)}</span>
        <span style="color:${isOffline ? 'var(--amber-warning)' : 'var(--emerald-success)'}">
          ${isOffline ? 'OFFLINE / FAIL-CLOSED' : `sync=${escapeHtml(ms)}ms | probe=${escapeHtml(probeMs)}ms`}
        </span>
      </div>
      <div style="width:100%; height:6px; background:#090d18; border-radius:3px; overflow:hidden;">
        <div style="width:${widthPct}%; height:100%; background:${isOffline ? 'var(--amber-warning)' : 'var(--cyan-primary)'};"></div>
      </div>
    `;
    container.appendChild(row);
  });
}

async function refreshClusterNodes() {
  try {
    const data = await apiFetch('/cluster/status');
    appState.clusterNodes = data.nodes;
    const container = document.getElementById('cluster-nodes-container');
    container.innerHTML = '';

    data.nodes.forEach(node => {
      const card = document.createElement('div');
      card.className = `node-card ${escapeHtml(node.status)}`;
      card.innerHTML = `
        <div class="node-header">
          <span class="node-name">${escapeHtml(node.name)}</span>
          <span class="node-status-badge ${escapeHtml(node.status)}">${escapeHtml(node.status)}</span>
        </div>
        <div class="node-meta">
          <div>Role: <strong>${escapeHtml(node.role.toUpperCase())}</strong></div>
          <div>Synced Epoch: <strong>${escapeHtml(node.last_heartbeat_epoch)}</strong></div>
          <div>Key Version: <strong>${escapeHtml(node.key_version)}</strong></div>
          <div>Health: <strong>${node.healthy ? 'HEALTHY' : 'FAIL-CLOSED'}</strong></div>
        </div>
      `;
      container.appendChild(card);
    });
    updateKeyLifecycleUI(data.active_key_version, data.grace_period_active);
  } catch (e) {
    console.error('Failed to refresh cluster nodes:', e);
  }
}

async function broadcastRevocation() {
  const actor = document.getElementById('revoke-actor-input').value.trim() || 'analyst-1';
  const logEl = document.getElementById('revocation-log-terminal');
  logEl.innerHTML = `<div class="terminal-line info">[INITIATING] Broadcasting durable revocation for: ${escapeHtml(actor)}...</div>`;

  try {
    const data = await apiFetch('/cluster/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_id: actor, entity_type: 'actor', reason: 'lost_device_reported' }),
    });
    logEl.innerHTML += `
      <div class="terminal-line pass">[COMMITTED] Authority epoch updated to ${escapeHtml(data.epoch)} in ${escapeHtml(data.auth_commit_latency_ms)}ms</div>
      <div class="terminal-line info">[REVOCATION HASH] ${escapeHtml(data.revocation_hash)}</div>
      <div class="terminal-line pass">[CONFIRMED NODES] ${escapeHtml(data.confirmed_nodes.join(', '))} enforced fail-closed denial</div>
      <div class="terminal-line pass">[TOTAL PROPAGATION] Synced in ${escapeHtml(data.total_propagation_ms)}ms</div>
    `;
    renderPropagationBars(data.node_latencies_ms, data.probe_latencies_ms);
    await Promise.all([refreshClusterNodes(), loadInitialStatus(), loadIntegrityStatus()]);
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Revocation broadcast failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function partitionNode(nodeId, action) {
  const logEl = document.getElementById('revocation-log-terminal');
  try {
    const data = await apiFetch('/cluster/partition-node', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: nodeId, action }),
    });
    logEl.innerHTML = `<div class="terminal-line ${action === 'disconnect' ? 'warn' : 'pass'}">[CLUSTER ACTION] ${escapeHtml(data.message)}</div>`;
    await refreshClusterNodes();
  } catch (e) {
    logEl.innerHTML = `<div class="terminal-line fail">[ERROR] Node partition action failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function rotateMasterKey() {
  const logEl = document.getElementById('revocation-log-terminal');
  try {
    const data = await apiFetch('/crypto/rotate-key', { method: 'POST' });
    logEl.innerHTML = `
      <div class="terminal-line pass">[KEY ROTATION] Promoted ${escapeHtml(data.previous_key_version)} → ${escapeHtml(data.active_key_version)} (${escapeHtml(data.rotation_duration_ms)}ms, ${escapeHtml(data.rewrapped_count)} assets rewrapped)</div>
      <div class="terminal-line info">[GRACE PERIOD] Previous key valid during ${escapeHtml(data.grace_period_seconds)}s grace window until ${escapeHtml(data.cutoff_timestamp)}</div>
      <div class="terminal-line pass">[CUTOFF ENFORCED] Expired keys strictly rejected upon cutoff</div>
    `;
    await Promise.all([refreshClusterNodes(), loadInitialStatus()]);
  } catch (e) {
    logEl.innerHTML = `<div class="terminal-line fail">[ERROR] Key rotation failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function runLostDeviceDemo() {
  const logEl = document.getElementById('lost-device-terminal');
  logEl.innerHTML = `<div class="terminal-line info">[RUNNING] 11-Step Lost-Device Resilience Demonstration...</div>`;
  try {
    const data = await apiFetch('/demo/lost-device', { method: 'POST' });
    logEl.innerHTML = `<div class="terminal-line info">===============================================================</div>`;
    data.steps.forEach(s => {
      const cls = ['allow', 'revoked', 'recovered', 'verified', 'reported', 'probed', 'enrolled'].includes(s.outcome)
        ? 'pass' : (s.outcome === 'deny' ? 'warn' : 'fail');
      logEl.innerHTML += `<div class="terminal-line ${cls}">Step ${String(s.step).padStart(2, '0')}: [${escapeHtml(s.action.toUpperCase())}] → ${escapeHtml(s.outcome)} (${escapeHtml(s.detail)})</div>`;
    });
    logEl.innerHTML += `<div class="terminal-line pass">===============================================================</div>`;
    logEl.innerHTML += `<div class="terminal-line pass">COMPLETED: Fail-closed revocation &amp; recovery verified in ${escapeHtml(data.revocation_latency_ms)}ms.</div>`;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Lost device demo failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function loadDevices() {
  try {
    const devices = await apiFetch('/iam/devices');
    const tbody = document.getElementById('devices-table-body');
    tbody.innerHTML = '';
    devices.forEach(d => {
      const tr = document.createElement('tr');
      const pillCls = d.status === 'active' ? 'routine' : 'suspicious';
      tr.innerHTML = `
        <td><strong>${escapeHtml(d.device_id)}</strong></td>
        <td>${escapeHtml(d.owner)}</td>
        <td><span class="badge-pill ${pillCls}">${escapeHtml(d.status.toUpperCase())}</span></td>
        <td>${escapeHtml(d.algorithm)}</td>
        <td><code>${escapeHtml(d.public_key_preview)}</code></td>
        <td>
          ${d.status === 'active'
            ? `<button class="btn-danger" style="padding:2px 8px;font-size:10px" data-revoke-dev="${escapeHtml(d.device_id)}">REVOKE</button>`
            : '<span style="color:var(--text-dim)">Revoked</span>'}
        </td>
      `;
      const btn = tr.querySelector('[data-revoke-dev]');
      if (btn) {
        btn.addEventListener('click', () => revokeDevice(d.device_id));
      }
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error('Failed to load devices:', e);
  }
}

async function revokeDevice(deviceId) {
  try {
    await apiFetch(`/iam/revoke-device?device_id=${encodeURIComponent(deviceId)}`, { method: 'POST' });
    await Promise.all([loadDevices(), refreshClusterNodes(), loadInitialStatus()]);
  } catch (e) {
    console.error('Failed to revoke device:', e);
  }
}

async function loadIntegrityStatus() {
  try {
    const d = await apiFetch('/integrity/status');
    const chainEl = document.getElementById('integ-audit-chain');
    chainEl.innerText = d.audit_chain_verified ? 'VERIFIED (IMMUTABLE)' : 'TAMPER DETECTED';
    chainEl.style.color = d.audit_chain_verified ? 'var(--emerald-success)' : 'var(--crimson-alert)';
    document.getElementById('integ-total-events').innerText = `${d.total_audit_events} Events`;
    document.getElementById('integ-checkpoint').innerText = d.external_checkpoint_valid
      ? `SEQ ${d.last_checkpoint_epoch} VALID` : 'INVALID';
    document.getElementById('integ-backup-digest').innerText = d.last_backup_digest;
  } catch (e) {
    console.error('Failed to load integrity status:', e);
  }
}

async function verifyIntegrityNow() {
  try {
    const d = await apiFetch('/integrity/verify', { method: 'POST' });
    document.getElementById('integ-audit-chain').innerText = d.audit_chain_verified ? 'VERIFIED (IMMUTABLE)' : 'TAMPER DETECTED';
    document.getElementById('integ-total-events').innerText = `${d.total_audit_events} Events`;
    document.getElementById('integ-checkpoint').innerText = d.external_checkpoint_valid
      ? `SEQ ${d.last_checkpoint_epoch} VALID` : 'INVALID';
    document.getElementById('integ-backup-digest').innerText = d.last_backup_digest;
    await loadInitialStatus();
  } catch (e) {
    console.error('Verification failed:', e);
  }
}

// ==============================================================================
// TAB 2: THREAT RADAR
// ==============================================================================
async function loadThreatRadarTab() {
  await Promise.all([
    loadThreatOverview(),
    loadPracticeEvents(),
    renderServiceGraph(),
    loadIncidents(),
    loadDetectionMetrics(),
    loadEvaluationComparison(),
  ]);
}

async function loadEvaluationComparison() {
  const tbody = document.getElementById('eval-comparison-body');
  if (!tbody) return;
  try {
    const res = await apiFetch('/detection/evaluation-comparison');
    tbody.innerHTML = '';
    [res.practice, res.held_out_synthetic].forEach(row => {
      if (!row) return;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${escapeHtml(row.dataset_name)}</strong></td>
        <td>${escapeHtml(row.total_events)}</td>
        <td style="color:var(--emerald-success); font-weight:700">${escapeHtml((row.exact_accuracy * 100).toFixed(2))}%</td>
        <td>${escapeHtml(row.precision.toFixed(4))}</td>
        <td>${escapeHtml(row.recall.toFixed(4))}</td>
        <td><strong>${escapeHtml(row.f1_score.toFixed(4))}</strong></td>
        <td>${escapeHtml(row.false_positives)} / ${escapeHtml(row.false_negatives)}</td>
        <td>${escapeHtml(Math.round(row.throughput_events_per_sec))} evt/s</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" style="color:var(--crimson-alert)">Failed to load generalization comparison: ${escapeHtml(e.message)}</td></tr>`;
  }
}

async function loadThreatOverview() {
  try {
    const d = await apiFetch('/detection/overview');
    document.getElementById('radar-events-count').innerText = d.events_processed;
    document.getElementById('radar-routine-count').innerText = d.routine_events;
    document.getElementById('radar-suspicious-count').innerText = d.suspicious_events;
    document.getElementById('radar-incidents-count').innerText = `${d.active_incidents} Active`;
    document.getElementById('radar-offset-count').innerText = d.clock_offset_events;
  } catch (e) {
    console.error('Failed to load threat overview:', e);
  }
}

async function loadPracticeEvents() {
  try {
    const evalMode = document.getElementById('toggle-eval-mode').checked;
    appState.events = await apiFetch(`/detection/practice-events?evaluation_mode=${evalMode}`);
    populateEventFilters(appState.events);
    applyEventFilters();
  } catch (e) {
    console.error('Failed to load practice events:', e);
  }
}

function populateEventFilters(events) {
  const actorSel = document.getElementById('filter-actor');
  const classSel = document.getElementById('filter-class');
  const prevActor = actorSel.value;
  const prevClass = classSel.value;

  const actors = [...new Set(events.map(e => e.actor))].sort();
  const classes = [...new Set(events.map(e => e.predicted_label))].sort();

  actorSel.innerHTML = '<option value="">All Actors</option>';
  actors.forEach(a => {
    const o = document.createElement('option');
    o.value = a;
    o.textContent = a;
    actorSel.appendChild(o);
  });
  actorSel.value = prevActor;

  classSel.innerHTML = '<option value="">All Classifications</option>';
  classes.forEach(c => {
    const o = document.createElement('option');
    o.value = c;
    o.textContent = c;
    classSel.appendChild(o);
  });
  classSel.value = prevClass;
}

function applyEventFilters() {
  const actor = document.getElementById('filter-actor').value;
  const cls = document.getElementById('filter-class').value;
  appState.filteredEvents = appState.events.filter(ev =>
    (!actor || ev.actor === actor) && (!cls || ev.predicted_label === cls)
  );
  renderEventsTable();
}

function renderEventsTable() {
  const tbody = document.getElementById('events-table-body');
  tbody.innerHTML = '';
  const list = appState.filteredEvents;

  list.forEach((ev, idx) => {
    const isSuspicious = ['unexpected_role_change', 'lateral_movement_candidate', 'review_after_role_change'].includes(ev.predicted_label);
    const tr = document.createElement('tr');
    tr.id = `evt-row-${ev.event_id}`;
    if (idx === appState.currentEventIndex && appState.isPlayingEvents) {
      tr.style.backgroundColor = 'rgba(0, 229, 255, 0.15)';
    }
    const badgeClass = isSuspicious ? 'suspicious' : (ev.predicted_label === 'approved_change' ? 'warning' : 'routine');
    const rawTime = ev.event_time_utc.includes('T') ? ev.event_time_utc.split('T')[1].replace('Z', '') : ev.event_time_utc;
    const corrTime = ev.corrected_time_utc.includes('T') ? ev.corrected_time_utc.split('T')[1].replace('Z', '') : ev.corrected_time_utc;
    const timeStr = rawTime === corrTime ? corrTime : `${rawTime} → ${corrTime}`;

    tr.innerHTML = `
      <td><strong>${escapeHtml(ev.event_id)}</strong></td>
      <td><code>${escapeHtml(timeStr)}</code></td>
      <td>${escapeHtml(ev.actor)}</td>
      <td><code>${escapeHtml(ev.source_service)} → ${escapeHtml(ev.target_service)}</code></td>
      <td>${escapeHtml(ev.action)}</td>
      <td><span style="color:${ev.outcome === 'allow' || ev.outcome === 'success' ? 'var(--emerald-success)' : 'var(--crimson-alert)'}">${escapeHtml(ev.outcome.toUpperCase())}</span></td>
      <td><span class="badge-pill ${badgeClass}">${escapeHtml(ev.predicted_label)}</span></td>
      <td><small style="color:var(--text-dim)">${escapeHtml(ev.ground_truth_label || 'hidden')}</small></td>
      <td><small style="color:var(--text-muted)">${escapeHtml(ev.reason)}</small></td>
    `;
    tbody.appendChild(tr);
  });
}

function playPracticeEvents() {
  if (appState.isPlayingEvents) return;
  appState.isPlayingEvents = true;
  document.getElementById('btn-play-events').innerText = 'PAUSE';
  appState.playInterval = setInterval(() => {
    if (appState.currentEventIndex >= appState.events.length) {
      pausePracticeEvents();
      appState.currentEventIndex = 0;
      return;
    }
    stepNextEvent();
  }, 850);
}

function pausePracticeEvents() {
  appState.isPlayingEvents = false;
  document.getElementById('btn-play-events').innerText = 'PLAY';
  if (appState.playInterval) clearInterval(appState.playInterval);
}

function togglePracticePlayback() {
  if (appState.isPlayingEvents) pausePracticeEvents();
  else playPracticeEvents();
}

function stepNextEvent() {
  if (appState.events.length === 0) return;
  const ev = appState.events[appState.currentEventIndex];
  renderEventsTable();
  const row = document.getElementById(`evt-row-${ev.event_id}`);
  if (row) row.scrollIntoView({ behavior: 'smooth', block: 'center' });

  const term = document.getElementById('threat-playback-terminal');
  const isSusp = ['unexpected_role_change', 'lateral_movement_candidate', 'review_after_role_change'].includes(ev.predicted_label);
  const colorClass = isSusp ? 'fail' : (ev.predicted_label === 'approved_change' ? 'warn' : 'pass');

  term.innerHTML += `
    <div class="terminal-line ${colorClass}">
      [${escapeHtml(ev.event_id)}] ${escapeHtml(ev.actor)} | ${escapeHtml(ev.source_service)} → ${escapeHtml(ev.target_service)} | ${escapeHtml(ev.action)} (${escapeHtml(ev.outcome)}) | Class: ${escapeHtml(ev.predicted_label)} — ${escapeHtml(ev.reason)}
    </div>
  `;
  term.scrollTop = term.scrollHeight;
  appState.currentEventIndex++;
  if (appState.currentEventIndex >= appState.events.length) pausePracticeEvents();
}

function resetPracticeEvents() {
  pausePracticeEvents();
  appState.currentEventIndex = 0;
  document.getElementById('threat-playback-terminal').innerHTML =
    '<div class="terminal-line info">[READY] Playback reset. Press PLAY or STEP NEXT to evaluate.</div>';
  renderEventsTable();
}

async function renderServiceGraph() {
  try {
    const graph = await apiFetch('/detection/service-graph');
    const svg = document.getElementById('service-graph-svg');
    svg.innerHTML = '';

    const coords = {
      'identity': { x: 95, y: 180 },
      'admin-console': { x: 95, y: 70 },
      'portal': { x: 255, y: 100 },
      'catalog': { x: 435, y: 100 },
      'reports': { x: 255, y: 260 },
      'reports-node-a': { x: 140, y: 310 },
      'reports-node-b': { x: 350, y: 310 },
      'billing': { x: 435, y: 260 },
      'archive': { x: 590, y: 260 },
    };

    svg.innerHTML += `
      <defs>
        <marker id="arrow-normal" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#00e5ff" />
        </marker>
        <marker id="arrow-alert" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
        </marker>
      </defs>
    `;

    graph.edges.forEach(e => {
      const src = coords[e.source];
      const dst = coords[e.target];
      if (!src || !dst) return;
      const isSusp = e.status === 'suspicious_attempted';
      const strokeColor = isSusp ? '#ef4444' : (e.status === 'denied' ? '#f59e0b' : '#00e5ff');
      const marker = isSusp ? 'url(#arrow-alert)' : 'url(#arrow-normal)';
      const dash = isSusp ? 'stroke-dasharray="6,4"' : '';

      svg.innerHTML += `
        <line x1="${src.x}" y1="${src.y}" x2="${dst.x}" y2="${dst.y}"
              stroke="${strokeColor}" stroke-width="${isSusp ? '3' : '1.5'}"
              ${dash} marker-end="${marker}">
          <title>${escapeHtml(e.source)} → ${escapeHtml(e.target)} (${escapeHtml(e.status)})</title>
        </line>
      `;
    });

    graph.nodes.forEach(n => {
      const pos = coords[n.id];
      if (!pos) return;
      svg.innerHTML += `
        <g transform="translate(${pos.x}, ${pos.y})">
          <circle r="24" fill="#131b2e" stroke="#00e5ff" stroke-width="2" />
          <text text-anchor="middle" dy="4" fill="#fff" font-size="9" font-weight="700" font-family="var(--font-mono)">${escapeHtml(n.label)}</text>
        </g>
      `;
    });
  } catch (e) {
    console.error('Failed to render service graph:', e);
  }
}

async function loadIncidents() {
  try {
    const incidents = await apiFetch('/detection/incidents');
    const container = document.getElementById('incidents-list-container');
    container.innerHTML = '';

    incidents.forEach(inc => {
      const card = document.createElement('div');
      card.className = 'soc-card glow-cyan';
      card.style.marginBottom = '12px';
      card.style.cursor = 'pointer';
      card.addEventListener('click', () => openIncidentModal(inc));

      card.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong style="color:var(--crimson-alert)">[${escapeHtml(inc.severity.toUpperCase())}] ${escapeHtml(inc.rule_id)}</strong>:
            <span style="color:#fff">${escapeHtml(inc.incident_type.replace(/_/g, ' ').toUpperCase())}</span>
          </div>
          <span class="badge-pill suspicious">${escapeHtml(inc.incident_id)}</span>
        </div>
        <p style="font-size:12px; color:var(--text-muted); margin-top:6px;">${escapeHtml(inc.explanation)}</p>
        <div style="font-size:11px; color:var(--text-dim); margin-top:4px;">
          Affected Identity: <code>${escapeHtml(inc.actor_id)}</code> | Evidence: <code>${escapeHtml(inc.evidence_event_ids.join(', '))}</code>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (e) {
    console.error('Failed to load incidents:', e);
  }
}

function openIncidentModal(inc) {
  document.getElementById('incident-modal-title').innerText = `${inc.incident_id} — ${inc.rule_id}`;
  document.getElementById('incident-modal-body').innerHTML = `
    <div style="display:flex; flex-direction:column; gap:12px; font-size:13px;">
      <div><strong>Incident Type:</strong> ${escapeHtml(inc.incident_type)}</div>
      <div><strong>Severity:</strong> <span style="color:var(--crimson-alert); font-weight:700;">${escapeHtml(inc.severity.toUpperCase())}</span></div>
      <div><strong>Target Identity:</strong> <code>${escapeHtml(inc.actor_id)}</code></div>
      <div><strong>Triggered Rule:</strong> ${escapeHtml(inc.rule_id)} (Deterministic, 0% AI/ML)</div>
      <div><strong>Evidence Events:</strong> <code>${escapeHtml(inc.evidence_event_ids.join(', '))}</code></div>
      <div><strong>Root Cause Explanation:</strong> ${escapeHtml(inc.explanation)}</div>
      <div style="background-color:rgba(0, 229, 255, 0.08); padding:10px; border-radius:6px; border:1px solid var(--border-color);">
        <strong style="color:var(--cyan-primary)">Recommended Operator Response:</strong><br/>
        ${escapeHtml(inc.recommended_action)}
      </div>
    </div>
  `;
  document.getElementById('incident-modal').classList.add('active');
}

function closeIncidentModal() {
  document.getElementById('incident-modal').classList.remove('active');
}

async function loadDetectionMetrics() {
  try {
    const m = await apiFetch('/detection/metrics');
    document.getElementById('metric-f1').innerText = m.f1_score.toFixed(3);
    document.getElementById('metric-precision').innerText = m.precision.toFixed(3);
    document.getElementById('metric-recall').innerText = m.recall.toFixed(3);
    document.getElementById('metric-accuracy').innerText = `Exact Accuracy: ${(m.exact_accuracy * 100).toFixed(1)}% (${m.total_events} events)`;
    document.getElementById('metric-latency').innerText = `${m.median_alert_latency_us} µs`;
    document.getElementById('metric-false-alerts').innerText = `${m.false_alerts_per_1000_benign}/1k`;
    document.getElementById('metric-throughput').innerText = `${Math.round(m.throughput_events_per_sec)} evt/s`;

    const cmBody = document.getElementById('confusion-matrix-body');
    cmBody.innerHTML = '';
    Object.entries(m.confusion_matrix || {}).forEach(([pair, count]) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><code>${escapeHtml(pair)}</code></td><td><strong>${escapeHtml(count)}</strong></td>`;
      cmBody.appendChild(tr);
    });
  } catch (e) {
    console.error('Failed to load detection metrics:', e);
  }
}

// ==============================================================================
// TAB 3: POST-QUANTUM MESSAGING
// ==============================================================================
function loadPQMessagingTab() {}

async function performPqcHandshake() {
  const logEl = document.getElementById('messaging-log-terminal');
  logEl.innerHTML = `<div class="terminal-line info">[INITIATING] Performing NIST ML-KEM-768 Ephemeral Handshake between Alice and Bob...</div>`;
  try {
    const d = await apiFetch('/messaging/demo-handshake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ initiator: 'alice', responder: 'bob' }),
    });
    logEl.innerHTML += `<div class="terminal-line pass">[ESTABLISHED] Session ID: ${escapeHtml(d.session_id)} (${escapeHtml(d.handshake_duration_ms)}ms)</div>`;
    d.stages.forEach(s => {
      logEl.innerHTML += `<div class="terminal-line pass">  Stage ${escapeHtml(s.stage)}: [${escapeHtml(s.name)}] by ${escapeHtml(s.actor.toUpperCase())} → ${escapeHtml(s.detail)}</div>`;
    });
    logEl.innerHTML += `<div class="terminal-line info">[KEM PUBLIC KEY] ${escapeHtml(d.ephemeral_kem_pk_preview)}</div>`;
    logEl.innerHTML += `<div class="terminal-line info">[CIPHERTEXT] ${escapeHtml(d.ciphertext_preview)}</div>`;
    logEl.innerHTML += `<div class="terminal-line pass">[EPHEMERAL BUFFER ZEROIZED] ${escapeHtml(d.ephemeral_keys_zeroized)}</div>`;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Handshake failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function sendEncryptedMessage() {
  const plaintext = document.getElementById('msg-plaintext-input').value || 'Top Secret Operational Brief';
  const logEl = document.getElementById('messaging-log-terminal');
  logEl.innerHTML += `<div class="terminal-line info">[SENDING] Encrypting message under AES-256-GCM with recipient AAD...</div>`;
  try {
    const d = await apiFetch('/messaging/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender: 'alice', recipient: 'bob', plaintext }),
    });
    logEl.innerHTML += `
      <div class="terminal-line pass">[DELIVERED] Message ID: ${escapeHtml(d.message_id)} | Seq #${escapeHtml(d.sequence_number)}</div>
      <div class="terminal-line info">[CIPHERTEXT PREVIEW] ${escapeHtml(d.ciphertext_preview)}</div>
      <div class="terminal-line pass">[DECRYPTED AT BOB] "${escapeHtml(d.plaintext_revealed_to_recipient)}"</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Message send failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function testReplayProtection() {
  const logEl = document.getElementById('messaging-log-terminal');
  try {
    const d = await apiFetch('/messaging/test-replay', { method: 'POST' });
    logEl.innerHTML += `
      <div class="terminal-line pass">[OUTCOME] ${escapeHtml(d.outcome)}</div>
      <div class="terminal-line info">[FILTER LATENCY] Checked sliding window in ${escapeHtml(d.check_latency_us)} µs</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Replay test failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function testRecipientTampering() {
  const logEl = document.getElementById('messaging-log-terminal');
  try {
    const d = await apiFetch('/messaging/test-tamper-recipient', { method: 'POST' });
    logEl.innerHTML += `
      <div class="terminal-line pass">[STATUS] ${escapeHtml(d.status)}</div>
      <div class="terminal-line pass">[ENFORCEMENT] ${escapeHtml(d.error)}</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Tamper test failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function testCiphertextTampering() {
  const logEl = document.getElementById('messaging-log-terminal');
  try {
    const d = await apiFetch('/messaging/test-tamper-ciphertext', { method: 'POST' });
    logEl.innerHTML += `
      <div class="terminal-line pass">[STATUS] ${escapeHtml(d.status)} (decrypted=${escapeHtml(d.ciphertext_decrypted)})</div>
      <div class="terminal-line pass">[ENFORCEMENT] ${escapeHtml(d.error)}</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Ciphertext tamper test failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function testRevokedDeviceMessaging() {
  const logEl = document.getElementById('messaging-log-terminal');
  try {
    const d = await apiFetch('/messaging/test-revoked-device', { method: 'POST' });
    logEl.innerHTML += `
      <div class="terminal-line pass">[STATUS] ${escapeHtml(d.status)} (dispatch_blocked=${escapeHtml(d.dispatch_blocked)})</div>
      <div class="terminal-line pass">[OUTCOME] ${escapeHtml(d.outcome)}</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Revoked device test failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function testForwardSecrecy() {
  const logEl = document.getElementById('messaging-log-terminal');
  try {
    const d = await apiFetch('/messaging/test-forward-secrecy', { method: 'POST' });
    logEl.innerHTML += `
      <div class="terminal-line pass">[PROOF RESULT] Forward Secrecy Preserved: ${d.forward_secrecy_preserved ? 'TRUE' : 'FALSE'}</div>
      <div class="terminal-line pass">[TRANSCRIPT DECRYPTED] ${d.captured_transcript_decrypted ? 'YES' : 'NO (Cryptographically Infeasible)'}</div>
      <div class="terminal-line info">[REASONING] ${escapeHtml(d.cryptographic_reasoning)}</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Forward secrecy test failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function testTransportFault(faultType) {
  const logEl = document.getElementById('messaging-log-terminal');
  try {
    const d = await apiFetch(`/messaging/test-transport-fault?fault_type=${encodeURIComponent(faultType)}`, { method: 'POST' });
    logEl.innerHTML += `
      <div class="terminal-line pass">[STATUS] ${escapeHtml(d.status)}</div>
      <div class="terminal-line info">${escapeHtml(d.action || `Reassembled ${d.bytes_recovered} bytes from out-of-order chunks.`)}</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Transport test failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function testOfflineOutbox() {
  const logEl = document.getElementById('messaging-log-terminal');
  try {
    const d = await apiFetch('/messaging/test-offline-outbox', { method: 'POST' });
    logEl.innerHTML += `
      <div class="terminal-line pass">[STATUS] ${escapeHtml(d.status)}</div>
      <div class="terminal-line pass">[ENFORCEMENT] ${escapeHtml(d.outcome)}</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Outbox test failed: ${escapeHtml(e.message)}</div>`;
  }
}

// ==============================================================================
// TAB 4: SECURITY LABORATORY
// ==============================================================================
async function loadSecurityLabTab() {
  await Promise.all([loadLabScenarios(), loadEvidenceFiles(), loadBenchmarkSummary()]);
}

async function loadBenchmarkSummary() {
  const tbody = document.getElementById('benchmark-summary-table-body');
  const srcEl = document.getElementById('benchmark-source-label');
  if (!tbody) return;
  try {
    const res = await apiFetch('/benchmarks/summary');
    if (srcEl) srcEl.innerText = res.available ? res.source : 'UNAVAILABLE';
    const bms = (res.data && res.data.benchmarks) ? res.data.benchmarks : {};
    const entries = Object.entries(bms).filter(([, vals]) => vals && typeof vals === 'object' && vals.median_ms !== undefined);
    if (!entries.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--text-dim)">No benchmark records on disk yet.</td></tr>';
      return;
    }
    tbody.innerHTML = '';
    entries.forEach(([name, vals]) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${escapeHtml(name)}</code></td>
        <td>${escapeHtml(vals.samples)}</td>
        <td style="color:var(--cyan-primary); font-weight:700">${escapeHtml(vals.median_ms)}</td>
        <td>${escapeHtml(vals.p95_ms)}</td>
        <td>${escapeHtml(vals.max_ms)}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    if (srcEl) srcEl.innerText = 'ERROR';
    tbody.innerHTML = `<tr><td colspan="5" style="color:var(--crimson-alert)">${escapeHtml(e.message)}</td></tr>`;
  }
}

async function loadLabScenarios() {
  try {
    appState.scenarios = await apiFetch('/lab/scenarios');
    renderScenariosList(appState.scenarios);
  } catch (e) {
    console.error('Failed to load lab scenarios:', e);
  }
}

function renderScenariosList(scenarios) {
  const container = document.getElementById('scenarios-list-container');
  container.innerHTML = '';

  scenarios.forEach(s => {
    const row = document.createElement('div');
    row.className = 'soc-card';
    row.style.marginBottom = '8px';
    row.style.padding = '12px 16px';
    row.style.display = 'flex';
    row.style.justifyContent = 'space-between';
    row.style.alignItems = 'center';

    row.innerHTML = `
      <div>
        <div style="font-weight:700; color:#fff; display:flex; align-items:center; gap:8px;">
          <span id="badge-${escapeHtml(s.name)}" class="badge-pill routine" style="font-size:9px;">READY</span>
          ${escapeHtml(s.name)}
          <span style="font-size:10px; color:var(--text-dim)">(${escapeHtml(s.category)})</span>
        </div>
        <p style="font-size:11px; color:var(--text-muted); margin-top:2px;">${escapeHtml(s.description)}</p>
      </div>
      <div style="display:flex; align-items:center; gap:12px;">
        <span id="duration-${escapeHtml(s.name)}" style="font-family:var(--font-mono); font-size:11px; color:var(--text-dim)">--</span>
        <button class="btn-secondary" style="padding:4px 10px; font-size:11px;" data-run-sc="${escapeHtml(s.name)}">RUN</button>
      </div>
    `;
    row.querySelector('[data-run-sc]').addEventListener('click', () => runIndividualScenario(s.name));
    container.appendChild(row);
  });
}

function filterScenarios(category) {
  if (category === 'all') {
    renderScenariosList(appState.scenarios);
  } else {
    renderScenariosList(
      appState.scenarios.filter(s => s.category.toLowerCase().includes(category.toLowerCase()))
    );
  }
}

async function runIndividualScenario(name) {
  const badge = document.getElementById(`badge-${name}`);
  const duration = document.getElementById(`duration-${name}`);
  if (badge) {
    badge.innerText = 'RUNNING';
    badge.className = 'badge-pill warning';
  }
  try {
    const d = await apiFetch(`/lab/run?name=${encodeURIComponent(name)}`, { method: 'POST' });
    if (badge) {
      badge.innerText = d.passed ? 'PASS' : 'FAIL';
      badge.className = `badge-pill ${d.passed ? 'routine' : 'suspicious'}`;
    }
    if (duration) duration.innerText = `${d.duration_ms}ms`;
  } catch (e) {
    if (badge) {
      badge.innerText = 'ERROR';
      badge.className = 'badge-pill suspicious';
    }
  }
}

async function runAllScenarios() {
  const progBar = document.getElementById('lab-progress-bar');
  const progText = document.getElementById('lab-progress-text');
  progText.innerText = 'Executing 40 Scenarios...';
  progBar.style.width = '20%';
  try {
    const d = await apiFetch('/lab/run-all', { method: 'POST' });
    progBar.style.width = '100%';
    progText.innerText = `COMPLETED: ${d.total_passed}/${d.total_scenarios} PASSED (${d.all_passed ? '100% SUCCESS' : 'FAILURES DETECTED'})`;

    d.results.forEach(r => {
      const badge = document.getElementById(`badge-${r.name}`);
      const duration = document.getElementById(`duration-${r.name}`);
      if (badge) {
        badge.innerText = r.passed ? 'PASS' : 'FAIL';
        badge.className = `badge-pill ${r.passed ? 'routine' : 'suspicious'}`;
      }
      if (duration) duration.innerText = `${r.duration_ms}ms`;
    });
  } catch (e) {
    progText.innerText = `Error executing test lab: ${e.message}`;
  }
}

async function runCombinedResilienceScenario() {
  const logEl = document.getElementById('combined-demo-terminal');
  logEl.innerHTML = `<div class="terminal-line info">[RUNNING] 40-Step Combined Security Resilience Demonstration...</div>`;
  try {
    const d = await apiFetch('/lab/run-combined', { method: 'POST' });
    logEl.innerHTML = `<div class="terminal-line info">===============================================================</div>`;
    d.steps.forEach(s => {
      const colorClass = s.status === 'PASS' ? 'pass' : 'fail';
      logEl.innerHTML += `<div class="terminal-line ${colorClass}">Step ${String(s.step).padStart(2, '0')}: [${escapeHtml(s.status)}] ${escapeHtml(s.title)}</div>`;
    });
    logEl.innerHTML += `<div class="terminal-line pass">===============================================================</div>`;
    logEl.innerHTML += `<div class="terminal-line pass">COMBINED SCENARIO: ${escapeHtml(d.steps_passed)}/${escapeHtml(d.total_steps)} steps passed in ${escapeHtml(d.execution_time_ms)}ms.</div>`;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Combined scenario failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function loadEvidenceFiles() {
  try {
    const d = await apiFetch('/lab/evidence/list');
    const select = document.getElementById('evidence-file-select');
    select.innerHTML = '<option value="">-- Select Evidence File --</option>';
    d.files.forEach(f => {
      const opt = document.createElement('option');
      opt.value = f.path;
      opt.textContent = `${f.path} (${f.size_bytes} bytes)`;
      select.appendChild(opt);
    });
  } catch (e) {
    console.error('Failed to load evidence files:', e);
  }
}

async function viewSelectedEvidence() {
  const select = document.getElementById('evidence-file-select');
  const filePath = select.value;
  if (!filePath) return;
  const viewer = document.getElementById('evidence-content-viewer');
  viewer.innerText = 'Loading evidence file...';
  try {
    const d = await apiFetch(`/lab/evidence/view?file_path=${encodeURIComponent(filePath)}`);
    viewer.innerText = d.content;
  } catch (e) {
    viewer.innerText = `Error loading evidence: ${e.message}`;
  }
}

// ==============================================================================
// TAB 5: DEDICATED 15-STEP JUDGE DEMO MODE
// ==============================================================================
async function loadJudgeDemoTab() {
  try {
    const st = await apiFetch('/judge-demo/status');
    appState.demoStatus = st;
    renderJudgeDemoUI(st);
  } catch (e) {
    console.error('Failed to load judge demo status:', e);
  }
}

function renderJudgeDemoUI(st) {
  const catalogEl = document.getElementById('demo-steps-catalog');
  catalogEl.innerHTML = '';

  const completedMap = {};
  (st.completed_steps || []).forEach(cs => { completedMap[cs.step] = cs; });

  (st.step_catalog || []).forEach(item => {
    const done = completedMap[item.step];
    const row = document.createElement('div');
    row.className = 'soc-card';
    row.style.padding = '10px 14px';
    row.style.cursor = 'pointer';
    const badgeCls = done ? (done.status === 'PASS' ? 'routine' : 'suspicious') : 'warning';
    const badgeText = done ? `${done.status} (${done.duration_ms}ms)` : 'PENDING';
    row.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <strong style="font-size:12px;">Step ${escapeHtml(item.step)}: ${escapeHtml(item.title)}</strong>
        <span class="badge-pill ${badgeCls}">${escapeHtml(badgeText)}</span>
      </div>
      <div style="font-size:11px; color:var(--text-dim); margin-top:2px;">${escapeHtml(item.objective)}</div>
    `;
    row.addEventListener('click', () => inspectDemoStep(item.step));
    catalogEl.appendChild(row);
  });

  const pct = Math.round(((st.current_step || 0) / (st.total_steps || 15)) * 100);
  document.getElementById('demo-progress-bar').style.width = `${pct}%`;
  document.getElementById('demo-progress-text').innerText =
    `Step ${st.current_step || 0} / ${st.total_steps || 15} — ${st.active ? 'ISOLATED SESSION ACTIVE' : 'IDLE'}`;

  const statusBadge = document.getElementById('demo-status-badge');
  statusBadge.innerText = st.active ? `STEP ${st.current_step}/15` : 'IDLE';
}

function inspectDemoStep(stepNum) {
  const st = appState.demoStatus;
  if (!st) return;
  appState.demoViewIndex = stepNum;
  const meta = (st.step_catalog || []).find(s => s.step === stepNum);
  const done = (st.completed_steps || []).find(s => s.step === stepNum);
  if (!meta) return;

  document.getElementById('demo-inspected-step').innerText = `STEP ${stepNum} / 15`;
  document.getElementById('demo-explanation-box').innerHTML = `
    <strong>${escapeHtml(meta.title)}</strong> (${escapeHtml(meta.objective)})<br/>
    <span style="color:var(--text-muted)">${escapeHtml(meta.explanation)}</span><br/>
    <div style="margin-top:6px; font-size:11px; color:var(--cyan-primary);"><strong>Expected:</strong> ${escapeHtml(meta.expected || '')}</div>
    ${done ? `<div style="margin-top:3px; font-size:11px; color:${done.status === 'PASS' ? 'var(--emerald-success)' : 'var(--crimson-alert)'};"><strong>Actual (${escapeHtml(done.duration_ms)}ms):</strong> ${escapeHtml(done.actual_outcome || '')}</div>` : ''}
  `;

  if (done) {
    const term = document.getElementById('demo-execution-terminal');
    term.innerHTML = `
      <div class="terminal-line ${done.status === 'PASS' ? 'pass' : 'fail'}">[STEP ${escapeHtml(done.step)}] ${escapeHtml(done.title)} → ${escapeHtml(done.status)} (${escapeHtml(done.duration_ms)}ms)</div>
      <pre style="color:#cbd5e1; margin-top:8px; white-space:pre-wrap;">${escapeHtml(JSON.stringify(done.result, null, 2))}</pre>
    `;
  }
}

async function startJudgeDemo() {
  const term = document.getElementById('demo-execution-terminal');
  term.innerHTML = '<div class="terminal-line info">[STARTING] Initializing isolated temporary environment for 15-Step Judge Demo...</div>';
  try {
    const st = await apiFetch('/judge-demo/start', { method: 'POST' });
    appState.demoStatus = st;
    appState.demoViewIndex = 1;
    renderJudgeDemoUI(st);
    inspectDemoStep(1);
    term.innerHTML += '<div class="terminal-line pass">[READY] Isolated demo environment active. Click NEXT STEP to execute Step 1.</div>';
  } catch (e) {
    term.innerHTML += `<div class="terminal-line fail">[ERROR] ${escapeHtml(e.message)}</div>`;
  }
}

async function nextJudgeDemoStep() {
  const term = document.getElementById('demo-execution-terminal');
  try {
    const stepRes = await apiFetch('/judge-demo/next', { method: 'POST' });
    const st = await apiFetch('/judge-demo/status');
    appState.demoStatus = st;
    appState.demoViewIndex = stepRes.step;
    renderJudgeDemoUI(st);
    inspectDemoStep(stepRes.step);
  } catch (e) {
    term.innerHTML += `<div class="terminal-line warn">[INFO] ${escapeHtml(e.message)}</div>`;
  }
}

function prevJudgeExplanation() {
  const target = Math.max(1, (appState.demoViewIndex || 1) - 1);
  inspectDemoStep(target);
}

async function resetJudgeDemo() {
  const term = document.getElementById('demo-execution-terminal');
  try {
    const st = await apiFetch('/judge-demo/reset', { method: 'POST' });
    appState.demoStatus = st;
    appState.demoViewIndex = 0;
    renderJudgeDemoUI(st);
    document.getElementById('demo-inspected-step').innerText = 'RESET';
    document.getElementById('demo-explanation-box').innerText = 'Demo environment cleanly wiped and reset.';
    term.innerHTML = '<div class="terminal-line info">[RESET] Isolated demo directory cleaned up.</div>';
  } catch (e) {
    term.innerHTML += `<div class="terminal-line fail">[ERROR] ${escapeHtml(e.message)}</div>`;
  }
}

/* ===================================================================== */
/* TAB 4: ADVERSARIAL SCRIPT INJECTOR & TEST HARNESS                     */
/* ===================================================================== */

async function loadInjectorTab() {
  const editor = document.getElementById('injector-code-editor');
  if (!editor) return;

  // Support Tab key in editor
  editor.addEventListener('keydown', (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = editor.selectionStart;
      const end = editor.selectionEnd;
      editor.value = editor.value.substring(0, start) + '    ' + editor.value.substring(end);
      editor.selectionStart = editor.selectionEnd = start + 4;
      updateScriptMeta();
    }
  });

  editor.addEventListener('input', updateScriptMeta);

  try {
    const data = await apiFetch('/injector/presets');
    appState.injectorPresets = data.presets || [];
    loadInjectorPreset('v6');
  } catch (err) {
    appendInjectorLog(`[ERROR] Failed to fetch challenge presets: ${err.message}`, 'fail');
  }
}

function updateScriptMeta() {
  const editor = document.getElementById('injector-code-editor');
  const meta = document.getElementById('injector-script-meta');
  if (!editor || !meta) return;
  const lines = editor.value.split('\n').length;
  const chars = editor.value.length;
  const kb = (chars / 1024).toFixed(1);
  meta.innerText = `${lines} lines | ${kb} KB`;
}

function loadInjectorPreset(presetId) {
  appState.currentPresetId = presetId;
  document.querySelectorAll('.btn-preset').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.preset === presetId);
  });

  const preset = (appState.injectorPresets || []).find(p => p.id === presetId);
  const editor = document.getElementById('injector-code-editor');
  const title = document.getElementById('injector-script-title');
  if (!editor || !preset) return;

  editor.value = preset.script_content || '';
  if (title) title.innerText = preset.name.toUpperCase();
  updateScriptMeta();

  // Update default rounds/seed
  if (presetId === 'extreme') {
    document.getElementById('injector-rounds-input').value = 8;
  } else if (presetId === 'normal') {
    document.getElementById('injector-rounds-input').value = 3;
  } else {
    document.getElementById('injector-rounds-input').value = 1;
  }

  appendInjectorLog(`[LOADED] Preset '${preset.name}' loaded into editor. Ready to execute.`, 'info');
}

function handleScriptFileUpload(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    const editor = document.getElementById('injector-code-editor');
    const title = document.getElementById('injector-script-title');
    if (editor) {
      editor.value = e.target.result;
      if (title) title.innerText = `CUSTOM: ${file.name.toUpperCase()}`;
      updateScriptMeta();
      document.querySelectorAll('.btn-preset').forEach(btn => btn.classList.remove('active'));
      appState.currentPresetId = 'uploaded';
      appendInjectorLog(`[UPLOAD] File '${file.name}' (${(file.size / 1024).toFixed(1)} KB) loaded into editor.`, 'pass');
    }
  };
  reader.readAsText(file);
}

function resetInjectorScript() {
  if (appState.currentPresetId && appState.currentPresetId !== 'uploaded') {
    loadInjectorPreset(appState.currentPresetId);
  } else {
    loadInjectorPreset('custom');
  }
}

function insertSnippet(type) {
  const editor = document.getElementById('injector-code-editor');
  if (!editor) return;

  let snippet = '';
  if (type === 'setup') {
    snippet = `\n# Setup invocation\nsetup_resp = invoke_adapter(state, {\n    "op": "setup",\n    "owners": {"res-1": "user-a"},\n    "contents": {"res-1": "CONFIDENTIAL_PAYLOAD"},\n    "disabled": [],\n    "key_material": "synthetic-test-key-material"\n})\nassert setup_resp.get("ready") is True\n`;
  } else if (type === 'read') {
    snippet = `\n# Read invocation\nread_resp = invoke_adapter(state, {\n    "op": "read",\n    "actor": "user-a",\n    "asset": "res-1",\n    "request_id": secrets.token_hex(12)\n})\nprint(f"Read decision: {read_resp.get('decision')}")\n`;
  } else if (type === 'revoke') {
    snippet = `\n# Revocation invocation\nrevoke_resp = invoke_adapter(state, {\n    "op": "revoke",\n    "actor": "user-a"\n})\nprint(f"Revoke response: {revoke_resp}")\n`;
  } else if (type === 'pqc') {
    snippet = `\n# Post-Quantum Protected Read invocation\nfrom pqcrypto.kem import ml_kem_768 as kem\npk, sk = kem.generate_keypair()\npread_resp = invoke_adapter(state, {\n    "op": "protected_read",\n    "actor": "user-a",\n    "asset": "res-1",\n    "challenge": "pqc-challenge-" + secrets.token_hex(8),\n    "public_key": base64.b64encode(pk).decode()\n})\nprint(f"Protected Read decision: {pread_resp.get('decision')}")\n`;
  } else if (type === 'audit') {
    snippet = `\n# Audit record lookup invocation\naudit_resp = invoke_adapter(state, {\n    "op": "audit",\n    "request_id": target_request_id\n})\nprint(f"Audit decision: {audit_resp.get('decision')}")\n`;
  }

  const start = editor.selectionStart;
  const end = editor.selectionEnd;
  editor.value = editor.value.substring(0, start) + snippet + editor.value.substring(end);
  editor.selectionStart = editor.selectionEnd = start + snippet.length;
  updateScriptMeta();
  editor.focus();
}

function clearInjectorTerminal() {
  const term = document.getElementById('injector-terminal');
  if (term) term.innerHTML = '<div class="terminal-line info">[CLEARED] Terminal log reset. Ready.</div>';
}

function appendInjectorLog(message, type = 'info') {
  const term = document.getElementById('injector-terminal');
  if (!term) return;
  const line = document.createElement('div');
  line.className = `terminal-line ${type}`;
  line.innerText = message;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

async function executeInjectedScript() {
  const editor = document.getElementById('injector-code-editor');
  const runBtn = document.getElementById('injector-run-btn');
  const statusPill = document.getElementById('injector-status-pill');
  if (!editor || !runBtn) return;

  const scriptContent = editor.value;
  if (!scriptContent.trim()) {
    appendInjectorLog('[ERROR] Script editor is empty. Provide Python code to execute.', 'fail');
    return;
  }

  const rounds = parseInt(document.getElementById('injector-rounds-input').value, 10) || 1;
  const seed = parseInt(document.getElementById('injector-seed-input').value, 10) || 987654321;
  const timeoutSec = parseInt(document.getElementById('injector-timeout-input').value, 10) || 60;

  runBtn.disabled = true;
  runBtn.innerText = '[EXECUTING...]';
  statusPill.className = 'badge-pill warning';
  statusPill.innerText = 'RUNNING';

  appendInjectorLog(`[START] Executing script (Seed: ${seed}, Rounds: ${rounds}, Timeout: ${timeoutSec}s)...`, 'info');

  try {
    const res = await apiFetch('/injector/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        script_content: scriptContent,
        preset_name: appState.currentPresetId,
        seed: seed,
        rounds: rounds,
        timeout_seconds: timeoutSec
      })
    });

    // Update Telemetry Boxes
    const summary = res.summary || {};
    document.getElementById('injector-pass-count').innerText = summary.PASS || 0;
    document.getElementById('injector-fail-count').innerText = summary.FAIL || 0;
    document.getElementById('injector-skip-count').innerText = (summary.SKIP || 0) + (summary.ERROR || 0);
    document.getElementById('injector-call-count').innerText = res.adapter_calls || 0;
    document.getElementById('injector-duration-text').innerText = `Duration: ${res.duration_ms.toLocaleString()} ms`;

    // Stream logs to terminal
    if (res.stdout) {
      const lines = res.stdout.split('\n');
      lines.forEach(l => {
        if (!l.trim()) return;
        let type = 'info';
        if (l.startsWith('PASS')) type = 'pass';
        else if (l.startsWith('FAIL') || l.startsWith('ERROR')) type = 'fail';
        else if (l.startsWith('SKIP')) type = 'skip';
        appendInjectorLog(l, type);
      });
    }

    if (res.stderr) {
      appendInjectorLog(`[STDERR]\n${res.stderr}`, 'fail');
    }

    // Render Invariant Breakdown
    renderInjectorBreakdown(res.tests_breakdown || []);

    if (res.success) {
      statusPill.className = 'badge-pill routine';
      statusPill.innerText = 'PASS';
      appendInjectorLog(`[COMPLETED] Script execution succeeded in ${res.duration_ms.toLocaleString()} ms. All invariants held.`, 'pass');
    } else {
      statusPill.className = 'badge-pill alert';
      statusPill.innerText = 'FAIL';
      appendInjectorLog(`[FAILED] Script exited with code ${res.exit_code}. Invariant failures detected.`, 'fail');
    }
  } catch (err) {
    statusPill.className = 'badge-pill alert';
    statusPill.innerText = 'ERROR';
    appendInjectorLog(`[ERROR] Request failed: ${err.message}`, 'fail');
  } finally {
    runBtn.disabled = false;
    runBtn.innerText = '[EXECUTE PYTHON ATTACK]';
  }
}

function renderInjectorBreakdown(breakdown) {
  const tbody = document.getElementById('injector-breakdown-body');
  const countEl = document.getElementById('injector-breakdown-count');
  if (!tbody) return;

  if (countEl) countEl.innerText = `${breakdown.length} tests parsed`;

  if (!breakdown || breakdown.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-dim); padding:12px;">No individual invariant lines parsed. Inspect stdout above.</td></tr>';
    return;
  }

  tbody.innerHTML = breakdown.map(item => {
    let badgeClass = 'routine';
    if (item.status === 'FAIL' || item.status === 'ERROR') badgeClass = 'alert';
    else if (item.status === 'SKIP') badgeClass = 'warning';

    return `
      <tr>
        <td><span class="badge-pill ${badgeClass}">[${escapeHtml(item.status)}]</span></td>
        <td style="color:var(--text-muted); font-size:11px;">${escapeHtml(item.category)}</td>
        <td style="font-family:var(--font-mono); font-weight:600; font-size:12px; color:#fff;">${escapeHtml(item.name)}</td>
        <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(item.message)}</td>
      </tr>
    `;
  }).join('');
}
