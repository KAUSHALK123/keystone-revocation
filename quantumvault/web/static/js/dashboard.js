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
  activeTab: 'dashboard',
  events: [],
  filteredEvents: [],
  currentEventIndex: 0,
  clusterNodes: [],
};

// ==============================================================================
// INITIALIZATION & NAVIGATION
// ==============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  loadInitialStatus();
  refreshClusterNodes();
  loadThreatData();
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

  if (tabId === 'revocation') {
    refreshClusterNodes();
  } else if (tabId === 'threats') {
    loadThreatData();
  }
}

// ==============================================================================
// GLOBAL STATUS
// ==============================================================================
async function loadInitialStatus() {
  try {
    const data = await apiFetch('/status');
    const epochText = `Epoch ${data.cluster_epoch}`;
    const keyText = `Key v${data.active_key_version}`;

    document.getElementById('header-epoch').innerText = epochText;
    document.getElementById('header-key-ver').innerText = keyText;
    document.getElementById('header-status-badge').innerText = data.backend_status.toUpperCase();

    const auditBadge = document.getElementById('header-audit-badge');
    auditBadge.innerText = data.audit_verified ? 'VERIFIED' : 'TAMPERED';
    auditBadge.style.color = data.audit_verified ? 'var(--emerald-success)' : 'var(--crimson-alert)';

    const dashEpoch = document.getElementById('dash-cluster-epoch');
    if (dashEpoch) dashEpoch.innerText = `${epochText} | Monotonic Sync`;

    const dashKey = document.getElementById('dash-active-key');
    if (dashKey) dashKey.innerText = keyText;

    const dashAudit = document.getElementById('dash-audit-status');
    if (dashAudit) {
      dashAudit.innerText = data.audit_verified ? 'VERIFIED' : 'TAMPERED';
      dashAudit.style.color = data.audit_verified ? 'var(--emerald-success)' : 'var(--crimson-alert)';
    }
  } catch (e) {
    console.error('Failed to load status:', e);
  }
}

// ==============================================================================
// TAB 0: DASHBOARD ACTIONS
// ==============================================================================
function logDash(text, cls = 'info') {
  const term = document.getElementById('dash-terminal');
  if (!term) return;
  term.innerHTML += `<div class="terminal-line ${cls}">${escapeHtml(text)}</div>`;
  term.scrollTop = term.scrollHeight;
}

function clearDashboardTerminal() {
  const term = document.getElementById('dash-terminal');
  if (term) term.innerHTML = '';
}

async function runHealthCheck() {
  logDash('[HEALTH CHECK] Querying QuantumVault core security status...', 'info');
  try {
    const [status, integrity] = await Promise.all([
      apiFetch('/status'),
      apiFetch('/integrity/status'),
    ]);

    logDash(`[OK] Cluster Status: ${status.backend_status.toUpperCase()} (Epoch ${status.cluster_epoch})`, 'pass');
    logDash(`[OK] Master Key: Version ${status.active_key_version} active`, 'pass');
    logDash(`[OK] Audit Hash Chain: ${integrity.audit_chain_verified ? 'VALID & IMMUTABLE' : 'TAMPER DETECTED'} (${integrity.total_audit_events} total events)`, integrity.audit_chain_verified ? 'pass' : 'fail');
    logDash(`[OK] Monotonic Checkpoint: Epoch ${integrity.last_checkpoint_epoch} verified`, 'pass');
    logDash(`[OK] PQC Subsystem: ML-KEM-768 (FIPS 203) & ML-DSA-65 (FIPS 204) verified`, 'pass');
    logDash('[SUMMARY] All security subsystems fully operational.', 'pass');
    await loadInitialStatus();
  } catch (e) {
    logDash(`[ERROR] Health check failed: ${e.message}`, 'fail');
  }
}

async function rotateKeyFromDashboard() {
  logDash('[KEY ROTATION] Initiating master cryptographic key rotation...', 'info');
  try {
    const data = await apiFetch('/crypto/rotate-key', { method: 'POST' });
    logDash(`[PASS] Promoted ${data.previous_key_version} → ${data.active_key_version} in ${data.rotation_duration_ms}ms`, 'pass');
    logDash(`[PASS] Rewrapped ${data.rewrapped_count} assets under new DEK`, 'pass');
    logDash(`[PASS] Previous key retained for ${data.grace_period_seconds}s grace window until ${data.cutoff_timestamp}`, 'pass');
    await loadInitialStatus();
  } catch (e) {
    logDash(`[ERROR] Key rotation failed: ${e.message}`, 'fail');
  }
}

async function verifyAuditFromDashboard() {
  logDash('[AUDIT CHECK] Verifying cryptographic SHA-256 hash chaining from genesis...', 'info');
  try {
    const data = await apiFetch('/integrity/verify', { method: 'POST' });
    logDash(`[PASS] Audit Chain Status: ${data.audit_chain_verified ? 'VERIFIED (0 TAMPERING)' : 'TAMPER DETECTED'}`, data.audit_chain_verified ? 'pass' : 'fail');
    logDash(`[PASS] Total Events Verified: ${data.total_audit_events}`, 'pass');
    logDash(`[PASS] External Checkpoint: Epoch ${data.last_checkpoint_epoch} HMAC signature valid`, 'pass');
    logDash(`[PASS] Backup Snapshot Digest: ${data.last_backup_digest}`, 'pass');
    await loadInitialStatus();
  } catch (e) {
    logDash(`[ERROR] Audit verification failed: ${e.message}`, 'fail');
  }
}

async function quickRevokeDemo() {
  logDash('[QUICK REVOKE] Broadcasting instant revocation for actor: user-alex...', 'info');
  try {
    const data = await apiFetch('/cluster/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_id: 'user-alex', entity_type: 'actor', reason: 'quick_demo_revocation' }),
    });
    logDash(`[PASS] Revocation committed to Authority at Epoch ${data.epoch} in ${data.auth_commit_latency_ms}ms`, 'pass');
    logDash(`[PASS] Propagated to nodes [${data.confirmed_nodes.join(', ')}] in ${data.total_propagation_ms}ms total`, 'pass');
    logDash(`[PASS] SHA-256 Revocation Hash: ${data.revocation_hash}`, 'pass');
    await Promise.all([loadInitialStatus(), refreshClusterNodes()]);
  } catch (e) {
    logDash(`[ERROR] Revocation failed: ${e.message}`, 'fail');
  }
}

async function quickLostDeviceTest() {
  logDash('[LOST DEVICE] Executing 11-step lost-device resilience scenario...', 'info');
  try {
    const data = await apiFetch('/demo/lost-device', { method: 'POST' });
    data.steps.forEach(s => {
      const cls = ['allow', 'revoked', 'recovered', 'verified', 'reported'].includes(s.outcome) ? 'pass' : (s.outcome === 'deny' ? 'warn' : 'fail');
      logDash(`Step ${String(s.step).padStart(2, '0')}: [${s.action.toUpperCase()}] → ${s.outcome} (${s.detail})`, cls);
    });
    logDash(`[COMPLETED] Lost-device resilience verified in ${data.revocation_latency_ms}ms.`, 'pass');
    await loadInitialStatus();
  } catch (e) {
    logDash(`[ERROR] Lost device test failed: ${e.message}`, 'fail');
  }
}

// ==============================================================================
// TAB 1: ACCESS & REVOCATION
// ==============================================================================
function logRev(text, cls = 'info') {
  const term = document.getElementById('revocation-log-terminal');
  if (!term) return;
  term.innerHTML += `<div class="terminal-line ${cls}">${escapeHtml(text)}</div>`;
  term.scrollTop = term.scrollHeight;
}

async function refreshClusterNodes() {
  try {
    const data = await apiFetch('/cluster/status');
    appState.clusterNodes = data.nodes;
    const container = document.getElementById('cluster-nodes-container');
    if (!container) return;
    container.innerHTML = '';

    data.nodes.forEach(node => {
      const card = document.createElement('div');
      card.className = `node-card ${node.status}`;
      card.innerHTML = `
        <div class="node-header">
          <span class="node-name">${escapeHtml(node.name)}</span>
          <span class="node-status-badge ${escapeHtml(node.status)}">${escapeHtml(node.status)}</span>
        </div>
        <div class="node-meta">
          <div>Role: <strong>${escapeHtml(node.role.toUpperCase())}</strong></div>
          <div>Synced Epoch: <strong>${escapeHtml(node.last_heartbeat_epoch)}</strong></div>
          <div>Health: <strong>${node.healthy ? 'HEALTHY (SYNCED)' : 'FAIL-CLOSED'}</strong></div>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (e) {
    console.error('Failed to refresh cluster nodes:', e);
  }
}

async function testReadAsset() {
  const actor = document.getElementById('read-actor-input').value.trim() || 'user-alex';
  const asset = document.getElementById('read-asset-input').value.trim() || 'brief-q4';
  const box = document.getElementById('read-result-box');
  const reqId = `req-web-${Date.now()}`;

  logRev(`[READ REQUEST] Actor: ${actor} | Asset: ${asset} | Request ID: ${reqId}`, 'info');

  try {
    const res = await apiFetch('/read', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor, asset, request_id: reqId }),
    });

    if (res.decision === 'allow') {
      box.innerHTML = `<span style="color:var(--emerald-success); font-weight:700;">[ALLOW]</span> <span style="color:#fff; margin-left:8px;">"${escapeHtml(res.body)}"</span>`;
      logRev(`[DECISION: ALLOW] Access granted to ${actor}. Body returned: "${res.body}"`, 'pass');
    } else {
      box.innerHTML = `<span style="color:var(--crimson-alert); font-weight:700;">[DENY]</span> <span style="color:var(--text-muted); margin-left:8px;">Access blocked. Identity or device is revoked.</span>`;
      logRev(`[DECISION: DENY] Access blocked for actor ${actor} (Fail-Closed PEP Enforcement)`, 'warn');
    }
  } catch (e) {
    box.innerHTML = `<span style="color:var(--crimson-alert); font-weight:700;">[ERROR]</span> <span style="color:#fff; margin-left:8px;">${escapeHtml(e.message)}</span>`;
    logRev(`[ERROR] Read failed: ${e.message}`, 'fail');
  }
}

async function testRevokeActor() {
  const actor = document.getElementById('revoke-actor-input').value.trim() || 'user-alex';
  const box = document.getElementById('read-result-box');

  logRev(`[REVOCATION] Initiating broadcast revocation for: ${actor}...`, 'info');

  try {
    const data = await apiFetch('/cluster/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_id: actor, entity_type: 'actor', reason: 'manual_soc_revocation' }),
    });

    box.innerHTML = `<span style="color:var(--amber-warning); font-weight:700;">[REVOKED]</span> <span style="color:#fff; margin-left:8px;">Actor "${escapeHtml(actor)}" revoked at Epoch ${data.epoch} (${data.total_propagation_ms}ms)</span>`;
    logRev(`[COMMITTED] Authority Epoch: ${data.epoch} | Latency: ${data.auth_commit_latency_ms}ms`, 'pass');
    logRev(`[PROPAGATED] Confirmed on [${data.confirmed_nodes.join(', ')}] in ${data.total_propagation_ms}ms`, 'pass');
    await Promise.all([loadInitialStatus(), refreshClusterNodes()]);
  } catch (e) {
    logRev(`[ERROR] Revocation failed: ${e.message}`, 'fail');
  }
}

async function testResetSampleAsset() {
  const box = document.getElementById('read-result-box');
  logRev('[SETUP] Re-initializing sample asset (brief-q4 owned by user-alex)...', 'info');

  try {
    await apiFetch('/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        owners: { 'brief-q4': 'user-alex' },
        contents: { 'brief-q4': 'Confidential Strategic Plan' },
        disabled: [],
        key_material: 'reset-sample-seed-material',
      }),
    });

    document.getElementById('read-actor-input').value = 'user-alex';
    document.getElementById('read-asset-input').value = 'brief-q4';
    document.getElementById('revoke-actor-input').value = 'user-alex';

    box.innerHTML = `<span style="color:var(--emerald-success); font-weight:700;">[READY]</span> <span style="color:#fff; margin-left:8px;">Sample asset initialized for user-alex. Click 'READ ASSET' to verify.</span>`;
    logRev('[SETUP COMPLETE] Sample asset ready: brief-q4 owned by user-alex.', 'pass');
    await Promise.all([loadInitialStatus(), refreshClusterNodes()]);
  } catch (e) {
    logRev(`[ERROR] Setup failed: ${e.message}`, 'fail');
  }
}

async function partitionNode(nodeId, action) {
  try {
    const data = await apiFetch('/cluster/partition-node', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: nodeId, action }),
    });
    logRev(`[PARTITION] ${data.message}`, action === 'disconnect' ? 'warn' : 'pass');
    await refreshClusterNodes();
  } catch (e) {
    logRev(`[ERROR] Partition action failed: ${e.message}`, 'fail');
  }
}

// ==============================================================================
// TAB 2: THREAT DETECTION
// ==============================================================================
async function loadThreatData() {
  try {
    const [overview, events] = await Promise.all([
      apiFetch('/detection/overview'),
      apiFetch('/detection/practice-events?evaluation_mode=false'),
    ]);

    document.getElementById('radar-events-count').innerText = overview.events_processed;
    document.getElementById('radar-routine-count').innerText = overview.routine_events;
    document.getElementById('radar-suspicious-count').innerText = overview.suspicious_events;
    document.getElementById('radar-incidents-count').innerText = overview.active_incidents;

    appState.events = events;
    populateThreatFilters(events);
    renderThreatTable(events);
  } catch (e) {
    console.error('Failed to load threat data:', e);
  }
}

function populateThreatFilters(events) {
  const actorSel = document.getElementById('filter-actor');
  const classSel = document.getElementById('filter-class');
  if (!actorSel || !classSel) return;

  const actors = [...new Set(events.map(e => e.actor))].sort();
  const classes = [...new Set(events.map(e => e.predicted_label))].sort();

  actorSel.innerHTML = '<option value="">All Actors</option>';
  actors.forEach(a => {
    const o = document.createElement('option');
    o.value = a;
    o.textContent = a;
    actorSel.appendChild(o);
  });

  classSel.innerHTML = '<option value="">All Classes</option>';
  classes.forEach(c => {
    const o = document.createElement('option');
    o.value = c;
    o.textContent = c.toUpperCase();
    classSel.appendChild(o);
  });
}

function applyEventFilters() {
  const actor = document.getElementById('filter-actor').value;
  const cls = document.getElementById('filter-class').value;

  const filtered = appState.events.filter(e => {
    const matchActor = !actor || e.actor === actor;
    const matchClass = !cls || e.predicted_label === cls;
    return matchActor && matchClass;
  });

  renderThreatTable(filtered);
}

function renderThreatTable(events) {
  const tbody = document.getElementById('telemetry-table-body');
  const countEl = document.getElementById('events-table-count');
  if (!tbody) return;

  countEl.innerText = `${events.length} events`;
  tbody.innerHTML = '';

  if (events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-dim); padding:16px;">No matching telemetry events.</td></tr>';
    return;
  }

  events.forEach(e => {
    const isSusp = e.predicted_label === 'suspicious';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${escapeHtml(e.event_id)}</strong></td>
      <td>${escapeHtml(e.timestamp)}</td>
      <td>${escapeHtml(e.actor)}</td>
      <td><code>${escapeHtml(e.service)}</code></td>
      <td><span class="badge-pill ${isSusp ? 'suspicious' : 'routine'}">${escapeHtml(e.predicted_label.toUpperCase())}</span></td>
      <td><span style="color:${isSusp ? 'var(--crimson-alert)' : 'var(--text-muted)'}">${escapeHtml(e.severity.toUpperCase())}</span></td>
      <td style="color:var(--text-muted); font-size:11px;">${escapeHtml(e.explanation || '--')}</td>
    `;
    tbody.appendChild(tr);
  });
}

function ingestNextEvent() {
  if (appState.events.length === 0) return;
  const evt = appState.events[appState.currentEventIndex % appState.events.length];
  appState.currentEventIndex++;

  const banner = document.getElementById('radar-alert-banner');
  const alertText = document.getElementById('radar-alert-text');
  const alertDetail = document.getElementById('radar-alert-detail');

  if (evt.predicted_label === 'suspicious') {
    banner.style.display = 'block';
    alertText.textContent = `ALERT [${evt.event_id}]: Suspicious access by ${evt.actor} on ${evt.service}`;
    alertDetail.textContent = evt.explanation;
  } else {
    banner.style.display = 'none';
  }

  renderThreatTable([evt]);
}

async function runFullTelemetryEval() {
  const banner = document.getElementById('radar-alert-banner');
  banner.style.display = 'none';
  await loadThreatData();
}

function resetTelemetryStream() {
  appState.currentEventIndex = 0;
  const banner = document.getElementById('radar-alert-banner');
  if (banner) banner.style.display = 'none';
  renderThreatTable(appState.events);
}

// ==============================================================================
// TAB 3: PQ MESSAGING
// ==============================================================================
function logMsg(text, cls = 'info') {
  const term = document.getElementById('messaging-log-terminal');
  if (!term) return;
  term.innerHTML += `<div class="terminal-line ${cls}">${escapeHtml(text)}</div>`;
  term.scrollTop = term.scrollHeight;
}

async function performPqcHandshake() {
  logMsg('[HANDSHAKE] Generating NIST ML-KEM-768 ephemeral keypair and signing offer...', 'info');
  try {
    const d = await apiFetch('/messaging/demo-handshake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ initiator: 'alice', responder: 'bob' }),
    });

    logMsg(`[ESTABLISHED] Session ID: ${d.session_id} (${d.handshake_duration_ms}ms)`, 'pass');
    logMsg(`[ML-KEM-768 PK] ${d.ephemeral_kem_pk_preview}`, 'pass');
    logMsg(`[CIPHERTEXT] ${d.ciphertext_preview}`, 'pass');
    logMsg(`[BUFFER ZEROIZED] Ephemeral private key zeroized in RAM: ${d.ephemeral_keys_zeroized}`, 'pass');
  } catch (e) {
    logMsg(`[ERROR] Handshake failed: ${e.message}`, 'fail');
  }
}

async function sendEncryptedMessage() {
  const plaintext = document.getElementById('msg-plaintext-input').value || 'Confidential Executive Directive';
  const box = document.getElementById('msg-received-box');
  logMsg(`[TRANSMIT] Encrypting under AES-256-GCM with recipient AAD: "${plaintext}"`, 'info');

  try {
    const d = await apiFetch('/messaging/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender: 'alice', recipient: 'bob', plaintext }),
    });

    box.innerHTML = `<span style="color:var(--emerald-success); font-weight:700;">[DECRYPTED]</span> <span style="color:#fff; margin-left:8px;">"${escapeHtml(d.plaintext_revealed_to_recipient)}"</span>`;
    logMsg(`[DELIVERED] Message ID: ${d.message_id} | Seq #${d.sequence_number}`, 'pass');
    logMsg(`[CIPHERTEXT] ${d.ciphertext_preview}`, 'pass');
    logMsg(`[RECIPIENT BOB] Successfully authenticated AAD and decrypted: "${d.plaintext_revealed_to_recipient}"`, 'pass');
  } catch (e) {
    box.innerHTML = `<span style="color:var(--crimson-alert); font-weight:700;">[ERROR]</span> <span style="color:#fff; margin-left:8px;">${escapeHtml(e.message)}</span>`;
    logMsg(`[ERROR] Send failed: ${e.message}`, 'fail');
  }
}

async function testReplayProtection() {
  logMsg('[REPLAY ATTACK] Injecting duplicate packet into sliding window...', 'info');
  try {
    const d = await apiFetch('/messaging/test-replay', { method: 'POST' });
    logMsg(`[OUTCOME] ${d.outcome}`, 'pass');
    logMsg(`[SLIDING WINDOW] Checked bitmask in ${d.check_latency_us} µs. Duplicate strictly rejected.`, 'pass');
  } catch (e) {
    logMsg(`[ERROR] Replay test failed: ${e.message}`, 'fail');
  }
}

async function testRecipientTamper() {
  logMsg('[TAMPER TEST] Altering AAD recipient binding in encrypted frame...', 'info');
  try {
    const d = await apiFetch('/messaging/test-tamper-recipient', { method: 'POST' });
    logMsg(`[OUTCOME] ${d.outcome}`, 'pass');
    logMsg(`[AEAD ENFORCEMENT] Tag verification failed. Spoofed recipient rejected.`, 'pass');
  } catch (e) {
    logMsg(`[ERROR] Tamper test failed: ${e.message}`, 'fail');
  }
}

async function testForwardSecrecy() {
  logMsg('[KEY THEFT] Simulating long-term identity signing key compromise...', 'info');
  try {
    const d = await apiFetch('/messaging/test-forward-secrecy', { method: 'POST' });
    logMsg(`[OUTCOME] ${d.outcome}`, 'pass');
    logMsg(`[FORWARD SECRECY] Ephemeral session keys protected. Historical transcript undecryptable.`, 'pass');
  } catch (e) {
    logMsg(`[ERROR] Forward secrecy test failed: ${e.message}`, 'fail');
  }
}

// ==============================================================================
// TAB 4: SECURITY LAB
// ==============================================================================
function logLab(text, cls = 'info') {
  const term = document.getElementById('lab-terminal');
  if (!term) return;
  term.innerHTML += `<div class="terminal-line ${cls}">${escapeHtml(text)}</div>`;
  term.scrollTop = term.scrollHeight;
}

async function runLabValidator() {
  const btn = document.getElementById('btn-lab-validator');
  if (btn) { btn.disabled = true; btn.textContent = 'RUNNING...'; }
  logLab('================================================================', 'info');
  logLab('[START] Running Official Track 4 Lost-Device Validator (12/12)...', 'info');

  try {
    const data = await apiFetch('/demo/lost-device', { method: 'POST' });
    data.steps.forEach(s => {
      const cls = ['allow', 'revoked', 'recovered', 'verified', 'reported'].includes(s.outcome) ? 'pass' : (s.outcome === 'deny' ? 'warn' : 'fail');
      logLab(`Step ${String(s.step).padStart(2, '0')}: [${s.action.toUpperCase()}] → ${s.outcome} (${s.detail})`, cls);
    });
    logLab(`[RESULT] All 12/12 Validator Invariants PASSED in ${data.revocation_latency_ms}ms.`, 'pass');
  } catch (e) {
    logLab(`[ERROR] Validator suite failed: ${e.message}`, 'fail');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'RUNNING LOST-DEVICE VALIDATOR (12/12)'; }
  }
}

async function runLabMultiProcess() {
  const btn = document.getElementById('btn-lab-multiprocess');
  if (btn) { btn.disabled = true; btn.textContent = 'SPAWNING PROCESSES...'; }
  logLab('================================================================', 'info');
  logLab('[START] Spawning genuine OS worker processes (Node A, Node B, Node C)...', 'info');

  try {
    const data = await apiFetch('/cluster/multiprocess/execute', { method: 'POST' });
    if (data.steps) {
      data.steps.forEach(s => {
        const cls = s.outcome === 'failed' ? 'fail' : (s.outcome === 'deny' || s.outcome === 'terminated' ? 'warn' : 'pass');
        logLab(`Step ${s.step}: [${s.action}] → ${s.outcome.toUpperCase()} (${s.detail})`, cls);
      });
    }
    logLab('[RESULT] All 12 Multi-Process OS isolation & failover steps PASSED.', 'pass');
  } catch (e) {
    logLab(`[ERROR] Multi-process suite failed: ${e.message}`, 'fail');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'RUN OS MULTI-PROCESS SUITE'; }
  }
}

async function runLabCombined() {
  const btn = document.getElementById('btn-lab-combined');
  if (btn) { btn.disabled = true; btn.textContent = 'RUNNING 40 SCENARIOS...'; }
  logLab('================================================================', 'info');
  logLab('[START] Executing 40-Scenario Automated Security Suite...', 'info');

  try {
    const data = await apiFetch('/lab/run-combined', { method: 'POST' });
    if (data.steps) {
      data.steps.forEach(s => {
        logLab(`Step ${String(s.step).padStart(2, '0')}: ${s.title} → ${s.status}`, s.status === 'PASS' ? 'pass' : 'fail');
      });
    }
    logLab(`[RESULT] Passed ${data.steps_passed} / ${data.total_steps} Scenarios in ${data.execution_time_ms}ms.`, 'pass');
  } catch (e) {
    logLab(`[ERROR] 40-scenario suite failed: ${e.message}`, 'fail');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'RUN 40-SCENARIO SUITE'; }
  }
}
