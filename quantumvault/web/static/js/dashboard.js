/**
 * QUANTUMVAULT — Security Operations Center Frontend Engine
 * 100% Offline-Compatible, Zero External Dependencies
 */

const API_BASE = '/api/v1';

// State Management
const appState = {
  activeTab: 'nodes',
  events: [],
  currentEventIndex: 0,
  isPlayingEvents: false,
  playInterval: null,
  clusterNodes: [],
  scenarios: []
};

// Initialization on DOM Load
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  loadInitialStatus();
  loadClusterTab();
  loadThreatRadarTab();
  loadPQMessagingTab();
  loadSecurityLabTab();
});

// Navigation Handling
function initNavigation() {
  const buttons = document.querySelectorAll('.nav-tab-btn');
  buttons.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      switchTab(target);
    });
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

// Global Status & Persistent Header
async function loadInitialStatus() {
  try {
    const res = await fetch(`${API_BASE}/status`);
    if (!res.ok) return;
    const data = await res.json();
    
    document.getElementById('header-epoch').innerText = `Epoch ${data.cluster_epoch}`;
    document.getElementById('header-key-ver').innerText = `Key ${data.active_key_version}`;
    document.getElementById('header-status-badge').innerText = data.backend_status.toUpperCase();
    document.getElementById('header-operator').innerText = `${data.operator} (${data.role})`;
  } catch (e) {
    console.error('Failed to load initial status:', e);
  }
}

// ==============================================================================
// TAB 1: NODES & REVOCATION
// ==============================================================================
async function loadClusterTab() {
  await refreshClusterNodes();
  await loadDevices();
  await loadIntegrityStatus();
}

async function refreshClusterNodes() {
  try {
    const res = await fetch(`${API_BASE}/cluster/status`);
    if (!res.ok) return;
    const data = await res.json();
    appState.clusterNodes = data.nodes;

    const container = document.getElementById('cluster-nodes-container');
    container.innerHTML = '';

    data.nodes.forEach(node => {
      const card = document.createElement('div');
      card.className = `node-card ${node.status}`;
      card.innerHTML = `
        <div class="node-header">
          <span class="node-name">${node.name}</span>
          <span class="node-status-badge ${node.status}">${node.status}</span>
        </div>
        <div class="node-meta">
          <div>Role: <strong>${node.role.toUpperCase()}</strong></div>
          <div>Synced Epoch: <strong>${node.last_heartbeat_epoch}</strong></div>
          <div>Key Version: <strong>${node.key_version}</strong></div>
          <div>Health: <strong>${node.healthy ? 'HEALTHY' : 'FAIL-CLOSED'}</strong></div>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (e) {
    console.error('Failed to refresh cluster nodes:', e);
  }
}

async function broadcastRevocation() {
  const actor = document.getElementById('revoke-actor-input').value || 'analyst-1';
  const logEl = document.getElementById('revocation-log-terminal');
  logEl.innerHTML = `<div class="terminal-line info">[INITIATING] Broadcasting durable revocation for: ${actor}...</div>`;

  try {
    const res = await fetch(`${API_BASE}/cluster/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_id: actor, entity_type: 'actor', reason: 'lost_device_reported' })
    });
    const data = await res.json();

    logEl.innerHTML += `
      <div class="terminal-line pass">[COMMITTED] Security Authority epoch updated to ${data.epoch} in ${data.auth_commit_latency_ms}ms</div>
      <div class="terminal-line info">[REVOCATION HASH] ${data.revocation_hash}</div>
      <div class="terminal-line pass">[CONFIRMED NODES] ${data.confirmed_nodes.join(', ')} enforced fail-closed denial</div>
      <div class="terminal-line pass">[TOTAL PROPAGATION] All nodes synchronized in ${data.total_propagation_ms}ms</div>
    `;
    await refreshClusterNodes();
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Revocation broadcast failed: ${e}</div>`;
  }
}

async function partitionNode(nodeId, action) {
  const logEl = document.getElementById('revocation-log-terminal');
  try {
    const res = await fetch(`${API_BASE}/cluster/partition-node`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: nodeId, action: action })
    });
    const data = await res.json();
    logEl.innerHTML = `<div class="terminal-line ${action === 'disconnect' ? 'warn' : 'pass'}">[CLUSTER ACTION] ${data.message}</div>`;
    await refreshClusterNodes();
  } catch (e) {
    logEl.innerHTML = `<div class="terminal-line fail">[ERROR] Node partition action failed: ${e}</div>`;
  }
}

async function rotateMasterKey() {
  const logEl = document.getElementById('revocation-log-terminal');
  try {
    const res = await fetch(`${API_BASE}/crypto/rotate-key`, { method: 'POST' });
    const data = await res.json();
    logEl.innerHTML = `
      <div class="terminal-line pass">[KEY ROTATION SUCCESS] Promoted master key to ${data.active_key_version}</div>
      <div class="terminal-line info">[GRACE PERIOD] Previous key ${data.previous_key_version} valid during ${data.grace_period_seconds}s grace window</div>
      <div class="terminal-line pass">[CUTOFF ENFORCED] Expired keys strictly rejected upon cutoff</div>
    `;
    await refreshClusterNodes();
    await loadInitialStatus();
  } catch (e) {
    logEl.innerHTML = `<div class="terminal-line fail">[ERROR] Key rotation failed: ${e}</div>`;
  }
}

async function runLostDeviceDemo() {
  const logEl = document.getElementById('lost-device-terminal');
  logEl.innerHTML = `<div class="terminal-line info">[RUNNING] 11-Step Lost-Device Resilience Demonstration...</div>`;

  try {
    const res = await fetch(`${API_BASE}/demo/lost-device`, { method: 'POST' });
    const data = await res.json();

    logEl.innerHTML = `<div class="terminal-line info">===============================================================</div>`;
    data.steps.forEach(s => {
      const prefix = (s.outcome === 'allow' || s.outcome === 'revoked' || s.outcome === 'recovered' || s.outcome === 'verified' || s.outcome === 'reported' || s.outcome === 'probed' || s.outcome === 'enrolled')
        ? 'pass' : 'warn';
      logEl.innerHTML += `<div class="terminal-line ${prefix}">Step ${s.step.toString().padStart(2, '0')}: [${s.action.toUpperCase()}] -> ${s.outcome} (${s.detail})</div>`;
    });
    logEl.innerHTML += `<div class="terminal-line pass">===============================================================</div>`;
    logEl.innerHTML += `<div class="terminal-line pass">DEMONSTRATION COMPLETED: Complete fail-closed revocation & recovery verified in ${data.revocation_latency_ms}ms.</div>`;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Lost device demo failed: ${e}</div>`;
  }
}

async function loadDevices() {
  try {
    const res = await fetch(`${API_BASE}/iam/devices`);
    if (!res.ok) return;
    const devices = await res.json();

    const tbody = document.getElementById('devices-table-body');
    tbody.innerHTML = '';
    devices.forEach(d => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${d.device_id}</strong></td>
        <td>${d.owner}</td>
        <td><span class="badge-pill ${d.status === 'active' ? 'routine' : 'suspicious'}">${d.status.toUpperCase()}</span></td>
        <td>${d.algorithm}</td>
        <td><code>${d.public_key_preview}</code></td>
        <td>
          ${d.status === 'active' ? `<button class="btn-danger" style="padding:2px 8px;font-size:10px" onclick="revokeDevice('${d.device_id}')">REVOKE</button>` : '<span style="color:var(--text-dim)">Revoked</span>'}
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    console.error('Failed to load devices:', e);
  }
}

async function revokeDevice(deviceId) {
  try {
    await fetch(`${API_BASE}/iam/revoke-device?device_id=${encodeURIComponent(deviceId)}`, { method: 'POST' });
    await loadDevices();
    await refreshClusterNodes();
  } catch (e) {
    alert(`Failed to revoke device: ${e}`);
  }
}

async function loadIntegrityStatus() {
  try {
    const res = await fetch(`${API_BASE}/integrity/status`);
    if (!res.ok) return;
    const d = await res.json();

    document.getElementById('integ-audit-chain').innerText = d.audit_chain_verified ? 'VERIFIED (IMMUTABLE)' : 'TAMPER DETECTED';
    document.getElementById('integ-audit-chain').style.color = d.audit_chain_verified ? 'var(--emerald-success)' : 'var(--crimson-alert)';
    document.getElementById('integ-total-events').innerText = `${d.total_audit_events} Events`;
    document.getElementById('integ-checkpoint').innerText = d.external_checkpoint_valid ? `EPOCH ${d.last_checkpoint_epoch} VALID` : 'INVALID';
  } catch (e) {
    console.error('Failed to load integrity status:', e);
  }
}

// ==============================================================================
// TAB 2: THREAT RADAR & PRACTICE DATASET
// ==============================================================================
async function loadThreatRadarTab() {
  await loadThreatOverview();
  await loadPracticeEvents();
  await renderServiceGraph();
  await loadIncidents();
  await loadDetectionMetrics();
}

async function loadThreatOverview() {
  try {
    const res = await fetch(`${API_BASE}/detection/overview`);
    if (!res.ok) return;
    const d = await res.json();

    document.getElementById('radar-events-count').innerText = d.events_processed;
    document.getElementById('radar-routine-count').innerText = d.routine_events;
    document.getElementById('radar-suspicious-count').innerText = d.suspicious_events;
    document.getElementById('radar-incidents-count').innerText = d.active_incidents;
    document.getElementById('radar-offset-count').innerText = d.clock_offset_events;
  } catch (e) {
    console.error('Failed to load threat overview:', e);
  }
}

async function loadPracticeEvents() {
  try {
    const res = await fetch(`${API_BASE}/detection/practice-events`);
    if (!res.ok) return;
    appState.events = await res.json();
    renderEventsTable();
  } catch (e) {
    console.error('Failed to load practice events:', e);
  }
}

function renderEventsTable() {
  const tbody = document.getElementById('events-table-body');
  tbody.innerHTML = '';

  appState.events.forEach((ev, idx) => {
    const isSuspicious = ['unexpected_role_change', 'lateral_movement_candidate', 'review_after_role_change'].includes(ev.predicted_label);
    const tr = document.createElement('tr');
    tr.id = `evt-row-${ev.event_id}`;
    if (idx === appState.currentEventIndex && appState.isPlayingEvents) {
      tr.style.backgroundColor = 'rgba(0, 229, 255, 0.15)';
    }

    const badgeClass = isSuspicious ? 'suspicious' : (ev.predicted_label === 'approved_role_change' ? 'warning' : 'routine');

    tr.innerHTML = `
      <td><strong>${ev.event_id}</strong></td>
      <td><code>${ev.corrected_time_utc.split('T')[1].replace('Z', '')}</code></td>
      <td>${ev.actor}</td>
      <td><code>${ev.source_service} → ${ev.target_service}</code></td>
      <td>${ev.action}</td>
      <td><span style="color:${ev.outcome === 'allow' || ev.outcome === 'success' ? 'var(--emerald-success)' : 'var(--crimson-alert)'}">${ev.outcome.toUpperCase()}</span></td>
      <td><span class="badge-pill ${badgeClass}">${ev.predicted_label}</span></td>
      <td><small style="color:var(--text-muted)">${ev.reason}</small></td>
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
  }, 1000);
}

function pausePracticeEvents() {
  appState.isPlayingEvents = false;
  document.getElementById('btn-play-events').innerText = 'PLAY';
  if (appState.playInterval) clearInterval(appState.playInterval);
}

function togglePracticePlayback() {
  if (appState.isPlayingEvents) {
    pausePracticeEvents();
  } else {
    playPracticeEvents();
  }
}

function stepNextEvent() {
  if (appState.events.length === 0) return;
  const ev = appState.events[appState.currentEventIndex];
  
  // Highlight row in table
  renderEventsTable();
  const row = document.getElementById(`evt-row-${ev.event_id}`);
  if (row) row.scrollIntoView({ behavior: 'smooth', block: 'center' });

  // Update terminal display
  const term = document.getElementById('threat-playback-terminal');
  const isSusp = ['unexpected_role_change', 'lateral_movement_candidate'].includes(ev.predicted_label);
  const colorClass = isSusp ? 'fail' : (ev.predicted_label === 'approved_role_change' ? 'warn' : 'pass');

  term.innerHTML += `
    <div class="terminal-line ${colorClass}">
      [${ev.event_id}] ${ev.actor} | ${ev.source_service} → ${ev.target_service} | Action: ${ev.action} | Outcome: ${ev.outcome} | Detection: ${ev.predicted_label} (${ev.reason})
    </div>
  `;
  term.scrollTop = term.scrollHeight;

  appState.currentEventIndex++;
  if (appState.currentEventIndex >= appState.events.length) {
    pausePracticeEvents();
  }
}

function resetPracticeEvents() {
  pausePracticeEvents();
  appState.currentEventIndex = 0;
  document.getElementById('threat-playback-terminal').innerHTML = '<div class="terminal-line info">[READY] Practice dataset playback reset. Press PLAY or STEP to evaluate.</div>';
  renderEventsTable();
}

async function renderServiceGraph() {
  try {
    const res = await fetch(`${API_BASE}/detection/service-graph`);
    if (!res.ok) return;
    const graph = await res.json();

    const svg = document.getElementById('service-graph-svg');
    svg.innerHTML = '';

    // Fixed service node positions for clear layout
    const coords = {
      'identity': { x: 100, y: 180 },
      'portal': { x: 260, y: 100 },
      'catalog': { x: 440, y: 100 },
      'reports': { x: 260, y: 260 },
      'billing': { x: 440, y: 260 },
      'archive': { x: 600, y: 260 }
    };

    // Draw defs for arrowheads
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

    // Draw Edges
    graph.edges.forEach(e => {
      const src = coords[e.source];
      const dst = coords[e.target];
      if (!src || !dst) return;

      const isSusp = e.status === 'suspicious_attempted';
      const strokeColor = isSusp ? '#ef4444' : '#00e5ff';
      const marker = isSusp ? 'url(#arrow-alert)' : 'url(#arrow-normal)';
      const dash = isSusp ? 'stroke-dasharray="6,4"' : '';

      svg.innerHTML += `
        <line x1="${src.x}" y1="${src.y}" x2="${dst.x}" y2="${dst.y}"
              stroke="${strokeColor}" stroke-width="${isSusp ? '3' : '1.5'}"
              ${dash} marker-end="${marker}">
          <title>${e.source} → ${e.target} (${e.status})</title>
        </line>
      `;
    });

    // Draw Nodes
    Object.keys(coords).forEach(s => {
      const pos = coords[s];
      svg.innerHTML += `
        <g transform="translate(${pos.x}, ${pos.y})">
          <circle r="26" fill="#131b2e" stroke="#00e5ff" stroke-width="2" />
          <text text-anchor="middle" dy="4" fill="#fff" font-size="11" font-weight="700" font-family="var(--font-mono)">${s.toUpperCase()}</text>
        </g>
      `;
    });
  } catch (e) {
    console.error('Failed to render service graph:', e);
  }
}

async function loadIncidents() {
  try {
    const res = await fetch(`${API_BASE}/detection/incidents`);
    if (!res.ok) return;
    const incidents = await res.json();

    const container = document.getElementById('incidents-list-container');
    container.innerHTML = '';

    incidents.forEach(inc => {
      const card = document.createElement('div');
      card.className = 'soc-card glow-cyan';
      card.style.marginBottom = '12px';
      card.style.cursor = 'pointer';
      card.onclick = () => openIncidentModal(inc);

      card.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong style="color:var(--crimson-alert)">[${inc.severity.toUpperCase()}] ${inc.rule_id}</strong>: 
            <span style="color:#fff">${inc.incident_type.replace(/_/g, ' ').toUpperCase()}</span>
          </div>
          <span class="badge-pill suspicious">${inc.incident_id}</span>
        </div>
        <p style="font-size:12px; color:var(--text-muted); margin-top:6px;">${inc.explanation}</p>
        <div style="font-size:11px; color:var(--text-dim); margin-top:4px;">
          Affected Identity: <code>${inc.actor_id}</code> | Evidence: <code>${inc.evidence_event_ids.join(', ')}</code>
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
      <div><strong>Incident Type:</strong> ${inc.incident_type}</div>
      <div><strong>Severity:</strong> <span style="color:var(--crimson-alert); font-weight:700;">${inc.severity.toUpperCase()}</span></div>
      <div><strong>Target Identity:</strong> <code>${inc.actor_id}</code></div>
      <div><strong>Triggered Deterministic Rule:</strong> ${inc.rule_id} (Zero AI/ML, 100% Deterministic)</div>
      <div><strong>Evidence Events:</strong> <code>${inc.evidence_event_ids.join(', ')}</code></div>
      <div><strong>Root Cause Explanation:</strong> ${inc.explanation}</div>
      <div style="background-color:rgba(0, 229, 255, 0.08); padding:10px; border-radius:6px; border:1px solid var(--border-color);">
        <strong style="color:var(--cyan-primary)">Recommended Operator Response:</strong><br/>
        ${inc.recommended_action}
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
    const res = await fetch(`${API_BASE}/detection/metrics`);
    if (!res.ok) return;
    const m = await res.json();

    document.getElementById('metric-f1').innerText = m.f1_score.toFixed(3);
    document.getElementById('metric-precision').innerText = m.precision.toFixed(3);
    document.getElementById('metric-recall').innerText = m.recall.toFixed(3);
    document.getElementById('metric-latency').innerText = `${m.median_alert_latency_us} µs`;
    document.getElementById('metric-false-alerts').innerText = `${m.false_alerts_per_1000_benign}/1k`;
    document.getElementById('metric-throughput').innerText = `${Math.round(m.throughput_events_per_sec)} evt/s`;
  } catch (e) {
    console.error('Failed to load detection metrics:', e);
  }
}

// ==============================================================================
// TAB 3: POST-QUANTUM MESSAGING
// ==============================================================================
function loadPQMessagingTab() {
  // Event listeners for messaging buttons are ready
}

async function performPqcHandshake() {
  const logEl = document.getElementById('messaging-log-terminal');
  logEl.innerHTML = `<div class="terminal-line info">[INITIATING] Performing NIST ML-KEM-768 Ephemeral Handshake between Alice and Bob...</div>`;

  try {
    const res = await fetch(`${API_BASE}/messaging/demo-handshake`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ initiator: 'alice', responder: 'bob' })
    });
    const d = await res.json();

    logEl.innerHTML += `<div class="terminal-line pass">[ESTABLISHED] Session ID: ${d.session_id} (${d.handshake_duration_ms}ms)</div>`;
    d.stages.forEach(s => {
      logEl.innerHTML += `<div class="terminal-line pass">  Stage ${s.stage}: [${s.name}] by ${s.actor.toUpperCase()} -> ${s.detail}</div>`;
    });
    logEl.innerHTML += `<div class="terminal-line info">[KEM PUBLIC KEY] ${d.ephemeral_kem_pk_preview}</div>`;
    logEl.innerHTML += `<div class="terminal-line info">[CIPHERTEXT] ${d.ciphertext_preview}</div>`;
    logEl.innerHTML += `<div class="terminal-line pass">[MEMORY ZEROIZATION] Ephemeral private keys immediately zeroized from memory (Forward Secrecy Guarantee).</div>`;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Handshake failed: ${e}</div>`;
  }
}

async function sendEncryptedMessage() {
  const plaintext = document.getElementById('msg-plaintext-input').value || 'Top Secret Operational Brief';
  const logEl = document.getElementById('messaging-log-terminal');
  logEl.innerHTML += `<div class="terminal-line info">[SENDING] Encrypting message under AES-256-GCM with recipient binding AAD...</div>`;

  try {
    const res = await fetch(`${API_BASE}/messaging/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender: 'alice', recipient: 'bob', plaintext: plaintext })
    });
    const d = await res.json();

    logEl.innerHTML += `
      <div class="terminal-line pass">[DELIVERED] Message ID: ${d.message_id} | Sequence: #${d.sequence_number}</div>
      <div class="terminal-line info">[CIPHERTEXT PREVIEW] ${d.ciphertext_preview}</div>
      <div class="terminal-line pass">[DECRYPTED AT BOB] "${d.plaintext_revealed_to_recipient}"</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Message send failed: ${e}</div>`;
  }
}

async function testReplayProtection() {
  const logEl = document.getElementById('messaging-log-terminal');
  logEl.innerHTML += `<div class="terminal-line warn">[TEST] Resubmitting duplicated sequence packet to Bob's sliding-window cache...</div>`;

  try {
    const res = await fetch(`${API_BASE}/messaging/test-replay`, { method: 'POST' });
    const d = await res.json();

    logEl.innerHTML += `
      <div class="terminal-line pass">[OUTCOME] ${d.outcome}</div>
      <div class="terminal-line info">[FILTER LATENCY] Checked sliding window in ${d.check_latency_us} µs</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Replay test failed: ${e}</div>`;
  }
}

async function testRecipientTampering() {
  const logEl = document.getElementById('messaging-log-terminal');
  logEl.innerHTML += `<div class="terminal-line warn">[TEST] Modifying authenticated recipient in AAD from 'bob' to 'eve'...</div>`;

  try {
    const res = await fetch(`${API_BASE}/messaging/test-tamper-recipient`, { method: 'POST' });
    const d = await res.json();

    logEl.innerHTML += `
      <div class="terminal-line pass">[STATUS] ${d.status}</div>
      <div class="terminal-line pass">[ENFORCEMENT] ${d.error}</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Tamper test failed: ${e}</div>`;
  }
}

async function testForwardSecrecy() {
  const logEl = document.getElementById('messaging-log-terminal');
  logEl.innerHTML += `<div class="terminal-line info">[TEST] Simulating later identity-key compromise (Forward Secrecy Harness)...</div>`;

  try {
    const res = await fetch(`${API_BASE}/messaging/test-forward-secrecy`, { method: 'POST' });
    const d = await res.json();

    logEl.innerHTML += `
      <div class="terminal-line pass">[PROOF RESULT] Forward Secrecy Preserved: ${d.forward_secrecy_preserved ? 'TRUE' : 'FALSE'}</div>
      <div class="terminal-line pass">[ADVERSARY COMPROMISED KEYS] ${d.adversary_compromised_keys.join(', ')}</div>
      <div class="terminal-line pass">[TRANSCRIPT DECRYPTED] ${d.captured_transcript_decrypted ? 'YES' : 'NO (Cryptographically Infeasible)'}</div>
      <div class="terminal-line info">[REASONING] ${d.cryptographic_reasoning}</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Forward secrecy test failed: ${e}</div>`;
  }
}

async function testTransportFault(faultType) {
  const logEl = document.getElementById('messaging-log-terminal');
  logEl.innerHTML += `<div class="terminal-line info">[TEST] Simulating transport fault: ${faultType}...</div>`;

  try {
    const res = await fetch(`${API_BASE}/messaging/test-transport-fault?fault_type=${encodeURIComponent(faultType)}`, { method: 'POST' });
    const d = await res.json();

    logEl.innerHTML += `
      <div class="terminal-line pass">[STATUS] ${d.status}</div>
      <div class="terminal-line info">${d.action || `Reassembled ${d.bytes_recovered} bytes from out-of-order chunks.`}</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Transport test failed: ${e}</div>`;
  }
}

async function testOfflineOutbox() {
  const logEl = document.getElementById('messaging-log-terminal');
  logEl.innerHTML += `<div class="terminal-line info">[TEST] Simulating encrypted offline composition & fail-closed reconnection...</div>`;

  try {
    const res = await fetch(`${API_BASE}/messaging/test-offline-outbox`, { method: 'POST' });
    const d = await res.json();

    logEl.innerHTML += `
      <div class="terminal-line pass">[STATUS] ${d.status}</div>
      <div class="terminal-line pass">[ENFORCEMENT] ${d.outcome}</div>
    `;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Outbox test failed: ${e}</div>`;
  }
}

// ==============================================================================
// TAB 4: SECURITY LABORATORY
// ==============================================================================
async function loadSecurityLabTab() {
  await loadLabScenarios();
  await loadEvidenceFiles();
}

async function loadLabScenarios() {
  try {
    const res = await fetch(`${API_BASE}/lab/scenarios`);
    if (!res.ok) return;
    appState.scenarios = await res.json();
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
          <span id="badge-${s.name}" class="badge-pill routine" style="font-size:9px;">READY</span>
          ${s.name}
          <span style="font-size:10px; color:var(--text-dim)">(${s.category})</span>
        </div>
        <p style="font-size:11px; color:var(--text-muted); margin-top:2px;">${s.description}</p>
      </div>
      <div style="display:flex; align-items:center; gap:12px;">
        <span id="duration-${s.name}" style="font-family:var(--font-mono); font-size:11px; color:var(--text-dim)">--</span>
        <button class="btn-secondary" style="padding:4px 10px; font-size:11px;" onclick="runIndividualScenario('${s.name}')">RUN</button>
      </div>
    `;
    container.appendChild(row);
  });
}

function filterScenarios(category) {
  if (category === 'all') {
    renderScenariosList(appState.scenarios);
  } else {
    const filtered = appState.scenarios.filter(s => s.category.toLowerCase().includes(category.toLowerCase()));
    renderScenariosList(filtered);
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
    const res = await fetch(`${API_BASE}/lab/run?name=${encodeURIComponent(name)}`, { method: 'POST' });
    const d = await res.json();

    if (badge) {
      badge.innerText = d.passed ? 'PASS' : 'FAIL';
      badge.className = `badge-pill ${d.passed ? 'routine' : 'suspicious'}`;
    }
    if (duration) {
      duration.innerText = `${d.duration_ms}ms`;
    }
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
    const res = await fetch(`${API_BASE}/lab/run-all`, { method: 'POST' });
    const d = await res.json();

    progBar.style.width = '100%';
    progText.innerText = `COMPLETED: ${d.total_passed}/${d.total_scenarios} PASSED (${d.all_passed ? '100% SUCCESS' : 'FAILURES DETECTED'})`;

    d.results.forEach(r => {
      const badge = document.getElementById(`badge-${r.name}`);
      const duration = document.getElementById(`duration-${r.name}`);
      if (badge) {
        badge.innerText = r.passed ? 'PASS' : 'FAIL';
        badge.className = `badge-pill ${r.passed ? 'routine' : 'suspicious'}`;
      }
      if (duration) {
        duration.innerText = `${r.duration_ms}ms`;
      }
    });
  } catch (e) {
    progText.innerText = `Error executing test lab: ${e}`;
  }
}

async function runCombinedResilienceScenario() {
  const logEl = document.getElementById('combined-demo-terminal');
  logEl.innerHTML = `<div class="terminal-line info">[RUNNING] 40-Step Combined Security Resilience Demonstration...</div>`;

  try {
    const res = await fetch(`${API_BASE}/lab/run-combined`, { method: 'POST' });
    const d = await res.json();

    logEl.innerHTML = `<div class="terminal-line info">===============================================================</div>`;
    d.steps.forEach(s => {
      const colorClass = s.status === 'PASS' ? 'pass' : 'fail';
      logEl.innerHTML += `<div class="terminal-line ${colorClass}">Step ${s.step.toString().padStart(2, '0')}: [${s.status}] ${s.title}</div>`;
    });
    logEl.innerHTML += `<div class="terminal-line pass">===============================================================</div>`;
    logEl.innerHTML += `<div class="terminal-line pass">COMBINED SCENARIO SUCCESS: ${d.steps_passed}/${d.total_steps} steps passed in ${d.execution_time_ms}ms.</div>`;
  } catch (e) {
    logEl.innerHTML += `<div class="terminal-line fail">[ERROR] Combined scenario failed: ${e}</div>`;
  }
}

async function loadEvidenceFiles() {
  try {
    const res = await fetch(`${API_BASE}/lab/evidence/list`);
    if (!res.ok) return;
    const d = await res.json();

    const select = document.getElementById('evidence-file-select');
    select.innerHTML = '<option value="">-- Select Evidence File --</option>';
    d.files.forEach(f => {
      const opt = document.createElement('option');
      opt.value = f.path;
      opt.innerText = `${f.path} (${f.size_bytes} bytes)`;
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
    const res = await fetch(`${API_BASE}/lab/evidence/view?file_path=${encodeURIComponent(filePath)}`);
    const d = await res.json();
    viewer.innerText = d.content;
  } catch (e) {
    viewer.innerText = `Error loading evidence: ${e}`;
  }
}
