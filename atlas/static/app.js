<<<<<<< HEAD
const S = { view: 'overview', me: null, servers: [], jobs: [], selectedServer: null, sse: null };
const $ = id => document.getElementById(id);
const esc = v => String(v ?? '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
const pct = v => `${Math.round(Number(v || 0))}%`;
const time = v => v ? new Date(v).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Never';
=======
const S = {
  view: 'overview',
  me: null,
  servers: [],
  jobs: [],
  pending: null
};

const $ = id => document.getElementById(id);
const esc = v => String(v ?? '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
const pct = v => `${Math.round(Number(v || 0))}%`;
const time = v => v ? new Date(v).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Never';

function toast(message, type = 'info') {
  const container = $('toast-container');
  if (!container) return;
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.innerHTML = `<span>${esc(message)}</span>`;
  container.appendChild(t);
  setTimeout(() => {
    t.style.opacity = '0';
    t.style.transform = 'translateY(8px)';
    setTimeout(() => t.remove(), 200);
  }, 3500);
}
>>>>>>> origin/main

async function api(path, opt = {}) {
  const o = { ...opt, headers: { ...(opt.headers || {}) } };
  if (o.body && typeof o.body !== 'string') {
    o.headers['Content-Type'] = 'application/json';
    o.body = JSON.stringify(o.body);
  }
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes((o.method || 'GET').toUpperCase())) {
    const c = document.cookie.split('; ').find(x => x.startsWith('atlas_csrf='));
    if (c) o.headers['X-CSRF-Token'] = decodeURIComponent(c.split('=')[1]);
  }
  const r = await fetch(path, o);
  const p = await r.json().catch(() => ({}));
<<<<<<< HEAD
  if (!r.ok) throw Error(p.detail || p.unsupported_reason || `Request failed (${r.status})`);
=======
  if (!r.ok) throw Error(p.detail || `Request failed (${r.status})`);
>>>>>>> origin/main
  return p;
}

async function boot() {
  try {
    S.me = await api('/api/me');
    $('login').classList.add('hidden');
    $('app').classList.remove('hidden');
<<<<<<< HEAD
    $('identity').textContent = `${S.me.username} · ${S.me.role}`;
    document.querySelectorAll('.admin').forEach(x => x.classList.toggle('hidden', S.me.role !== 'admin'));
    initSSE();
  } catch {
    $('login').classList.remove('hidden');
    $('app').classList.add('hidden');
    return;
  }
  try {
    await loadOverview();
  } catch (err) {
    console.error('Failed to load overview data:', err);
  }
}

function initSSE() {
  if (S.sse) return;
  try {
    S.sse = new EventSource('/api/events/stream');
    S.sse.onmessage = e => {
      try {
        const evt = JSON.parse(e.data);
        if (S.view === 'audit') loadAudit();
        if (S.view === 'overview') loadOverview();
      } catch {}
    };
  } catch {}
}

=======
    $('user-display').textContent = S.me.username;
    $('role-display').textContent = S.me.role.toUpperCase();
    document.querySelectorAll('.admin').forEach(x => x.classList.toggle('hidden', S.me.role !== 'admin'));
    await loadOverview();
  } catch {
    $('login').classList.remove('hidden');
    $('app').classList.add('hidden');
  }
}

// Login & Logout
>>>>>>> origin/main
$('login-form').addEventListener('submit', async e => {
  e.preventDefault();
  $('login-error').textContent = '';
  try {
<<<<<<< HEAD
    await api('/api/auth/login', { method: 'POST', body: { username: $('username').value, password: $('password').value } });
    boot();
=======
    await api('/api/auth/login', {
      method: 'POST',
      body: { username: $('username').value, password: $('password').value }
    });
    toast('Authentication successful', 'success');
    await boot();
>>>>>>> origin/main
  } catch (err) {
    $('login-error').textContent = err.message;
  }
});

$('logout').addEventListener('click', async () => {
<<<<<<< HEAD
  try { await api('/api/auth/logout', { method: 'POST' }); } finally { location.reload(); }
});

document.querySelectorAll('.nav').forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));
=======
  try {
    await api('/api/auth/logout', { method: 'POST' });
    toast('Signed out', 'info');
  } finally {
    location.reload();
  }
});

// Mobile menu toggle
const mobileToggle = $('mobile-toggle');
if (mobileToggle) {
  mobileToggle.addEventListener('click', () => {
    $('sidebar').classList.toggle('mobile-open');
  });
}

// Navigation
document.querySelectorAll('.nav-btn').forEach(b => {
  b.addEventListener('click', () => {
    switchView(b.dataset.view);
    if ($('sidebar')) $('sidebar').classList.remove('mobile-open');
  });
});
>>>>>>> origin/main

function switchView(v) {
  S.view = v;
  document.querySelectorAll('.view').forEach(x => x.classList.add('hidden'));
<<<<<<< HEAD
  const target = $(v);
  if (target) target.classList.remove('hidden');
  document.querySelectorAll('.nav').forEach(x => x.classList.toggle('active', x.dataset.view === v));

  const titles = {
    overview: ['CONTROL PLANE', 'Command Center'],
    fleet: ['SERVER INVENTORY', 'Managed Systems'],
    patches: ['VULNERABILITY & PATCH CENTER', 'Fleet Patch Assessment'],
    policies: ['CONFIGURATION MANAGEMENT', 'Desired State Policies'],
    compliance: ['COMPLIANCE & AUDITING', 'Baselines & SCAP Reports'],
    hardware: ['HARDWARE & BMC', 'Redfish / IPMI Nodes'],
    provisioning: ['BARE-METAL PROVISIONING', 'OS Installation Profiles'],
    rollouts: ['STAGED DEPLOYMENTS', 'Rollout Canary Rings'],
    approvals: ['CHANGE CONTROL', 'Pending Approvals Queue'],
    maintenance: ['CHANGE WINDOWS', 'Maintenance Windows'],
    audit: ['ACCOUNTABILITY', 'Audit Trail Log']
  };
  const t = titles[v] || ['CONTROL PLANE', 'Dashboard'];
  $('kicker').textContent = t[0];
  $('title').textContent = t[1];

  const loaders = {
    overview: loadOverview,
    fleet: loadFleet,
    patches: loadPatches,
    policies: loadPolicies,
    compliance: loadCompliance,
    hardware: loadBMC,
    provisioning: loadProvisioning,
    rollouts: loadRollouts,
    approvals: loadApprovals,
    maintenance: loadMaintenance,
    audit: loadAudit
  };
  if (loaders[v]) loaders[v]();
}

async function loadOverview() {
  const [sum, servers] = await Promise.all([api('/api/summary'), api('/api/servers')]);
  S.servers = servers;
  $('servers').textContent = sum.servers;
  $('online').textContent = sum.online;
  $('warning').textContent = sum.warning;
  $('pending').textContent = sum.pending_approvals;
  $('window').textContent = sum.maintenance_window ? 'Active Maintenance Window' : 'No Active Maintenance Window';
  $('fleet-table').innerHTML = servers.map(row).join('') || `<tr><td colspan="8" class="sub">No servers registered.</td></tr>`;
}

function row(s) {
  return `<tr>
    <td><div class="name"><a href="#" onclick="showServerDetail('${s.id}'); return false;">${esc(s.name)}</a></div><div class="sub">${esc(s.hostname)}</div></td>
    <td>${esc(s.platform)} · ${esc(s.arch)}</td>
    <td><span class="state"><i class="dot ${s.status}"></i>${esc(s.status)}</span></td>
    <td>${pct(s.cpu)}</td>
    <td>${pct(s.memory)}</td>
    <td>${pct(s.disk)}</td>
    <td>${time(s.last_seen)}</td>
    <td>
      <button class="ghost" onclick="queueAction('${s.id}','collect_diagnostics')">Diagnostics</button>
      <button class="ghost" onclick="queueAction('${s.id}','reboot')">Reboot</button>
    </td>
  </tr>`;
}

async function loadFleet() {
  S.servers = await api('/api/servers');
  renderFleet();
}

function renderFleet() {
  const q = ($('search').value || '').toLowerCase();
  const list = S.servers.filter(s => `${s.name} ${s.hostname} ${s.platform}`.toLowerCase().includes(q));
  $('cards').innerHTML = list.map(card).join('') || `<div class="sub">No matching servers.</div>`;
}

function card(s) {
  return `<article class="card">
    <div class="card-head">
      <div>
        <div class="name"><a href="#" onclick="showServerDetail('${s.id}'); return false;">${esc(s.name)}</a></div>
        <div class="sub">${esc(s.hostname)} · ${esc(s.platform)} ${esc(s.arch)}</div>
      </div>
      <span class="state"><i class="dot ${s.status}"></i>${esc(s.status)}</span>
    </div>
    <div class="util">
      <div><span>CPU</span><b>${pct(s.cpu)}</b></div>
      <div><span>Memory</span><b>${pct(s.memory)}</b></div>
      <div><span>Disk</span><b>${pct(s.disk)}</b></div>
    </div>
    <div class="actions">
      <button class="ghost" onclick="queueAction('${s.id}','assess_patches')">Patch Assessment</button>
      <button class="ghost" onclick="queueAction('${s.id}','collect_diagnostics')">Diagnostics</button>
      <button class="ghost" onclick="queueAction('${s.id}','reboot')">Reboot</button>
    </div>
  </article>`;
}

async function showServerDetail(id) {
  const srv = S.servers.find(s => s.id === id) || (await api('/api/servers')).find(s => s.id === id);
  if (!srv) return;
  S.selectedServer = srv;
  switchView('server-detail');
  $('sd-hostname').textContent = srv.hostname.toUpperCase();
  $('sd-title').textContent = `${srv.name} Workspace`;

  $('sd-summary').innerHTML = `
    <div class="metrics" style="margin-bottom:24px;">
      <div><span>Platform</span><b>${esc(srv.platform)}</b><small>${esc(srv.arch)}</small></div>
      <div><span>CPU Usage</span><b>${pct(srv.cpu)}</b><small>Core Utilization</small></div>
      <div><span>Memory Usage</span><b>${pct(srv.memory)}</b><small>RAM Utilization</small></div>
      <div><span>Disk Usage</span><b>${pct(srv.disk)}</b><small>Primary Storage</small></div>
    </div>
    <div class="actions">
      <button class="primary" onclick="queueAction('${srv.id}','assess_patches')">Run Patch Check</button>
      <button class="secondary" onclick="queueAction('${srv.id}','collect_diagnostics')">Collect Diagnostics</button>
      <button class="ghost" onclick="queueAction('${srv.id}','reboot')">Reboot System</button>
=======
  $(v).classList.remove('hidden');
  document.querySelectorAll('.nav-btn').forEach(x => x.classList.toggle('active', x.dataset.view === v));

  const titleMap = {
    overview: ['CONTROL PLANE', 'Fleet Overview'],
    fleet: ['SERVER INVENTORY', 'Managed Servers'],
    operations: ['OPERATIONAL HISTORY', 'Lifecycle Operations'],
    approvals: ['CHANGE GOVERNANCE', 'Pending Approvals'],
    audit: ['SECURITY LOG', 'Audit Trail']
  }[v];

  $('kicker').textContent = titleMap[0];
  $('title').textContent = titleMap[1];

  ({
    overview: loadOverview,
    fleet: loadFleet,
    operations: loadJobs,
    approvals: loadApprovals,
    audit: loadAudit
  }[v])();
}

// Rendering telemetry bar
function renderTelemetryBar(label, value) {
  const num = Math.round(Number(value || 0));
  let statusClass = 'normal';
  if (num >= 90) statusClass = 'critical';
  else if (num >= 70) statusClass = 'warning';

  return `
    <div class="telemetry-cell">
      <div class="telemetry-header">
        <span>${label}</span>
        <span>${num}%</span>
      </div>
      <div class="telemetry-bar-bg">
        <div class="telemetry-bar-fill ${statusClass}" style="width: ${num}%"></div>
      </div>
>>>>>>> origin/main
    </div>
  `;
}

<<<<<<< HEAD
async function loadPatches() {
  const cves = await api('/api/vulnerabilities/cves');
  $('cve-table').innerHTML = cves.map(c => `<tr>
    <td><span class="badge red">${esc(c.cve_id)}</span></td>
    <td><div class="name">${esc(c.title)}</div></td>
    <td><span class="badge ${c.severity==='CRITICAL'||c.severity==='HIGH'?'red':'amber'}">${esc(c.severity)}</span></td>
    <td><b>${c.cvss_score}</b></td>
    <td>${esc(JSON.stringify(c.affected_packages))}</td>
    <td>${time(c.published_at)}</td>
  </tr>`).join('') || `<tr><td colspan="6" class="sub">No vulnerabilities ingested.</td></tr>`;
}

async function loadPolicies() {
  const [pols, drift] = await Promise.all([api('/api/policies'), api('/api/policies/drift')]);
  $('policies-table').innerHTML = pols.map(p => `<tr>
    <td><div class="name">${esc(p.name)}</div></td>
    <td><span class="badge cyan">${esc(p.kind)}</span></td>
    <td>${esc(p.target_scope)}</td>
    <td>${esc(p.remediation_behavior)}</td>
    <td>v${p.version}</td>
    <td>${time(p.created_at)}</td>
  </tr>`).join('') || `<tr><td colspan="6" class="sub">No policies created.</td></tr>`;

  $('drift-table').innerHTML = drift.map(d => `<tr>
    <td>${esc(d.server_name)}</td>
    <td>${esc(d.policy_name)}</td>
    <td><span class="badge cyan">${esc(d.resource_type)}</span></td>
    <td><span class="badge ${d.status==='compliant'?'green':'red'}">${esc(d.status)}</span></td>
    <td><small>${esc(d.difference)}</small></td>
    <td>${time(d.last_evaluated)}</td>
  </tr>`).join('') || `<tr><td colspan="6" class="sub">No drift records logged.</td></tr>`;
}

async function loadCompliance() {
  const [bases, reports] = await Promise.all([api('/api/compliance/baselines'), api('/api/compliance/reports')]);
  $('baselines-table').innerHTML = bases.map(b => `<tr>
    <td><div class="name">${esc(b.name)}</div></td>
    <td><span class="badge cyan">${esc(b.framework)}</span></td>
    <td>${esc(b.description)}</td>
    <td>${time(b.created_at)}</td>
  </tr>`).join('') || `<tr><td colspan="4" class="sub">No baselines defined.</td></tr>`;

  $('compliance-reports-table').innerHTML = reports.map(r => `<tr>
    <td>${esc(r.server_name)}</td>
    <td>${esc(r.baseline_name)} (${esc(r.framework)})</td>
    <td><b>${pct(r.score)}</b></td>
    <td><span class="badge ${r.status==='passed'?'green':'red'}">${esc(r.status)}</span></td>
    <td>${time(r.evaluated_at)}</td>
  </tr>`).join('') || `<tr><td colspan="5" class="sub">No evaluation results.</td></tr>`;
}

async function loadBMC() {
  const nodes = await api('/api/hardware/bmc');
  $('bmc-table').innerHTML = nodes.map(b => `<tr>
    <td><div class="name">${esc(b.name)}</div></td>
    <td>${esc(b.address)}</td>
    <td><span class="badge cyan">${esc(b.bmc_type)}</span></td>
    <td>${esc(b.username)}</td>
    <td><span class="badge ${b.power_state==='On'?'green':'red'}">${esc(b.power_state)}</span></td>
    <td>${esc(b.health_status)}</td>
    <td>
      <button class="ghost" onclick="bmcPower('${b.id}','on')">Power On</button>
      <button class="ghost" onclick="bmcPower('${b.id}','off')">Power Off</button>
    </td>
  </tr>`).join('') || `<tr><td colspan="7" class="sub">No BMC nodes registered.</td></tr>`;
}

async function bmcPower(id, action) {
  try {
    await api(`/api/hardware/bmc/${id}/power`, { method: 'POST', body: { action } });
    await loadBMC();
  } catch (err) {
    alert(err.message);
  }
}

async function loadProvisioning() {
  const profs = await api('/api/provisioning/profiles');
  $('profiles-table').innerHTML = profs.map(p => `<tr>
    <td><div class="name">${esc(p.name)}</div></td>
    <td><span class="badge cyan">${esc(p.os_family)}</span></td>
    <td><small>${esc(p.image_url)}</small></td>
    <td>${time(p.created_at)}</td>
  </tr>`).join('') || `<tr><td colspan="4" class="sub">No installation profiles.</td></tr>`;
}

async function loadRollouts() {
  const rings = await api('/api/rollouts/rings');
  $('rings-table').innerHTML = rings.map(r => `<tr>
    <td><div class="name">${esc(r.name)}</div></td>
    <td><b>Ring ${r.ring_order}</b></td>
    <td>${esc(r.target_group)}</td>
    <td>${r.max_concurrency}</td>
    <td>${pct(r.failure_threshold_pct)}</td>
    <td>
      <button class="ghost" onclick="promoteRing('${r.id}')">Promote</button>
    </td>
  </tr>`).join('') || `<tr><td colspan="6" class="sub">No rollout rings created.</td></tr>`;
}

async function promoteRing(id) {
  try {
    const res = await api(`/api/rollouts/promote/${id}`, { method: 'POST' });
    alert(`Promoted ring. Next ring target: ${res.next_ring}`);
  } catch (e) {
    alert(e.message);
  }
}

async function loadApprovals() {
  const r = await api('/api/approvals');
  $('approval-list').innerHTML = r.map(a => `<div class="approval">
    <div>
      <h4>${esc(a.action)} · Host ${esc(a.server_id)}</h4>
      <div class="meta">Requested ${time(a.created_at)} · Job ID ${esc(a.job_id)}</div>
    </div>
    <button class="primary" onclick="approve('${a.id}')">Approve Request</button>
  </div>`).join('') || `<div class="sub">No pending approvals queue.</div>`;
}

async function approve(id) {
  try {
    await api(`/api/approvals/${id}/approve`, { method: 'POST' });
    await loadApprovals();
    await loadOverview();
  } catch (e) {
    alert(e.message);
  }
}

async function loadMaintenance() {
  const mws = await api('/api/maintenance-windows');
  $('mw-table').innerHTML = mws.map(m => `<tr>
    <td><div class="name">${esc(m.name)}</div></td>
    <td>${time(m.starts_at)}</td>
    <td>${time(m.ends_at)}</td>
    <td><span class="badge cyan">${esc(m.schedule_type)}</span></td>
    <td><span class="badge ${m.is_blackout?'red':'green'}">${m.is_blackout?'Blackout':'Window'}</span></td>
    <td><button class="ghost" onclick="deleteMW('${m.id}')">Delete</button></td>
  </tr>`).join('') || `<tr><td colspan="6" class="sub">No maintenance windows.</td></tr>`;
}

async function deleteMW(id) {
  try {
    await api(`/api/maintenance-windows/${id}`, { method: 'DELETE' });
    await loadMaintenance();
  } catch (e) {
    alert(e.message);
  }
}

async function loadAudit() {
  const r = await api('/api/audit');
  $('audit-table').innerHTML = r.map(a => `<tr>
    <td>${time(a.created_at)}</td>
    <td><b>${esc(a.actor)}</b></td>
    <td><span class="badge cyan">${esc(a.action)}</span></td>
    <td>${esc(a.target)}</td>
    <td><span class="badge ${a.result==='success'?'green':'red'}">${esc(a.result)}</span></td>
  </tr>`).join('') || `<tr><td colspan="5" class="sub">No audit events recorded.</td></tr>`;
}

window.queueAction = (id, action) => {
  S.pending = { id, action };
  $('action-title').textContent = action.replaceAll('_', ' ').toUpperCase();
  $('service-label').classList.toggle('hidden', !action.startsWith('service_'));
  $('package-label').classList.toggle('hidden', !action.startsWith('package_'));
=======
// Render server status dot/pill
function renderStatusPill(status) {
  const label = esc(status);
  return `<span class="status-pill"><i class="dot ${status}"></i>${label}</span>`;
}

// Overview Loader
async function loadOverview() {
  try {
    const [sum, servers] = await Promise.all([api('/api/summary'), api('/api/servers')]);
    S.servers = servers;
    $('servers').textContent = sum.servers;
    $('online').textContent = sum.online;
    $('warning').textContent = sum.warning;
    $('pending').textContent = sum.pending_approvals;

    const windowEl = $('window');
    if (sum.maintenance_window) {
      windowEl.textContent = 'Maintenance Window: Active';
      windowEl.style.color = 'var(--green)';
    } else {
      windowEl.textContent = 'Maintenance Window: Inactive';
      windowEl.style.color = 'var(--text-muted)';
    }

    $('fleet-table').innerHTML = servers.map(overviewRow).join('') || `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding: 20px;">No registered servers in fleet.</td></tr>`;
  } catch (err) {
    toast(`Failed to load overview: ${err.message}`, 'error');
  }
}

function overviewRow(s) {
  return `
    <tr>
      <td>
        <div class="cell-primary">${esc(s.name)}</div>
        <div class="cell-sub">${esc(s.hostname)}</div>
      </td>
      <td>
        <span class="badge badge-neutral">${esc(s.platform)}</span>
        <span class="cell-sub" style="margin-left: 4px;">${esc(s.arch)}</span>
      </td>
      <td>${renderStatusPill(s.status)}</td>
      <td>${renderTelemetryBar('CPU', s.cpu)}</td>
      <td>${renderTelemetryBar('RAM', s.memory)}</td>
      <td>${renderTelemetryBar('DISK', s.disk)}</td>
      <td>
        <span class="tabular">${time(s.last_seen)}</span>
      </td>
    </tr>
  `;
}

// Fleet Loader
async function loadFleet() {
  try {
    S.servers = await api('/api/servers');
    renderFleet();
  } catch (err) {
    toast(`Failed to load server inventory: ${err.message}`, 'error');
  }
}

function renderFleet() {
  const q = ($('search').value || '').toLowerCase();
  const list = S.servers.filter(s => `${s.name} ${s.hostname} ${s.platform} ${s.os_version}`.toLowerCase().includes(q));

  $('cards').innerHTML = list.map(serverCard).join('') || `<div style="grid-column: 1/-1; color: var(--text-muted); padding: 24px 0;">No servers match search criteria.</div>`;
}

function serverCard(s) {
  return `
    <article class="server-card">
      <div class="server-card-head">
        <div class="server-identity">
          <h4>${esc(s.name)}</h4>
          <div class="server-meta">${esc(s.hostname)} • ${esc(s.platform)} ${esc(s.arch)}</div>
          <div class="cell-sub" style="margin-top:2px;">${esc(s.os_version || 'Generic OS')}</div>
        </div>
        ${renderStatusPill(s.status)}
      </div>

      <div class="server-metrics-group">
        <div class="server-metric-item">
          <span>CPU</span>
          <b>${pct(s.cpu)}</b>
        </div>
        <div class="server-metric-item">
          <span>MEM</span>
          <b>${pct(s.memory)}</b>
        </div>
        <div class="server-metric-item">
          <span>DISK</span>
          <b>${pct(s.disk)}</b>
        </div>
      </div>

      <div class="card-actions">
        <button class="ghost" style="font-size:11px;" onclick="queue('${s.id}','assess_patches')">Patch Check</button>
        <button class="ghost" style="font-size:11px;" onclick="queue('${s.id}','collect_diagnostics')">Diagnostics</button>
        <button class="ghost" style="font-size:11px;" onclick="queue('${s.id}','service_restart')">Restart Service</button>
        <button class="destructive" style="font-size:11px;" onclick="queue('${s.id}','reboot')">Reboot</button>
      </div>

      <div class="server-card-footer">
        <span>Uptime: <span class="tabular">${Math.floor((s.uptime || 0) / 3600)}h</span></span>
        <span>Seen: <span class="tabular">${time(s.last_seen)}</span></span>
      </div>
    </article>
  `;
}

// Operations Loader
async function loadJobs() {
  try {
    S.jobs = await api('/api/jobs');
    $('jobs').innerHTML = S.jobs.map(jobRow).join('') || `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding: 20px;">No operational jobs recorded.</td></tr>`;
  } catch (err) {
    toast(`Failed to load operations log: ${err.message}`, 'error');
  }
}

function jobRow(j) {
  const targetServer = S.servers.find(s => s.id === j.server_id);
  const serverName = targetServer ? targetServer.name : j.server_id;
  const statusBadge = j.status === 'succeeded' ? 'badge-green' : (j.status === 'failed' ? 'badge-red' : 'badge-amber');
  const resultStr = JSON.stringify(j.result || {}, null, 2);

  return `
    <tr>
      <td class="cell-primary">${esc(j.action.replaceAll('_', ' '))}</td>
      <td>
        <div>${esc(serverName)}</div>
        <div class="cell-sub tabular">${esc(j.server_id)}</div>
      </td>
      <td><span class="badge ${statusBadge}">${esc(j.status.toUpperCase())}</span></td>
      <td>${j.requires_approval ? '<span class="badge badge-amber">GATE REQUIRED</span>' : '<span class="badge badge-neutral">DIRECT</span>'}</td>
      <td class="tabular">${time(j.created_at)}</td>
      <td>
        <button class="ghost" style="height:26px; font-size:11px; padding:0 8px;" onclick="inspectResult('${esc(j.action)}', ${esc(JSON.stringify(resultStr))})">
          Inspect Result
        </button>
      </td>
    </tr>
  `;
}

window.inspectResult = (title, jsonStr) => {
  $('inspect-title').textContent = `${title} Output`;
  $('inspect-code').textContent = jsonStr;
  $('inspect-modal').classList.remove('hidden');
};

// Approvals Loader
async function loadApprovals() {
  try {
    const r = await api('/api/approvals');
    $('approval-list').innerHTML = r.map(approvalCard).join('') || `<div style="color:var(--text-muted); padding:20px 0;">No change operations currently pending approval.</div>`;
  } catch (err) {
    toast(`Failed to load approvals: ${err.message}`, 'error');
  }
}

function approvalCard(a) {
  const targetServer = S.servers.find(s => s.id === a.server_id);
  const serverName = targetServer ? targetServer.name : a.server_id;

  return `
    <div class="approval-card">
      <div class="approval-info">
        <h4>
          <span>${esc(a.action.replaceAll('_', ' '))}</span>
          <span class="badge badge-amber">HIGH IMPACT</span>
        </h4>
        <div class="approval-meta">
          Target: <strong style="color:var(--text-primary);">${esc(serverName)}</strong> • Requested: <span class="tabular">${time(a.created_at)}</span>
        </div>
        <div class="cell-sub tabular">Job ID: ${esc(a.job_id)}</div>
      </div>
      <div style="display:flex; gap:8px;">
        <button class="primary" onclick="approve(${a.id})">Grant Approval</button>
      </div>
    </div>
  `;
}

// Audit Loader
async function loadAudit() {
  try {
    const r = await api('/api/audit');
    $('audit-table').innerHTML = r.map(auditRow).join('') || `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding: 20px;">No audit events found.</td></tr>`;
  } catch (err) {
    toast(`Failed to load audit logs: ${err.message}`, 'error');
  }
}

function auditRow(a) {
  const resultBadge = a.result === 'success' ? 'badge-green' : 'badge-red';
  return `
    <tr>
      <td class="tabular">${time(a.created_at)}</td>
      <td class="cell-primary">${esc(a.actor)}</td>
      <td><span class="mono" style="font-size:11px;">${esc(a.action)}</span></td>
      <td><span class="cell-sub mono">${esc(a.target)}</span></td>
      <td><span class="badge ${resultBadge}">${esc(a.result.toUpperCase())}</span></td>
    </tr>
  `;
}

// Action Queueing
window.queue = (id, action) => {
  S.pending = { id, action };
  $('action-title').textContent = action.replaceAll('_', ' ').toUpperCase();
  $('action-copy').textContent = `Review parameters before submitting "${action}" operation to target host.`;
  $('service-label').classList.toggle('hidden', !action.startsWith('service_'));
  $('service').value = '';
>>>>>>> origin/main
  $('action').classList.remove('hidden');
};

window.submitAction = async () => {
  const p = S.pending;
  if (!p) return;
<<<<<<< HEAD
  const params = {};
  if (p.action.startsWith('service_')) params.service = $('service').value.trim();
  if (p.action.startsWith('package_')) params.package = $('package').value.trim();
  try {
    await api(`/api/servers/${p.id}/jobs`, { method: 'POST', body: { action: p.action, params } });
    $('action').classList.add('hidden');
    S.pending = null;
    await loadOverview();
  } catch (e) {
    alert(e.message);
  }
};

$('search').addEventListener('input', renderFleet);
$('confirm-action').addEventListener('click', submitAction);
document.querySelectorAll('[data-close="action"]').forEach(x => x.addEventListener('click', () => $('action').classList.add('hidden')));
$('refresh').addEventListener('click', loadOverview);
$('refresh-patches').addEventListener('click', loadPatches);
$('refresh-approvals').addEventListener('click', loadApprovals);
$('refresh-audit').addEventListener('click', loadAudit);
$('add').addEventListener('click', () => { $('enroll').classList.remove('hidden'); $('token-box').classList.add('hidden'); });
document.querySelectorAll('[data-close="enroll"]').forEach(x => x.addEventListener('click', () => $('enroll').classList.add('hidden')));
=======
  const params = p.action.startsWith('service_') ? { service: $('service').value.trim() } : {};
  try {
    const res = await api(`/api/servers/${p.id}/jobs`, {
      method: 'POST',
      body: { action: p.action, params }
    });
    $('action').classList.add('hidden');
    S.pending = null;

    if (res.requires_approval) {
      toast('Operation queued: Approval gate required', 'info');
    } else {
      toast('Operation successfully queued for execution', 'success');
    }

    await loadOverview();
    if (S.view === 'operations') await loadJobs();
  } catch (e) {
    toast(e.message, 'error');
  }
};

window.approve = async id => {
  try {
    await api(`/api/approvals/${id}/approve`, { method: 'POST' });
    toast('Change operation approved', 'success');
    await loadApprovals();
    await loadOverview();
  } catch (e) {
    toast(e.message, 'error');
  }
};

// Global Event Listeners & Binding
$('search').addEventListener('input', renderFleet);
$('confirm-action').addEventListener('click', submitAction);

document.querySelectorAll('[data-close]').forEach(btn => {
  btn.addEventListener('click', () => {
    const targetId = btn.dataset.close;
    if ($(targetId)) $(targetId).classList.add('hidden');
  });
});

// Escape key listener for modals
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
  }
});

$('refresh').addEventListener('click', () => { loadOverview(); toast('Refreshed fleet status', 'info'); });
$('refresh-jobs').addEventListener('click', () => { loadJobs(); toast('Refreshed operations log', 'info'); });
$('refresh-approvals').addEventListener('click', () => { loadApprovals(); toast('Refreshed pending approvals', 'info'); });
$('refresh-audit').addEventListener('click', () => { loadAudit(); toast('Refreshed audit trail', 'info'); });

$('add').addEventListener('click', () => {
  $('enroll').classList.remove('hidden');
  $('token-box').classList.add('hidden');
});
>>>>>>> origin/main

$('generate').addEventListener('click', async () => {
  try {
    const r = await api('/api/enrollment-tokens', { method: 'POST' });
    $('token').textContent = r.token;
    $('expiry').textContent = `Expires ${time(r.expires_at)}`;
    $('token-box').classList.remove('hidden');
<<<<<<< HEAD
  } catch (e) {
    alert(e.message);
  }
});

=======
    toast('Generated new enrollment token', 'success');
  } catch (e) {
    toast(e.message, 'error');
  }
});

// Boot app
>>>>>>> origin/main
boot();
