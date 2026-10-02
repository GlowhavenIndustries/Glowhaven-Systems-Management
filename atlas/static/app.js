const S = { view: 'overview', me: null, servers: [], jobs: [], selectedServer: null, sse: null };
const $ = id => document.getElementById(id);
const esc = v => String(v ?? '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
const pct = v => `${Math.round(Number(v || 0))}%`;
const time = v => v ? new Date(v).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Never';

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
  if (!r.ok) throw Error(p.detail || p.unsupported_reason || `Request failed (${r.status})`);
  return p;
}

async function boot() {
  try {
    S.me = await api('/api/me');
    $('login').classList.add('hidden');
    $('app').classList.remove('hidden');
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

$('login-form').addEventListener('submit', async e => {
  e.preventDefault();
  $('login-error').textContent = '';
  try {
    await api('/api/auth/login', { method: 'POST', body: { username: $('username').value, password: $('password').value } });
    boot();
  } catch (err) {
    $('login-error').textContent = err.message;
  }
});

$('logout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST' }); } finally { location.reload(); }
});

document.querySelectorAll('.nav').forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));

function switchView(v) {
  S.view = v;
  document.querySelectorAll('.view').forEach(x => x.classList.add('hidden'));
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
    </div>
  `;
}

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
  $('action').classList.remove('hidden');
};

window.submitAction = async () => {
  const p = S.pending;
  if (!p) return;
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

$('generate').addEventListener('click', async () => {
  try {
    const r = await api('/api/enrollment-tokens', { method: 'POST' });
    $('token').textContent = r.token;
    $('expiry').textContent = `Expires ${time(r.expires_at)}`;
    $('token-box').classList.remove('hidden');
  } catch (e) {
    alert(e.message);
  }
});

boot();
