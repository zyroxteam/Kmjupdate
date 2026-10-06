/* KMJ TIPS admin panel app logic */
const $ = (id) => document.getElementById(id);
const token = () => sessionStorage.getItem('kmj_token');

function toast(msg, type) {
  const t = document.createElement('div');
  t.className = 'toast ' + (type || '');
  t.textContent = msg;
  $('toasts').appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 320); }, 3200);
}

async function api(path, method, body) {
  const r = await fetch(path, {
    method: method || 'GET',
    headers: Object.assign(
      { 'Authorization': 'Bearer ' + token() },
      body ? { 'Content-Type': 'application/json' } : {}
    ),
    body: body ? JSON.stringify(body) : undefined
  });
  if (r.status === 401) { sessionStorage.clear(); location.href = '/login.html'; throw new Error('Session expired'); }
  const j = await r.json().catch(() => ({}));
  if (!j.ok) throw new Error(j.error || 'Request failed');
  return j;
}

function fmtDate(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleDateString() + ' ' + new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
function expText(ts) {
  if (!ts) return '<span class="badge active">lifetime</span>';
  return Date.now() > ts ? '<span class="badge expired">expired</span>' : fmtDate(ts);
}

/* ---------- navigation ---------- */
const TITLES = {
  dashboard: ['Dashboard', 'Overview of keys & app updates'],
  keys: ['Activation Keys', 'Generate, verify lifecycle, revoke & export'],
  updates: ['App Updates', 'Publish releases the Android SDK will pick up'],
  settings: ['Settings', 'Panel preferences & security']
};
document.querySelectorAll('.nav-link[data-view]').forEach((btn) => {
  btn.onclick = () => {
    document.querySelectorAll('.nav-link[data-view]').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    const v = btn.dataset.view;
    ['dashboard', 'keys', 'updates', 'settings'].forEach((k) => {
      $('view-' + k).style.display = k === v ? 'block' : 'none';
    });
    $('viewTitle').textContent = TITLES[v][0];
    $('viewSub').textContent = TITLES[v][1];
    $('sidebar').classList.remove('open');
    $('scrim').classList.remove('show');
    if (v === 'dashboard') loadDashboard();
    if (v === 'keys') loadKeys();
    if (v === 'updates') loadUpdateForm();
  };
});
$('hamburger').onclick = () => { $('sidebar').classList.add('open'); $('scrim').classList.add('show'); };
$('scrim').onclick = () => { $('sidebar').classList.remove('open'); $('scrim').classList.remove('show'); };
$('logoutBtn').onclick = () => { sessionStorage.clear(); location.href = '/login.html'; };
$('userLabel').textContent = sessionStorage.getItem('kmj_user') || 'admin';

function syncThemeBtn() {
  const dark = document.documentElement.getAttribute('data-theme') === 'dark';
  $('themeLabel').textContent = dark ? 'Light Mode' : 'Dark Mode';
  $('themeToggle').querySelector('.ico').textContent = dark ? '☀️' : '🌙';
}
$('themeToggle').onclick = () => {
  const dark = document.documentElement.getAttribute('data-theme') === 'dark';
  document.documentElement.setAttribute('data-theme', dark ? '' : 'dark');
  try { localStorage.setItem('kmj_theme', dark ? 'light' : 'dark'); } catch (e) {}
  syncThemeBtn();
};
syncThemeBtn();

/* ---------- dashboard ---------- */
let chart = null;
async function loadDashboard() {
  try {
    const j = await api('/api/admin/stats');
    const k = j.keys;
    const cards = [
      ['c-purple', '🔑', k.total, 'Total Keys'],
      ['c-green', '✅', k.active, 'Active Keys'],
      ['c-blue', '📱', k.used, 'Used Keys'],
      ['c-amber', '⌛', k.expired, 'Expired Keys'],
      ['c-red', '🚫', k.revoked, 'Revoked Keys'],
      ['c-green', '📦', 'v' + j.current_version.version_name, 'Current Version (' + j.current_version.version_code + ')']
    ];
    $('statGrid').innerHTML = cards.map((c) =>
      `<div class="stat-card glass ${c[0]}"><div class="stat-ico">${c[1]}</div><div class="stat-num">${c[2]}</div><div class="stat-label">${c[3]}</div></div>`
    ).join('');

    $('versionCard').innerHTML =
      `<div style="display:flex;align-items:center;gap:12px">
        <div class="logo" style="width:52px;height:52px;font-size:22px">📦</div>
        <div><div style="font-size:20px;font-weight:800">v${j.current_version.version_name}</div>
        <div style="color:var(--muted);font-size:13px">versionCode ${j.current_version.version_code}
        ${j.current_version.force_update ? ' • <span class="badge revoked">force update</span>' : ''}</div></div>
      </div>`;

    const dots = { created: '#4f46e5', verified: '#16a34a', revoked: '#dc2626' };
    $('recentList').innerHTML = j.recent_activity.length ? j.recent_activity.map((e) =>
      `<div class="activity-item"><span class="dot" style="background:${dots[e.event] || '#64748b'}"></span>
       <span><b>${e.event}</b> <span class="key-mono">${e.key.slice(0, 18)}…</span></span>
       <small>${fmtDate(e.created_at)}</small></div>`
    ).join('') : '<div class="empty">No activity yet.</div>';

    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    const gridColor = dark ? 'rgba(255,255,255,.08)' : 'rgba(15,23,42,.08)';
    const tickColor = dark ? '#94a3b8' : '#64748b';
    if (chart) chart.destroy();
    chart = new Chart($('activityChart'), {
      type: 'bar',
      data: {
        labels: j.chart.days,
        datasets: [
          { label: 'Created', data: j.chart.created, backgroundColor: '#4f46e5', borderRadius: 5 },
          { label: 'Verified', data: j.chart.verified, backgroundColor: '#16a34a', borderRadius: 5 }
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: true,
        plugins: { legend: { labels: { color: tickColor, boxWidth: 12 } } },
        scales: {
          x: { ticks: { color: tickColor, maxTicksLimit: 7 }, grid: { display: false } },
          y: { beginAtZero: true, ticks: { color: tickColor, precision: 0 }, grid: { color: gridColor } }
        }
      }
    });
  } catch (e) { toast(e.message, 'err'); }
}

/* ---------- keys ---------- */
let keyPage = 0;
const PAGE_SIZE = 20;
async function loadKeys() {
  try {
    const q = encodeURIComponent($('keySearch').value.trim());
    const st = $('keyFilter').value;
    const j = await api(`/api/admin/keys?limit=${PAGE_SIZE}&offset=${keyPage * PAGE_SIZE}&q=${q}&status=${st}`);
    $('keyEmpty').style.display = j.keys.length ? 'none' : 'block';
    $('keyRows').innerHTML = j.keys.map((r) =>
      `<tr>
        <td><span class="key-mono">${r.key}</span>
          <button class="btn ghost small" style="margin-left:6px" onclick="copyKey('${r.key}')">📋</button></td>
        <td>${escapeHtml(r.label) || '<span style="color:var(--muted)">—</span>'}</td>
        <td><span class="badge ${r.status}">${r.status}</span>${r.single_use ? ' <span title="Single-use">🔒</span>' : ''}</td>
        <td style="white-space:nowrap">${expText(r.expires_at)}</td>
        <td>${r.use_count}</td>
        <td style="white-space:nowrap">${fmtDate(r.created_at)}</td>
        <td><div class="row-actions">
          ${r.status !== 'revoked' ? `<button class="btn ghost small" onclick="revokeKey(${r.id})">Revoke</button>` : ''}
          <button class="btn danger small" onclick="deleteKey(${r.id})">Delete</button>
        </div></td>
      </tr>`
    ).join('');
    const pages = Math.max(1, Math.ceil(j.total / PAGE_SIZE));
    $('pageInfo').textContent = `Page ${keyPage + 1} of ${pages} (${j.total} keys)`;
    $('prevPage').disabled = keyPage === 0;
    $('nextPage').disabled = keyPage + 1 >= pages;
  } catch (e) { toast(e.message, 'err'); }
}
function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
window.copyKey = (k) => {
  (navigator.clipboard ? navigator.clipboard.writeText(k) : Promise.reject())
    .then(() => toast('Key copied', 'ok'))
    .catch(() => { prompt('Copy key:', k); });
};
window.revokeKey = async (id) => {
  if (!confirm('Revoke this key? Devices will fail verification immediately.')) return;
  try { await api('/api/admin/keys/' + id + '/revoke', 'POST'); toast('Key revoked', 'ok'); loadKeys(); }
  catch (e) { toast(e.message, 'err'); }
};
window.deleteKey = async (id) => {
  if (!confirm('Delete this key permanently?')) return;
  try { await api('/api/admin/keys/' + id, 'DELETE'); toast('Key deleted', 'ok'); loadKeys(); }
  catch (e) { toast(e.message, 'err'); }
};
let searchTimer = null;
$('keySearch').oninput = () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { keyPage = 0; loadKeys(); }, 350); };
$('keyFilter').onchange = () => { keyPage = 0; loadKeys(); };
$('prevPage').onclick = () => { if (keyPage > 0) { keyPage--; loadKeys(); } };
$('nextPage').onclick = () => { keyPage++; loadKeys(); };
$('exportBtn').onclick = async () => {
  try {
    const r = await fetch('/api/admin/keys/export', { headers: { 'Authorization': 'Bearer ' + token() } });
    if (!r.ok) throw new Error('Export failed');
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'kmj-keys-export.csv';
    a.click();
    URL.revokeObjectURL(a.href);
    toast('Exported', 'ok');
  } catch (e) { toast(e.message, 'err'); }
};

/* generate modal */
$('genBtn').onclick = () => { $('genResult').innerHTML = ''; $('genModal').classList.add('open'); };
$('genCancel').onclick = () => $('genModal').classList.remove('open');
$('genModal').addEventListener('click', (e) => { if (e.target === $('genModal')) $('genModal').classList.remove('open'); });
$('genConfirm').onclick = async () => {
  const btn = $('genConfirm'); btn.disabled = true;
  try {
    const exp = $('g_expiry').value;
    const j = await api('/api/admin/keys', 'POST', {
      prefix: $('g_prefix').value,
      label: $('g_label').value,
      count: parseInt($('g_count').value, 10) || 1,
      expiry_days: exp === 'lifetime' ? null : parseInt(exp, 10),
      single_use: $('g_single').checked
    });
    $('genResult').innerHTML = j.keys.map((k) =>
      `<div style="display:flex;align-items:center;gap:8px;margin:6px 0">
        <span class="key-mono" style="flex:1">${k.key}</span>
        <button class="btn ghost small" onclick="copyKey('${k.key}')">📋 Copy</button>
      </div>`).join('');
    toast(j.generated + ' key(s) generated', 'ok');
    loadKeys();
  } catch (e) { toast(e.message, 'err'); }
  btn.disabled = false;
};

/* ---------- updates ---------- */
function updatePreviewJson() {
  const j = {
    latest_version: $('u_version_name').value || '1.0.0',
    version_code: parseInt($('u_version_code').value, 10) || 0,
    update_available: !!$('u_download_url').value.trim(),
    force_update: $('u_force').checked,
    title: $('u_title').value || 'New Update Available',
    changelog: $('u_changelog').value || 'Bug fixes and improvements',
    download_url: $('u_download_url').value
  };
  if ($('u_website_url').value.trim()) j.website_url = $('u_website_url').value.trim();
  $('updatePreview').textContent = JSON.stringify(j, null, 2);
}
['u_version_name', 'u_version_code', 'u_title', 'u_changelog', 'u_download_url', 'u_website_url'].forEach((id) => {
  $(id).addEventListener('input', updatePreviewJson);
});
$('u_force').addEventListener('change', updatePreviewJson);
async function loadUpdateForm() {
  try {
    const j = await api('/api/admin/update');
    const u = j.update;
    $('u_version_name').value = u.version_name;
    $('u_version_code').value = u.version_code;
    $('u_title').value = u.title;
    $('u_changelog').value = u.changelog;
    $('u_download_url').value = u.download_url;
    $('u_website_url').value = u.website_url || '';
    $('u_force').checked = u.force_update === 1;
    updatePreviewJson();
  } catch (e) { toast(e.message, 'err'); }
}
$('saveUpdateBtn').onclick = async () => {
  const btn = $('saveUpdateBtn'); btn.disabled = true;
  try {
    await api('/api/admin/update', 'PUT', {
      version_name: $('u_version_name').value.trim(),
      version_code: parseInt($('u_version_code').value, 10),
      title: $('u_title').value.trim(),
      changelog: $('u_changelog').value,
      download_url: $('u_download_url').value.trim(),
      website_url: $('u_website_url').value.trim(),
      force_update: $('u_force').checked
    });
    toast('Update published', 'ok');
  } catch (e) { toast(e.message, 'err'); }
  btn.disabled = false;
};
$('copyJsonBtn').onclick = () => {
  const t = $('updatePreview').textContent;
  (navigator.clipboard ? navigator.clipboard.writeText(t) : Promise.reject())
    .then(() => toast('JSON copied', 'ok'))
    .catch(() => prompt('Copy JSON:', t));
};

/* ---------- settings ---------- */
$('pwBtn').onclick = async () => {
  try {
    await api('/api/admin/change-password', 'POST', {
      current_password: $('pw_cur').value,
      new_password: $('pw_new').value
    });
    $('pw_cur').value = ''; $('pw_new').value = '';
    toast('Password changed', 'ok');
  } catch (e) { toast(e.message, 'err'); }
};

/* init */
loadDashboard();
