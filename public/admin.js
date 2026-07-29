let token = sessionStorage.getItem('pf_admin_token') || '';
let licenses = [];
const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Erro HTTP ${response.status}`);
  return data;
}

$('loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('loginError').textContent = 'Entrando...';
  try {
    const data = await api('/api/login', { method: 'POST', body: JSON.stringify({ username: $('username').value.trim(), password: $('password').value }) });
    token = data.token;
    sessionStorage.setItem('pf_admin_token', token);
    await showDashboard();
  } catch (error) { $('loginError').textContent = error.message; }
});

async function showDashboard() {
  $('loginView').classList.add('hidden');
  $('dashboardView').classList.remove('hidden');
  await Promise.all([loadDashboard(), loadLicenses(), loadLogs()]);
}

async function loadDashboard() {
  const data = await api('/api/dashboard');
  $('totalKeys').textContent = data.totalKeys;
  $('activeKeys').textContent = data.active;
  $('expiredKeys').textContent = data.expired;
  $('blockedKeys').textContent = data.blocked;
}

async function loadLicenses() {
  licenses = await api('/api/licenses');
  renderLicenses();
}

function esc(value) { return String(value ?? '').replace(/[&<>'"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char])); }
function renderLicenses() {
  const search = $('search').value.trim().toLowerCase();
  const filtered = licenses.filter((l) => `${l.key} ${l.clientName}`.toLowerCase().includes(search));
  $('licensesBody').innerHTML = filtered.map((l) => `
    <tr>
      <td>${esc(l.clientName)}</td><td class="key">${esc(l.key)}</td>
      <td class="status ${l.status}-status">${esc(l.status.toUpperCase())}</td>
      <td>${l.daysRemaining}</td><td title="${esc(l.hwid || '')}">${l.hwid ? esc(l.hwid.slice(0,12)) + '…' : 'Não vinculado'}</td>
      <td>${l.lastLogin ? new Date(l.lastLogin).toLocaleString('pt-BR') : 'Nunca'}</td>
      <td class="actions">
        <button onclick="copyKey('${esc(l.key)}')">Copiar</button>
        <button onclick="renew('${esc(l.key)}')">Renovar</button>
        <button onclick="resetHwid('${esc(l.key)}')">Reset HWID</button>
        <button onclick="toggleBlock('${esc(l.key)}','${esc(l.status)}')">${l.status === 'blocked' ? 'Desbloquear' : 'Bloquear'}</button>
        <button onclick="removeKey('${esc(l.key)}')">Excluir</button>
      </td>
    </tr>`).join('') || '<tr><td colspan="7">Nenhuma licença encontrada.</td></tr>';
}

$('search').addEventListener('input', renderLicenses);
$('createKey').onclick = async () => {
  try {
    const payload = { clientName: $('clientName').value.trim() || 'Novo cliente', days: Number($('days').value || 30) };
    const custom = $('customKey').value.trim(); if (custom) payload.key = custom;
    const created = await api('/api/license/create', { method: 'POST', body: JSON.stringify(payload) });
    $('actionMessage').textContent = `Key criada: ${created.key}`;
    $('customKey').value = '';
    await Promise.all([loadDashboard(), loadLicenses(), loadLogs()]);
  } catch (error) { $('actionMessage').textContent = error.message; }
};
window.copyKey = async (key) => { await navigator.clipboard.writeText(key); $('actionMessage').textContent = 'Key copiada.'; };
window.renew = async (key) => { const days = Number(prompt('Adicionar quantos dias?', '30')); if (!days) return; await api('/api/license/renew', { method:'POST', body:JSON.stringify({key,days}) }); await refresh(); };
window.resetHwid = async (key) => { if (!confirm('Resetar o HWID desta Key?')) return; await api('/api/license/reset-hwid', { method:'POST', body:JSON.stringify({key}) }); await refresh(); };
window.toggleBlock = async (key,status) => { await api(`/license/${status === 'blocked' ? 'unblock' : 'block'}`, { method:'POST', body:JSON.stringify({key}) }); await refresh(); };
window.removeKey = async (key) => { if (!confirm('Excluir esta Key permanentemente?')) return; await api(`/license/${encodeURIComponent(key)}`, { method:'DELETE' }); await refresh(); };
async function refresh(){ await Promise.all([loadDashboard(),loadLicenses(),loadLogs()]); }

async function loadLogs() {
  const logs = await api('/api/logs');
  $('logsList').innerHTML = logs.slice(0,200).map((log) => `<div class="log"><b>${esc(log.type)}</b><div>${esc(JSON.stringify(log.details))}</div><small>${new Date(log.createdAt).toLocaleString('pt-BR')}</small></div>`).join('') || 'Sem logs.';
}

document.querySelectorAll('.nav').forEach((button) => button.onclick = () => {
  document.querySelectorAll('.nav').forEach((b) => b.classList.remove('active')); button.classList.add('active');
  const logs = button.dataset.view === 'logs'; $('logsView').classList.toggle('hidden', !logs); $('licensesView').classList.toggle('hidden', logs);
});
$('logout').onclick = () => { sessionStorage.removeItem('pf_admin_token'); location.reload(); };

if (token) showDashboard().catch(() => { sessionStorage.removeItem('pf_admin_token'); token=''; });
