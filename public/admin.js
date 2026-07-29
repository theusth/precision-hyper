const VERCEL_API_URL = 'https://precision-hyper.vercel.app';

/*
Quando o painel estiver aberto na própria Vercel, usa o mesmo domínio.
Quando estiver rodando pelo Electron ou arquivo local, usa o link acima.
*/
const API_URL =
  window.location.protocol === 'http:' || window.location.protocol === 'https:'
    ? window.location.origin
    : VERCEL_API_URL;

let token = sessionStorage.getItem('pf_admin_token') || '';
let licenses = [];

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    if (response.status === 401) {
      sessionStorage.removeItem('pf_admin_token');
      token = '';
    }

    throw new Error(
      data.error ||
      data.message ||
      `Erro HTTP ${response.status}`
    );
  }

  return data;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => {
    const characters = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    };

    return characters[character];
  });
}

function showMessage(message, isError = false) {
  const element = $('actionMessage');

  if (!element) return;

  element.textContent = message;
  element.style.color = isError ? '#ff667d' : '#4bea70';
}

function showLoginMessage(message, isError = false) {
  const element = $('loginMessage');

  if (!element) return;

  element.textContent = message;
  element.style.color = isError ? '#ff667d' : '#aaa';
}

/* LOGIN */

$('loginForm')?.addEventListener('submit', async (event) => {
  event.preventDefault();

  const username = $('username')?.value.trim();
  const password = $('password')?.value;

  if (!username || !password) {
    showLoginMessage('Digite o usuário e a senha.', true);
    return;
  }

  showLoginMessage('Entrando...');

  try {
    const data = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        username,
        password
      })
    });

    if (!data.token) {
      throw new Error('A API não retornou o token de acesso.');
    }

    token = data.token;
    sessionStorage.setItem('pf_admin_token', token);

    await showDashboard();
  } catch (error) {
    showLoginMessage(error.message, true);
  }
});

async function showDashboard() {
  $('loginView')?.classList.add('hidden');
  $('dashboardView')?.classList.remove('hidden');

  try {
    await refresh();
  } catch (error) {
    console.error(error);

    if (!token) {
      showLogin();
      return;
    }

    showMessage(error.message, true);
  }
}

function showLogin() {
  $('dashboardView')?.classList.add('hidden');
  $('loginView')?.classList.remove('hidden');
}

/* DASHBOARD */

async function loadDashboard() {
  const data = await api('/api/dashboard');

  if ($('totalKeys')) {
    $('totalKeys').textContent = data.totalKeys ?? 0;
  }

  if ($('activeKeys')) {
    $('activeKeys').textContent =
      data.active ?? data.activeKeys ?? 0;
  }

  if ($('expiredKeys')) {
    $('expiredKeys').textContent =
      data.expired ?? data.expiredKeys ?? 0;
  }

  if ($('blockedKeys')) {
    $('blockedKeys').textContent =
      data.blocked ?? data.blockedKeys ?? 0;
  }
}

/* LICENÇAS */

async function loadLicenses() {
  const data = await api('/api/licenses');

  licenses = Array.isArray(data)
    ? data
    : Array.isArray(data.licenses)
      ? data.licenses
      : [];

  renderLicenses();
}

function getLicenseStatus(license) {
  return license.status || 'active';
}

function getDaysRemaining(license) {
  if (license.daysRemaining !== undefined) {
    return license.daysRemaining;
  }

  if (!license.expiresAt && !license.expires_at) {
    return '-';
  }

  const expiresAt = new Date(
    license.expiresAt || license.expires_at
  );

  const difference = expiresAt.getTime() - Date.now();

  return Math.max(
    0,
    Math.ceil(difference / (1000 * 60 * 60 * 24))
  );
}

function renderLicenses() {
  const tableBody = $('licenseRows');

  if (!tableBody) return;

  const searchValue = $('search')?.value
    .trim()
    .toLowerCase() || '';

  const filteredLicenses = licenses.filter((license) => {
    const key = license.key || license.licenseKey || '';
    const clientName =
      license.clientName ||
      license.client_name ||
      license.customerName ||
      '';

    return `${key} ${clientName}`
      .toLowerCase()
      .includes(searchValue);
  });

  if (!filteredLicenses.length) {
    tableBody.innerHTML = `
      <tr>
        <td colspan="6">Nenhuma licença encontrada.</td>
      </tr>
    `;
    return;
  }

  tableBody.innerHTML = filteredLicenses.map((license) => {
    const key = license.key || license.licenseKey || '';
    const clientName =
      license.clientName ||
      license.client_name ||
      license.customerName ||
      'Sem nome';

    const status = getLicenseStatus(license);
    const hwid = license.hwid || '';
    const daysRemaining = getDaysRemaining(license);

    const safeKey = encodeURIComponent(key);

    return `
      <tr>
        <td>${escapeHtml(clientName)}</td>

        <td class="key">
          ${escapeHtml(key)}
        </td>

        <td class="status ${escapeHtml(status)}-status">
          ${escapeHtml(status.toUpperCase())}
        </td>

        <td>${escapeHtml(daysRemaining)}</td>

        <td title="${escapeHtml(hwid)}">
          ${
            hwid
              ? `${escapeHtml(hwid.slice(0, 12))}…`
              : 'Não vinculado'
          }
        </td>

        <td class="actions">
          <button
            type="button"
            onclick="copyKey(decodeURIComponent('${safeKey}'))"
          >
            Copiar
          </button>

          <button
            type="button"
            onclick="renewLicense(decodeURIComponent('${safeKey}'))"
          >
            Renovar
          </button>

          <button
            type="button"
            onclick="resetHwid(decodeURIComponent('${safeKey}'))"
          >
            Reset HWID
          </button>

          <button
            type="button"
            onclick="toggleBlock(
              decodeURIComponent('${safeKey}'),
              '${escapeHtml(status)}'
            )"
          >
            ${status === 'blocked' ? 'Desbloquear' : 'Bloquear'}
          </button>

          <button
            type="button"
            onclick="removeLicense(decodeURIComponent('${safeKey}'))"
          >
            Excluir
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

$('search')?.addEventListener('input', renderLicenses);

/* CRIAR LICENÇA */

$('createLicense')?.addEventListener('click', async () => {
  const clientName =
    $('clientName')?.value.trim() || 'Novo cliente';

  const days = Number($('days')?.value || 30);
  const customKey = $('customKey')?.value.trim();

  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    showMessage(
      'Informe uma quantidade de dias entre 1 e 3650.',
      true
    );
    return;
  }

  const payload = {
    clientName,
    days
  };

  if (customKey) {
    payload.key = customKey;
  }

  showMessage('Gerando licença...');

  try {
    const created = await api('/api/license/create', {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    const createdKey =
      created.key ||
      created.license?.key ||
      created.licenseKey;

    showMessage(
      createdKey
        ? `Key criada: ${createdKey}`
        : 'Licença criada com sucesso.'
    );

    if ($('customKey')) {
      $('customKey').value = '';
    }

    if ($('clientName')) {
      $('clientName').value = '';
    }

    await refresh();
  } catch (error) {
    showMessage(error.message, true);
  }
});

/* AÇÕES */

window.copyKey = async (key) => {
  try {
    await navigator.clipboard.writeText(key);
    showMessage('Key copiada.');
  } catch {
    showMessage(`Key: ${key}`);
  }
};

window.renewLicense = async (key) => {
  const value = prompt(
    'Adicionar quantos dias?',
    '30'
  );

  if (value === null) return;

  const days = Number(value);

  if (!Number.isInteger(days) || days < 1) {
    showMessage('Quantidade de dias inválida.', true);
    return;
  }

  try {
    await api('/api/license/renew', {
      method: 'POST',
      body: JSON.stringify({
        key,
        days
      })
    });

    showMessage('Licença renovada com sucesso.');
    await refresh();
  } catch (error) {
    showMessage(error.message, true);
  }
};

window.resetHwid = async (key) => {
  const confirmed = confirm(
    'Deseja realmente resetar o HWID desta key?'
  );

  if (!confirmed) return;

  try {
    await api('/api/license/reset-hwid', {
      method: 'POST',
      body: JSON.stringify({ key })
    });

    showMessage('HWID resetado com sucesso.');
    await refresh();
  } catch (error) {
    showMessage(error.message, true);
  }
};

window.toggleBlock = async (key, status) => {
  const action =
    status === 'blocked'
      ? 'unblock'
      : 'block';

  try {
    await api(`/api/license/${action}`, {
      method: 'POST',
      body: JSON.stringify({ key })
    });

    showMessage(
      action === 'block'
        ? 'Licença bloqueada.'
        : 'Licença desbloqueada.'
    );

    await refresh();
  } catch (error) {
    showMessage(error.message, true);
  }
};

window.removeLicense = async (key) => {
  const confirmed = confirm(
    'Deseja excluir esta key permanentemente?'
  );

  if (!confirmed) return;

  try {
    await api(
      `/api/license/${encodeURIComponent(key)}`,
      {
        method: 'DELETE'
      }
    );

    showMessage('Licença excluída com sucesso.');
    await refresh();
  } catch (error) {
    showMessage(error.message, true);
  }
};

/* LOGS */

async function loadLogs() {
  const data = await api('/api/logs');

  const logs = Array.isArray(data)
    ? data
    : Array.isArray(data.logs)
      ? data.logs
      : [];

  renderLogs($('recentLogs'), logs.slice(0, 5));
  renderLogs($('allLogs'), logs.slice(0, 200));
}

function renderLogs(container, logs) {
  if (!container) return;

  if (!logs.length) {
    container.innerHTML = '<p>Sem logs disponíveis.</p>';
    return;
  }

  container.innerHTML = logs.map((log) => {
    const type =
      log.type ||
      log.action ||
      'Atividade';

    const details =
      log.details ||
      log.message ||
      {};

    const createdAt =
      log.createdAt ||
      log.created_at ||
      new Date().toISOString();

    const detailsText =
      typeof details === 'string'
        ? details
        : JSON.stringify(details);

    return `
      <div class="log">
        <b>${escapeHtml(type)}</b>
        <div>${escapeHtml(detailsText)}</div>
        <small>
          ${new Date(createdAt).toLocaleString('pt-BR')}
        </small>
      </div>
    `;
  }).join('');
}

/* NAVEGAÇÃO */

document.querySelectorAll('.nav').forEach((button) => {
  button.addEventListener('click', () => {
    const page = button.dataset.page;

    document.querySelectorAll('.nav').forEach((item) => {
      item.classList.remove('active');
    });

    button.classList.add('active');

    document.querySelectorAll('.page').forEach((element) => {
      element.classList.add('hidden');
    });

    const selectedPage = $(`${page}Page`);

    if (selectedPage) {
      selectedPage.classList.remove('hidden');
    }

    const pageNames = {
      dashboard: 'Dashboard',
      licenses: 'Licenças',
      logs: 'Logs'
    };

    if ($('pageTitle')) {
      $('pageTitle').textContent =
        pageNames[page] || 'Painel Admin';
    }
  });
});

/* LOGOUT */

$('logout')?.addEventListener('click', () => {
  sessionStorage.removeItem('pf_admin_token');
  token = '';

  showLogin();
  showLoginMessage('');
});

/* ATUALIZAR PAINEL */

async function refresh() {
  await Promise.all([
    loadDashboard(),
    loadLicenses(),
    loadLogs()
  ]);
}

/* INICIALIZAÇÃO */

if (token) {
  showDashboard().catch((error) => {
    console.error(error);

    sessionStorage.removeItem('pf_admin_token');
    token = '';

    showLogin();
    showLoginMessage(
      'Sua sessão expirou. Entre novamente.',
      true
    );
  });
} else {
  showLogin();
}