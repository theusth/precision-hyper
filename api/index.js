const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();

app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: false
  })
);

app.use(express.json({ limit: '64kb' }));

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 200,
    standardHeaders: true,
    legacyHeaders: false
  })
);

/* =========================
   CONFIGURAÇÕES
========================= */

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET || '';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';

/*
Você pode usar:

ADMIN_PASSWORD=admin123

ou, de forma mais segura:

ADMIN_PASSWORD_HASH=$2a$...
*/
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';

const supabaseConfigured = Boolean(
  SUPABASE_URL && SUPABASE_SECRET_KEY
);

// Nunca deixe uma configuração inválida derrubar toda a Serverless Function.
// O cliente é inicializado com proteção, permitindo que /api/health e /api/login
// continuem respondendo e mostrem o erro correto.
let supabase = null;
let supabaseInitError = '';

if (supabaseConfigured) {
  try {
    const parsedUrl = new URL(SUPABASE_URL);

    if (parsedUrl.protocol !== 'https:') {
      throw new Error('SUPABASE_URL precisa começar com https://');
    }

    supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    });
  } catch (error) {
    supabaseInitError = error instanceof Error ? error.message : String(error);
    console.error('Falha ao iniciar Supabase:', supabaseInitError);
  }
}

/* =========================
   CORS
========================= */

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigin = process.env.ALLOWED_ORIGIN;

  if (
    allowedOrigin &&
    origin &&
    origin !== allowedOrigin
  ) {
    return res.status(403).json({
      error: 'Origem não permitida.'
    });
  }

  if (origin) {
    res.setHeader(
      'Access-Control-Allow-Origin',
      allowedOrigin || origin
    );
  }

  res.setHeader('Vary', 'Origin');

  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization'
  );

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, DELETE, OPTIONS'
  );

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  next();
});

/* =========================
   FUNÇÕES AUXILIARES
========================= */

function normalizeKey(value) {
  return String(value || '')
    .trim()
    .toUpperCase();
}

function daysLeft(expiresAt) {
  const expires = new Date(expiresAt).getTime();

  if (!Number.isFinite(expires)) {
    return 0;
  }

  return Math.max(
    0,
    Math.ceil((expires - Date.now()) / 86400000)
  );
}

function statusOf(license) {
  if (license.status === 'blocked') {
    return 'blocked';
  }

  const expiration = new Date(
    license.expires_at
  ).getTime();

  return expiration > Date.now()
    ? 'active'
    : 'expired';
}

function serializeLicense(license) {
  return {
    id: license.id,
    key: license.key,
    clientName: license.client_name,
    createdAt: license.created_at,
    expiresAt: license.expires_at,
    status: statusOf(license),
    daysRemaining: daysLeft(license.expires_at),
    hwid: license.hwid,
    activatedAt: license.activated_at,
    lastIp: license.last_ip,
    lastLogin: license.last_login,
    os: license.os
  };
}

function randomKey() {
  const chunk = () =>
    crypto
      .randomBytes(3)
      .toString('hex')
      .toUpperCase();

  return `PRECISION-${chunk()}-${chunk()}-${chunk()}`;
}

function requireSupabase(res) {
  if (supabase) {
    return true;
  }

  res.status(500).json({
    error:
      'Supabase não configurado. Adicione SUPABASE_URL e SUPABASE_SECRET_KEY na Vercel.'
  });

  return false;
}

function safeStringCompare(valueA, valueB) {
  const first = Buffer.from(
    String(valueA).padEnd(256).slice(0, 256)
  );

  const second = Buffer.from(
    String(valueB).padEnd(256).slice(0, 256)
  );

  return crypto.timingSafeEqual(first, second);
}

async function checkAdminPassword(password) {
  if (ADMIN_PASSWORD_HASH) {
    try {
      return await bcrypt.compare(
        password,
        ADMIN_PASSWORD_HASH
      );
    } catch (error) {
      console.error(
        'Hash de senha inválido:',
        error.message
      );

      return false;
    }
  }

  if (ADMIN_PASSWORD) {
    return safeStringCompare(
      password,
      ADMIN_PASSWORD
    );
  }

  return false;
}

async function addLog(type, details = {}) {
  if (!supabase) {
    return;
  }

  try {
    const { error } = await supabase
      .from('logs')
      .insert({
        type,
        details
      });

    if (error) {
      console.error(
        'Erro ao registrar log:',
        error.message
      );
    }
  } catch (error) {
    /*
    Um erro na tabela de logs não pode impedir
    o usuário de entrar no painel.
    */
    console.error(
      'Erro inesperado no log:',
      error.message
    );
  }
}

async function getLicenseByKey(key) {
  if (!supabase) {
    throw new Error('Supabase não configurado.');
  }

  const normalizedKey = normalizeKey(key);

  const { data, error } = await supabase
    .from('licenses')
    .select('*')
    .eq('key', normalizedKey)
    .maybeSingle();

  if (error) {
    throw error;
  }

  return data;
}

function adminAuth(req, res, next) {
  if (!JWT_SECRET) {
    return res.status(500).json({
      error:
        'JWT_SECRET não configurado na Vercel.'
    });
  }

  const authorization = String(
    req.headers.authorization || ''
  );

  const token = authorization.replace(
    /^Bearer\s+/i,
    ''
  );

  if (!token) {
    return res.status(401).json({
      error: 'Token não informado.'
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    if (decoded.role !== 'admin') {
      return res.status(403).json({
        error: 'Acesso negado.'
      });
    }

    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({
      error: 'Sessão inválida ou expirada.'
    });
  }
}

/* =========================
   SAÚDE DA API
========================= */

app.get(
  ['/', '/health', '/api/health'],
  (_req, res) => {
    return res.json({
      ok: true,
      service: 'Precision Fix API',
      version: '3.0.0',
      configuration: {
        supabase: Boolean(supabase),
        supabaseVariablesPresent: supabaseConfigured,
        supabaseError: supabaseInitError || null,
        jwt: Boolean(JWT_SECRET),
        adminUser: Boolean(ADMIN_USER),
        adminPassword: Boolean(
          ADMIN_PASSWORD ||
          ADMIN_PASSWORD_HASH
        )
      },
      missing: [
        !SUPABASE_URL ? 'SUPABASE_URL' : null,
        !SUPABASE_SECRET_KEY ? 'SUPABASE_SECRET_KEY' : null,
        !JWT_SECRET ? 'JWT_SECRET' : null,
        !(ADMIN_PASSWORD || ADMIN_PASSWORD_HASH)
          ? 'ADMIN_PASSWORD ou ADMIN_PASSWORD_HASH'
          : null
      ].filter(Boolean)
    });
  }
);

/* =========================
   LOGIN ADMIN
========================= */

app.post(
  ['/login', '/api/login'],
  async (req, res) => {
    try {
      if (!JWT_SECRET) {
        return res.status(500).json({
          error:
            'JWT_SECRET não configurado na Vercel.'
        });
      }

      if (
        !ADMIN_PASSWORD &&
        !ADMIN_PASSWORD_HASH
      ) {
        return res.status(500).json({
          error:
            'Configure ADMIN_PASSWORD ou ADMIN_PASSWORD_HASH na Vercel.'
        });
      }

      const username = String(
        req.body?.username || ''
      ).trim();

      const password = String(
        req.body?.password || ''
      );

      if (!username || !password) {
        return res.status(400).json({
          error:
            'Informe o usuário e a senha.'
        });
      }

      const validUser = safeStringCompare(
        username,
        ADMIN_USER
      );

      const validPassword =
        await checkAdminPassword(password);

      await addLog(
        validUser && validPassword
          ? 'ADMIN_LOGIN'
          : 'ADMIN_LOGIN_FAILED',
        {
          username,
          ip: req.ip
        }
      );

      if (!validUser || !validPassword) {
        return res.status(401).json({
          error:
            'Usuário ou senha inválidos.'
        });
      }

      const token = jwt.sign(
        {
          role: 'admin',
          username
        },
        JWT_SECRET,
        {
          expiresIn: '8h'
        }
      );

      return res.json({
        token,
        user: {
          username
        }
      });
    } catch (error) {
      console.error(
        'Erro no login:',
        error
      );

      return res.status(500).json({
        error:
          'Erro interno ao realizar login.'
      });
    }
  }
);

/* =========================
   VALIDAR LICENÇA
========================= */

app.post(
  ['/license/validate', '/api/license/validate'],
  async (req, res) => {
    try {
      if (!requireSupabase(res)) {
        return;
      }

      const key = normalizeKey(
        req.body?.key
      );

      const hwid = String(
        req.body?.hwid || ''
      ).trim();

      const clientName = String(
        req.body?.clientName || 'Cliente'
      ).trim();

      const os = String(
        req.body?.os || 'Windows'
      ).trim();

      if (!key) {
        return res.status(400).json({
          valid: false,
          error: 'Key não informada.'
        });
      }

      if (!hwid) {
        return res.status(400).json({
          valid: false,
          error: 'HWID não informado.'
        });
      }

      const license =
        await getLicenseByKey(key);

      if (!license) {
        await addLog('INVALID_KEY', {
          key,
          ip: req.ip
        });

        return res.status(404).json({
          valid: false,
          error: 'Key inválida.'
        });
      }

      const currentStatus =
        statusOf(license);

      if (currentStatus !== 'active') {
        await addLog('LICENSE_DENIED', {
          key,
          status: currentStatus,
          ip: req.ip
        });

        return res.status(403).json({
          valid: false,
          error:
            currentStatus === 'blocked'
              ? 'Licença bloqueada.'
              : 'Licença expirada.'
        });
      }

      if (
        license.hwid &&
        license.hwid !== hwid
      ) {
        await addLog('HWID_MISMATCH', {
          key,
          oldHwid: license.hwid,
          newHwid: hwid,
          ip: req.ip
        });

        return res.status(403).json({
          valid: false,
          error:
            'HWID diferente. Resete a Key no painel.'
        });
      }

      const updates = {
        client_name:
          clientName ||
          license.client_name,
        os,
        last_ip: req.ip,
        last_login:
          new Date().toISOString()
      };

      if (!license.hwid) {
        updates.hwid = hwid;

        updates.activated_at =
          new Date().toISOString();

        await addLog('HWID_BOUND', {
          key,
          hwid
        });
      }

      const { data, error } =
        await supabase
          .from('licenses')
          .update(updates)
          .eq('id', license.id)
          .select('*')
          .single();

      if (error) {
        throw error;
      }

      await addLog('LICENSE_LOGIN', {
        key,
        hwid,
        ip: req.ip
      });

      return res.json({
        valid: true,
        license: serializeLicense(data)
      });
    } catch (error) {
      console.error(
        'Erro na validação:',
        error
      );

      return res.status(500).json({
        valid: false,
        error:
          error.message ||
          'Erro interno na validação.'
      });
    }
  }
);

/* =========================
   DASHBOARD
========================= */

app.get(
  ['/dashboard', '/api/dashboard'],
  adminAuth,
  async (_req, res) => {
    try {
      if (!requireSupabase(res)) {
        return;
      }

      const { data, error } =
        await supabase
          .from('licenses')
          .select('status, expires_at');

      if (error) {
        throw error;
      }

      const licenses = data || [];

      const statuses =
        licenses.map(statusOf);

      return res.json({
        totalKeys: licenses.length,

        active: statuses.filter(
          (status) =>
            status === 'active'
        ).length,

        expired: statuses.filter(
          (status) =>
            status === 'expired'
        ).length,

        blocked: statuses.filter(
          (status) =>
            status === 'blocked'
        ).length
      });
    } catch (error) {
      console.error(
        'Erro no dashboard:',
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          'Erro ao carregar dashboard.'
      });
    }
  }
);

/* =========================
   LISTAR LICENÇAS
========================= */

app.get(
  ['/licenses', '/api/licenses'],
  adminAuth,
  async (_req, res) => {
    try {
      if (!requireSupabase(res)) {
        return;
      }

      const { data, error } =
        await supabase
          .from('licenses')
          .select('*')
          .order('created_at', {
            ascending: false
          });

      if (error) {
        throw error;
      }

      return res.json(
        (data || []).map(
          serializeLicense
        )
      );
    } catch (error) {
      console.error(
        'Erro ao listar licenças:',
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          'Erro ao listar licenças.'
      });
    }
  }
);

/* =========================
   CRIAR LICENÇA
========================= */

app.post(
  ['/license/create', '/api/license/create'],
  adminAuth,
  async (req, res) => {
    try {
      if (!requireSupabase(res)) {
        return;
      }

      const requestedDays = Number(
        req.body?.days || 30
      );

      const days = Math.max(
        1,
        Math.min(
          3650,
          Number.isFinite(requestedDays)
            ? Math.floor(requestedDays)
            : 30
        )
      );

      const key = normalizeKey(
        req.body?.key || randomKey()
      );

      const clientName = String(
        req.body?.clientName ||
        'Novo cliente'
      ).trim();

      const payload = {
        key,
        client_name: clientName,
        expires_at: new Date(
          Date.now() +
          days * 86400000
        ).toISOString(),
        status: 'active'
      };

      const { data, error } =
        await supabase
          .from('licenses')
          .insert(payload)
          .select('*')
          .single();

      if (error) {
        if (error.code === '23505') {
          return res.status(409).json({
            error: 'Essa Key já existe.'
          });
        }

        throw error;
      }

      await addLog(
        'LICENSE_CREATED',
        {
          key,
          days,
          clientName
        }
      );

      return res
        .status(201)
        .json(serializeLicense(data));
    } catch (error) {
      console.error(
        'Erro ao criar licença:',
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          'Erro ao criar licença.'
      });
    }
  }
);

/* =========================
   ALTERAR LICENÇA
========================= */

async function mutateLicense(
  req,
  res,
  action
) {
  try {
    if (!requireSupabase(res)) {
      return;
    }

    const key = normalizeKey(
      req.body?.key
    );

    if (!key) {
      return res.status(400).json({
        error: 'Key não informada.'
      });
    }

    const license =
      await getLicenseByKey(key);

    if (!license) {
      return res.status(404).json({
        error: 'Key não encontrada.'
      });
    }

    let updates = {};

    if (action === 'reset-hwid') {
      updates = {
        hwid: null,
        activated_at: null
      };
    }

    if (action === 'block') {
      updates = {
        status: 'blocked'
      };
    }

    if (action === 'unblock') {
      updates = {
        status: 'active'
      };
    }

    if (action === 'renew') {
      const requestedDays = Number(
        req.body?.days || 30
      );

      const days = Math.max(
        1,
        Math.min(
          3650,
          Number.isFinite(requestedDays)
            ? Math.floor(requestedDays)
            : 30
        )
      );

      const currentExpiration =
        new Date(
          license.expires_at
        ).getTime();

      const baseDate = Math.max(
        Date.now(),
        Number.isFinite(
          currentExpiration
        )
          ? currentExpiration
          : Date.now()
      );

      updates = {
        expires_at: new Date(
          baseDate +
          days * 86400000
        ).toISOString(),
        status: 'active'
      };
    }

    const { data, error } =
      await supabase
        .from('licenses')
        .update(updates)
        .eq('id', license.id)
        .select('*')
        .single();

    if (error) {
      throw error;
    }

    await addLog(
      `LICENSE_${action
        .toUpperCase()
        .replaceAll('-', '_')}`,
      {
        key
      }
    );

    return res.json({
      ok: true,
      license:
        serializeLicense(data)
    });
  } catch (error) {
    console.error(
      `Erro na ação ${action}:`,
      error
    );

    return res.status(500).json({
      error:
        error.message ||
        'Erro interno.'
    });
  }
}

for (const action of [
  'reset-hwid',
  'block',
  'unblock',
  'renew'
]) {
  app.post(
    [
      `/license/${action}`,
      `/api/license/${action}`
    ],
    adminAuth,
    (req, res) =>
      mutateLicense(
        req,
        res,
        action
      )
  );
}

/* =========================
   EXCLUIR LICENÇA
========================= */

app.delete(
  ['/license/:key', '/api/license/:key'],
  adminAuth,
  async (req, res) => {
    try {
      if (!requireSupabase(res)) {
        return;
      }

      const key = normalizeKey(
        req.params.key
      );

      const license =
        await getLicenseByKey(key);

      if (!license) {
        return res.status(404).json({
          error: 'Key não encontrada.'
        });
      }

      const { error } =
        await supabase
          .from('licenses')
          .delete()
          .eq('id', license.id);

      if (error) {
        throw error;
      }

      await addLog(
        'LICENSE_DELETED',
        {
          key
        }
      );

      return res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        'Erro ao excluir licença:',
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          'Erro ao excluir licença.'
      });
    }
  }
);

/* =========================
   LOGS
========================= */

app.get(
  ['/logs', '/api/logs'],
  adminAuth,
  async (_req, res) => {
    try {
      if (!requireSupabase(res)) {
        return;
      }

      const { data, error } =
        await supabase
          .from('logs')
          .select('*')
          .order('created_at', {
            ascending: false
          })
          .limit(500);

      if (error) {
        throw error;
      }

      return res.json(
        (data || []).map((log) => ({
          id: log.id,
          type: log.type,
          details: log.details,
          createdAt: log.created_at
        }))
      );
    } catch (error) {
      console.error(
        'Erro ao carregar logs:',
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          'Erro ao carregar logs.'
      });
    }
  }
);

/* =========================
   ROTA NÃO ENCONTRADA
========================= */

app.use((req, res) => {
  return res.status(404).json({
    error: 'Rota não encontrada.'
  });
});

module.exports = app;
