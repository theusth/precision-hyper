const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const required = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'JWT_SECRET', 'ADMIN_USER', 'ADMIN_PASSWORD_HASH'];
for (const name of required) {
  if (!process.env[name]) throw new Error(`Variável de ambiente ausente: ${name}`);
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
app.use(express.json({ limit: '64kb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 200, standardHeaders: true, legacyHeaders: false }));

app.use((req, res, next) => {
  const allowed = process.env.ALLOWED_ORIGIN;
  const origin = req.headers.origin;
  if (!allowed || !origin || origin === allowed) {
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    if (req.method === 'OPTIONS') return res.status(204).end();
    return next();
  }
  return res.status(403).json({ error: 'Origem não permitida.' });
});

function normalizeKey(value) { return String(value || '').trim().toUpperCase(); }
function daysLeft(expiresAt) { return Math.max(0, Math.ceil((new Date(expiresAt).getTime() - Date.now()) / 86400000)); }
function statusOf(license) {
  if (license.status === 'blocked') return 'blocked';
  return new Date(license.expires_at).getTime() > Date.now() ? 'active' : 'expired';
}
function serialize(license) {
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
async function addLog(type, details = {}) {
  await supabase.from('logs').insert({ type, details });
}
function randomKey() {
  const chunk = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `PRECISION-${chunk()}-${chunk()}-${chunk()}`;
}
function auth(req, res, next) {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET);
    if (req.admin.role !== 'admin') throw new Error('invalid role');
    next();
  } catch {
    res.status(401).json({ error: 'Não autorizado.' });
  }
}
async function getLicenseByKey(key) {
  const { data, error } = await supabase.from('licenses').select('*').ilike('key', normalizeKey(key)).maybeSingle();
  if (error) throw error;
  return data;
}

app.get(['/health', '/api/health'], (_req, res) => res.json({ ok: true, service: 'Precision Fix API', version: '2.0.0' }));

app.post(['/login', '/api/login'], async (req, res) => {
  try {
    const username = String(req.body?.username || '');
    const password = String(req.body?.password || '');
    const okUser = crypto.timingSafeEqual(Buffer.from(username.padEnd(128).slice(0,128)), Buffer.from(process.env.ADMIN_USER.padEnd(128).slice(0,128)));
    const okPass = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
    await addLog(okUser && okPass ? 'ADMIN_LOGIN' : 'ADMIN_LOGIN_FAILED', { username, ip: req.ip });
    if (!okUser || !okPass) return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
    return res.json({ token: jwt.sign({ role: 'admin', username }, process.env.JWT_SECRET, { expiresIn: '8h' }) });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Erro interno.' });
  }
});

app.post(['/license/validate', '/api/license/validate'], async (req, res) => {
  try {
    const key = normalizeKey(req.body?.key);
    const hwid = String(req.body?.hwid || '').trim();
    const clientName = String(req.body?.clientName || 'Cliente').trim();
    const os = String(req.body?.os || 'Windows').trim();
    const license = await getLicenseByKey(key);
    if (!license) {
      await addLog('INVALID_KEY', { key, ip: req.ip });
      return res.status(404).json({ valid: false, error: 'Key inválida.' });
    }
    const currentStatus = statusOf(license);
    if (currentStatus !== 'active') {
      await addLog('LICENSE_DENIED', { key, status: currentStatus, ip: req.ip });
      return res.status(403).json({ valid: false, error: currentStatus === 'blocked' ? 'Licença bloqueada.' : 'Licença expirada.' });
    }
    if (!hwid) return res.status(400).json({ valid: false, error: 'HWID ausente.' });
    if (license.hwid && license.hwid !== hwid) {
      await addLog('HWID_MISMATCH', { key, oldHwid: license.hwid, newHwid: hwid, ip: req.ip });
      return res.status(403).json({ valid: false, error: 'HWID diferente. Resete a Key no painel administrativo.' });
    }
    const updates = {
      client_name: clientName || license.client_name,
      os,
      last_ip: req.ip,
      last_login: new Date().toISOString()
    };
    if (!license.hwid) {
      updates.hwid = hwid;
      updates.activated_at = new Date().toISOString();
      await addLog('HWID_BOUND', { key, hwid });
    }
    const { data, error } = await supabase.from('licenses').update(updates).eq('id', license.id).select('*').single();
    if (error) throw error;
    await addLog('LICENSE_LOGIN', { key, hwid, ip: req.ip });
    return res.json({ valid: true, license: serialize(data) });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ valid: false, error: 'Erro interno na validação.' });
  }
});

app.get(['/licenses', '/api/licenses'], auth, async (_req, res) => {
  const { data, error } = await supabase.from('licenses').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  return res.json(data.map(serialize));
});

app.get(['/dashboard', '/api/dashboard'], auth, async (_req, res) => {
  const { data, error } = await supabase.from('licenses').select('status,expires_at');
  if (error) return res.status(500).json({ error: error.message });
  const statuses = data.map(statusOf);
  return res.json({ totalKeys: data.length, active: statuses.filter(s => s === 'active').length, expired: statuses.filter(s => s === 'expired').length, blocked: statuses.filter(s => s === 'blocked').length });
});

app.get(['/logs', '/api/logs'], auth, async (_req, res) => {
  const { data, error } = await supabase.from('logs').select('*').order('created_at', { ascending: false }).limit(500);
  if (error) return res.status(500).json({ error: error.message });
  return res.json(data.map(log => ({ id: log.id, type: log.type, details: log.details, createdAt: log.created_at })));
});

app.post(['/license/create', '/api/license/create'], auth, async (req, res) => {
  const days = Math.max(1, Math.min(3650, Number(req.body?.days || 30)));
  const key = normalizeKey(req.body?.key || randomKey());
  const payload = { key, client_name: String(req.body?.clientName || 'Novo cliente').trim(), expires_at: new Date(Date.now() + days * 86400000).toISOString(), status: 'active' };
  const { data, error } = await supabase.from('licenses').insert(payload).select('*').single();
  if (error) return res.status(error.code === '23505' ? 409 : 500).json({ error: error.code === '23505' ? 'Key já existe.' : error.message });
  await addLog('LICENSE_CREATED', { key, days, clientName: payload.client_name });
  return res.status(201).json(serialize(data));
});

async function mutate(req, res, action) {
  try {
    const key = normalizeKey(req.body?.key);
    const license = await getLicenseByKey(key);
    if (!license) return res.status(404).json({ error: 'Key não encontrada.' });
    let updates = {};
    if (action === 'reset-hwid') updates = { hwid: null, activated_at: null };
    if (action === 'block') updates = { status: 'blocked' };
    if (action === 'unblock') updates = { status: 'active' };
    if (action === 'renew') {
      const days = Math.max(1, Math.min(3650, Number(req.body?.days || 30)));
      const base = Math.max(Date.now(), new Date(license.expires_at).getTime() || Date.now());
      updates = { expires_at: new Date(base + days * 86400000).toISOString(), status: 'active' };
    }
    const { data, error } = await supabase.from('licenses').update(updates).eq('id', license.id).select('*').single();
    if (error) throw error;
    await addLog(`LICENSE_${action.toUpperCase().replaceAll('-', '_')}`, { key });
    return res.json({ ok: true, license: serialize(data) });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Erro interno.' });
  }
}
for (const action of ['reset-hwid', 'block', 'unblock', 'renew']) {
  app.post([`/license/${action}`, `/api/license/${action}`], auth, (req, res) => mutate(req, res, action));
}

app.delete(['/license/:key', '/api/license/:key'], auth, async (req, res) => {
  const key = normalizeKey(req.params.key);
  const license = await getLicenseByKey(key);
  if (!license) return res.status(404).json({ error: 'Key não encontrada.' });
  const { error } = await supabase.from('licenses').delete().eq('id', license.id);
  if (error) return res.status(500).json({ error: error.message });
  await addLog('LICENSE_DELETED', { key });
  return res.json({ ok: true });
});

app.use((req, res) => res.status(404).json({ error: 'Rota não encontrada.' }));
module.exports = app;
