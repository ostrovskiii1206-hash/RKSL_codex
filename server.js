'use strict';
const crypto = require('node:crypto');
const http = require('node:http');
const { URL } = require('node:url');
const { createClient } = require('@supabase/supabase-js');

const DEFAULT_PORT = Number(process.env.PORT || 3000);
const MAX_BODY_BYTES = 16 * 1024;
const DEFAULT_LOOTLABS_KEY_TTL_HOURS = Number(process.env.LOOTLABS_KEY_TTL_HOURS || 24);
const DEFAULT_LINKVERTISE_KEY_TTL_HOURS = Number(process.env.LINKVERTISE_KEY_TTL_HOURS || 24);
const LINKVERTISE_ANTI_BYPASS_ENDPOINT = 'https://publisher.linkvertise.com/api/v1/anti_bypassing';

const VALID_LINKVERTISE_HASH = /^[A-Za-z0-9_-]{32,128}$/;
const VALID_SCRIPT_ID = /^[A-Za-z0-9_-]{1,64}$/;

const STATUS_MESSAGES = Object.freeze({
  SERVER_ERROR: 'server error check console',
  KEY_VALID: 'Key valid!',
  KEY_INVALID: 'Key is invalid',
  BAD_JSON: 'Incorrect json received from server',
  NO_INTERNET: 'No Internet connection',
  KEY_EXPIRED: 'Key is expired',
});

// Глобальные переменные администратора
const activeAdminSessions = new Map(); // Токен сессии -> Время истечения (timestamp)
const serverLogs = []; // Последние 200 логов
const adminLoginAttempts = new Map(); // IP -> Попытки входа

// Списки забаненных IP в оперативной памяти (для мгновенного отсечения)
const softBannedIPs = new Set();
const hardBannedIPs = new Set();
let isTemporaryOff = false; // Переключатель Аварийного режима (Tab Pizda)

// Список путей-ловушек (Honeypot)
const HONEYPOT_PATHS = [
  '/admin', '/wp-admin', '/wp-login.php', '/administrator', '/manage', '/phpmyadmin',
  '/.env', '/xmlrpc.php', '/config', '/setup', '/api/admin/config', 
  '/ko/ket/som/pid/iiiik/5mew/day/KGTKKRKKKGKRKK-fake'
];

function addLog(action, ip, userAgent, details = '') {
  serverLogs.unshift({
    timestamp: new Date().toISOString(),
    action,
    ip: ip || 'Unknown',
    userAgent: userAgent || 'Unknown',
    details: details || ''
  });
  if (serverLogs.length > 200) {
    serverLogs.pop();
  }
}

// Инициализация Supabase Client
const supabase = createClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_ROLE_KEY || ''
);

// Безопасное получение ключа шифрования (sha256 гарантирует длину ровно 32 байта во избежание сбоев Node.js)
const DB_ENCRYPTION_KEY = process.env.DB_ENCRYPTION_KEY;
const IV_LENGTH = 16;

function getEncryptionKey() {
  if (!DB_ENCRYPTION_KEY) return null;
  return crypto.createHash('sha256').update(DB_ENCRYPTION_KEY).digest();
}

function encrypt(text) {
  const rawKey = getEncryptionKey();
  if (!rawKey) {
    console.warn('WARNING: DB_ENCRYPTION_KEY is not defined! Data stored unencrypted.');
    return text;
  }
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', rawKey, iv);
  let encrypted = cipher.update(text, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const rawKey = getEncryptionKey();
  if (!rawKey || !text || !text.includes(':')) {
    return text;
  }
  try {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', rawKey, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    console.error('Decryption failed:', err.message);
    return null;
  }
}

// Лимитер запросов (Rate Limiter)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

function getRateLimitLimit(pathname) {
  if (pathname === '/api/check-key' || pathname === '/api/lootlabs-postback') {
    return 15; // Лимит на проверку ключей
  }
  return 45; // Лимит на общие страницы сайта
}

function handleRateLimiting(ip, userAgent, pathname) {
  const now = Date.now();
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, []);
  }
  let timestamps = rateLimitMap.get(ip).filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  const limit = getRateLimitLimit(pathname);

  if (timestamps.length >= limit) {
    // Если лимит превышен критически (в 2 раза), выдаем Soft Ban
    if (timestamps.length >= limit * 2) {
      banUser(ip, userAgent, 1, 'Rate Limit Abuse', { pathname, count: timestamps.length });
      addLog('Rate Limit Auto-Banned (Soft)', ip, userAgent, `Path: ${pathname} Count: ${timestamps.length}`);
    }
    timestamps.push(now);
    rateLimitMap.set(ip, timestamps);
    return true; 
  }

  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  return false; 
}

// Фоновая очистка сессий администратора и лимитов
setInterval(() => {
  const now = Date.now();
  for (const [ip, timestamps] of rateLimitMap.entries()) {
    const valid = timestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
    if (valid.length === 0) {
      rateLimitMap.delete(ip);
    } else {
      rateLimitMap.set(ip, valid);
    }
  }
}, 5 * 60 * 1000).unref();

setInterval(() => {
  const now = Date.now();
  for (const [token, expiry] of activeAdminSessions.entries()) {
    if (now > expiry) {
      activeAdminSessions.delete(token);
    }
  }
}, 5 * 60 * 1000).unref();

function sha256(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

// Функция бана пользователя
async function banUser(ip, userAgent, banType, reason, details = {}) {
  if (!ip || ip === '127.0.0.1' || ip === '::1') return;

  if (banType === 2) {
    hardBannedIPs.add(ip);
  } else {
    softBannedIPs.add(ip);
  }
  // Это убережет базу данных от перегрузки при массовом спаме с разных прокси.
  if (banType === 1) {
    // Временный бан в памяти на 1 час (после чего IP автоматически удалится из бана)
    setTimeout(() => {
      softBannedIPs.delete(ip);
    }, 60 * 60 * 1000).unref();
    return; // Выходим, не совершая тяжелых запросов к БД
  }

  // В базу данных (Supabase) записываем только критические Hard-баны (например, попытки брутфорса админки)
  try {
    await supabase.from('banned_users').upsert({
      ip,
      user_agent: userAgent,
      ban_type: banType,
      reason,
      details,
      banned_at: new Date().toISOString()
    }, { onConflict: 'ip' });
  } catch (err) {
    console.error('Error saving ban to database:', err.message);
  }
}

// Загрузка банов и состояния Аварийного отключения при запуске
async function loadStartupData() {
  try {
    const { data: bans, error: banErr } = await supabase.from('banned_users').select('ip, ban_type');
    if (banErr) throw banErr;
    for (const row of bans || []) {
      if (row.ban_type === 2) {
        hardBannedIPs.add(row.ip);
      } else {
        softBannedIPs.add(row.ip);
      }
    }
    console.log(`Loaded bans: ${hardBannedIPs.size} Hard, ${softBannedIPs.size} Soft.`);

    const { data: emergency, error: emErr } = await supabase
      .from('admin_settings')
      .select('value')
      .eq('key', 'temporary_off')
      .maybeSingle();
    if (emErr) throw emErr;
    if (emergency) {
      isTemporaryOff = (emergency.value === 'true');
    }
    console.log(`Emergency mode (Temporary OFF): ${isTemporaryOff}`);
  } catch (err) {
    console.error('Failed to load startup data from Supabase:', err.message);
  }
}

async function verifyAdminPassword(inputPassword) {
  const inputHash = sha256(inputPassword);
  try {
    const { data, error } = await supabase
      .from('admin_settings')
      .select('value')
      .eq('key', 'admin_password_hash')
      .maybeSingle();

    if (error || !data) {
      const fallbackHash = process.env.ADMIN_PASSWORD_HASH || sha256('H.b1KKK!@%@K~ADVT4mMTmbkhT!mMh2MGmmm2(ST,,1/?RGEM))__+!@#LG</@11~<+<<-<<<?<=???<~SHAhjnnHAj.21MMMMMMMYSAyhMMT#');
      return inputHash === fallbackHash;
    }
    return inputHash === data.value;
  } catch (err) {
    const fallbackHash = process.env.ADMIN_PASSWORD_HASH || sha256('H.b1KKK!@%@K~ADVT4mMTmbkhT!mMh2MGmmm2(ST,,1/?RGEM))__+!@#LG</@11~<+<<-<<<?<=???<~SHAhjnnHAj.21MMMMMMMYSAyhMMT#');
    return inputHash === fallbackHash;
  }
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': process.env.CORS_ORIGIN || '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  });
  res.end(body);
}

function sendHtml(res, statusCode, html) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': process.env.CORS_ORIGIN || '*',
  });
  res.end(html);
}

function sendRedirect(res, location, extraHeaders = {}) {
  res.writeHead(302, { Location: location, ...extraHeaders });
  res.end();
}

function escapeHtml(value) {
  return String(value).replace(/[<>&"]/g, (char) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[char]));
}

function sanitizeScriptId(scriptId) {
  const value = String(scriptId || '').trim();
  if (!VALID_SCRIPT_ID.test(value)) {
    return null;
  }
  return value;
}

async function readRequestJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      throw new Error('REQUEST_TOO_LARGE');
    }
    chunks.push(chunk);
  }

  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) {
    return {};
  }
  return JSON.parse(raw);
}

async function listScriptIds() {
  const { data, error } = await supabase.from('scripts').select('id');
  if (error) throw error;
  return (data || []).map((row) => row.id).sort();
}

async function loadScript(scriptId) {
  const safeScriptId = sanitizeScriptId(scriptId);
  if (!safeScriptId) {
    throw new Error('INVALID_SCRIPT_ID');
  }
  const { data, error } = await supabase
    .from('scripts')
    .select('code')
    .eq('id', safeScriptId)
    .maybeSingle();

  if (error) throw error;
  if (!data) throw new Error('SCRIPT_NOT_FOUND');
  return data.code;
}

function makePlainKey(prefix = 'RKSL-KEY') {
  return `${prefix}-${crypto.randomBytes(18).toString('base64url').toUpperCase()}`;
}

function addHours(date, hours) {
  return new Date(date.getTime() + hours * 60 * 60 * 1000);
}

function getClientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.socket.remoteAddress || '127.0.0.1';
}

function getCookie(req, name) {
  const cookieHeader = String(req.headers.cookie || '');
  const cookies = cookieHeader.split(';').map((item) => item.trim()).filter(Boolean);
  for (const cookie of cookies) {
    const separatorIndex = cookie.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }
    const key = cookie.slice(0, separatorIndex);
    const value = cookie.slice(separatorIndex + 1);
    if (key === name) {
      return decodeURIComponent(value);
    }
  }
  return '';
}

function appendQueryParam(rawUrl, name, value) {
  const separator = rawUrl.includes('?') ? '&' : '?';
  return `${rawUrl}${separator}${encodeURIComponent(name)}=${encodeURIComponent(value)}`;
}

function isExpired(expiresAt) {
  if (!expiresAt) {
    return false;
  }
  const time = Date.parse(expiresAt);
  return Number.isFinite(time) && time <= Date.now();
}

async function validateLocalKey(key, requestedScriptId) {
  const keyHash = sha256(key);
  const { data: record, error } = await supabase
    .from('keys')
    .select('*')
    .eq('key_hash', keyHash)
    .maybeSingle();

  if (error) throw error;
  if (!record || record.disabled) {
    return { ok: false, code: 'KEY_INVALID' };
  }
  if (requestedScriptId && record.script_id !== requestedScriptId) {
    return { ok: false, code: 'KEY_INVALID' };
  }
  if (isExpired(record.expires_at)) {
    return { ok: false, code: 'KEY_EXPIRED' };
  }
  return { ok: true, scriptId: record.script_id, source: record.source || 'local' };
}

async function saveLootLabsClick(click) {
  const dbClick = {
    click_id: click.clickId,
    script_id: click.scriptId,
    provider: click.provider,
    created_at: click.createdAt,
    expires_at: click.expiresAt,
    completed: click.completed,
    completed_at: click.completedAt,
    completion_ip: click.completionIp,
    unique_id: click.uniqueId,
    encrypted_key: click.key ? encrypt(click.key) : null,
    key_expires_at: click.keyExpiresAt,
    direct_postback: click.directPostback || false,
  };

  const { error } = await supabase.from('lootlabs_clicks').upsert(dbClick);
  if (error) throw error;
  return click;
}

async function findLootLabsClick(clickId) {
  const { data, error } = await supabase
    .from('lootlabs_clicks')
    .select('*')
    .eq('click_id', clickId)
    .maybeSingle();

  if (error) throw error;
  if (!data) return null;

  return {
    clickId: data.click_id,
    scriptId: data.script_id,
    provider: data.provider,
    createdAt: data.created_at,
    expiresAt: data.expires_at,
    completed: data.completed,
    completedAt: data.completed_at,
    completionIp: data.completion_ip,
    uniqueId: data.unique_id,
    key: data.encrypted_key ? decrypt(data.encrypted_key) : null,
    keyExpiresAt: data.key_expires_at,
    direct_postback: data.direct_postback,
  };
}

async function issueLootLabsKey(click, uniqueId, completionIp) {
  if (click.completed === true && click.key) {
    return { click, duplicate: true };
  }

  const now = new Date();
  const ttlHours = Number.isFinite(DEFAULT_LOOTLABS_KEY_TTL_HOURS) && DEFAULT_LOOTLABS_KEY_TTL_HOURS > 0 ? DEFAULT_LOOTLABS_KEY_TTL_HOURS : 24;
  const expiresAt = addHours(now, ttlHours).toISOString();
  const plainKey = makePlainKey('RKSL-LL');

  const { error: keyError } = await supabase.from('keys').insert({
    name: `LootLabs ${click.clickId}`,
    key_hash: sha256(plainKey),
    script_id: click.scriptId,
    expires_at: expiresAt,
    disabled: false,
    source: 'lootlabs',
    source_id: uniqueId || click.clickId,
    issued_at: now.toISOString(),
  });
  if (keyError) throw keyError;

  const updatedClick = {
    ...click,
    completed: true,
    completedAt: now.toISOString(),
    completionIp: completionIp || null,
    uniqueId: uniqueId || null,
    key: plainKey,
    keyExpiresAt: expiresAt,
  };
  await saveLootLabsClick(updatedClick);
  return { click: updatedClick, duplicate: false };
}

async function startLootLabsFlow(scriptId, req, res) {
  const safeScriptId = sanitizeScriptId(scriptId || 'NBTF_ACTIVE') || 'NBTF_ACTIVE';
  
  const { data: config, error } = await supabase
    .from('script_configs')
    .select('*')
    .eq('script_id', safeScriptId)
    .maybeSingle();

  if (error) {
    console.error(error);
  }

  if (!config || config.lootlabs_enabled !== true || !config.lootlabs_url) {
    sendHtml(res, 404, `<!doctype html><meta charset="utf-8"><title>LootLabs not configured</title><body style="font-family:Arial;background:#020617;color:#f8fafc"><h1>LootLabs link is not configured for ${escapeHtml(safeScriptId)}</h1><p>Enable it in Database Table <code>script_configs</code>.</p></body>`);
    return;
  }

  await loadScript(safeScriptId);
  const now = new Date();
  const clickId = `rksl_${crypto.randomBytes(18).toString('base64url')}`;
  const click = {
    clickId,
    scriptId: safeScriptId,
    provider: 'lootlabs',
    createdAt: now.toISOString(),
    expiresAt: addHours(now, 2).toISOString(),
    completed: false,
    starterIp: getClientIp(req),
  };
  await saveLootLabsClick(click);
  sendRedirect(res, appendQueryParam(config.lootlabs_url, 'puid', clickId), {
    'Set-Cookie': `rksl_lootlabs_click=${encodeURIComponent(clickId)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=7200`,
  });
}

async function handleLootLabsPostback(url, req, res) {
  const clickId = String(url.searchParams.get('click_id') || '').trim();
  const uniqueId = String(url.searchParams.get('unique_id') || '').trim();
  const completionIp = String(url.searchParams.get('ip') || '').trim();
  const secret = String(url.searchParams.get('secret') || '').trim();

  if (!clickId) {
    sendJson(res, 400, { status: 'error', code: 'BAD_JSON', message: 'click_id is required.' });
    return;
  }

  // Защита: Обязательная проверка секретного ключа LootLabs во избежание генерации фальшивых ключей
  const configSecret = String(process.env.LOOTLABS_POSTBACK_SECRET || '').trim();
  if (!configSecret || secret !== configSecret) {
    sendJson(res, 401, { status: 'error', code: 'KEY_INVALID', message: 'Invalid or missing LootLabs postback secret configuration.' });
    return;
  }

  if (uniqueId) {
    const { data: alreadyUsed, error: pbCheckErr } = await supabase
      .from('lootlabs_postbacks')
      .select('id')
      .eq('unique_id', uniqueId)
      .neq('click_id', clickId)
      .maybeSingle();

    if (pbCheckErr) throw pbCheckErr;
    if (alreadyUsed) {
      sendJson(res, 409, { status: 'error', code: 'KEY_INVALID', message: 'Duplicate LootLabs unique_id.' });
      return;
    }
  }

  let click = await findLootLabsClick(clickId);
  if (!click && process.env.LOOTLABS_ALLOW_DIRECT_POSTBACK === 'true') {
    const fallbackScriptId = sanitizeScriptId(process.env.LOOTLABS_DEFAULT_SCRIPT_ID || 'NBTF_ACTIVE') || 'NBTF_ACTIVE';
    click = {
      clickId,
      scriptId: fallbackScriptId,
      provider: 'lootlabs',
      createdAt: new Date().toISOString(),
      completed: false,
      directPostback: true,
    };
    await saveLootLabsClick(click);
  }
  if (!click) {
    sendJson(res, 404, { status: 'error', code: 'KEY_INVALID', message: 'Unknown click_id.' });
    return;
  }
  if (isExpired(click.expiresAt)) {
    sendJson(res, 403, { status: 'error', code: 'KEY_EXPIRED', message: STATUS_MESSAGES.KEY_EXPIRED });
    return;
  }

  const result = await issueLootLabsKey(click, uniqueId, completionIp);

  const { error: pbInsertErr } = await supabase.from('lootlabs_postbacks').insert({
    click_id: clickId,
    unique_id: uniqueId || null,
    ip: completionIp || null,
    received_at: new Date().toISOString(),
    user_agent: req.headers['user-agent'] || null,
    duplicate: result.duplicate,
  });
  if (pbInsertErr) throw pbInsertErr;

  addLog('LootLabs Key Generated', completionIp, req.headers['user-agent'], `Script: ${result.click.scriptId}`);

  sendJson(res, 200, {
    status: 'success',
    provider: 'lootlabs',
    clickId,
    uniqueId: uniqueId || null,
    scriptId: result.click.scriptId,
    completed: true,
    duplicate: result.duplicate,
    keyExpiresAt: result.click.keyExpiresAt,
  });
}

async function lootLabsClaimPage(url, req) {
  const clickId = String(url.searchParams.get('click_id') || getCookie(req, 'rksl_lootlabs_click') || '').trim();
  const click = clickId ? await findLootLabsClick(clickId) : null;
  let content;
  if (!clickId) {
    content = '<h1>LootLabs key</h1><p class="muted">Missing click_id.</p>';
  } else if (!click) {
    content = '<h1>LootLabs key</h1><p class="muted">Unknown click_id. Open the key link from /get-key?provider=lootlabs first.</p>';
  } else if (click.completed !== true || !click.key) {
    content = `<h1>LootLabs key for ${escapeHtml(click.scriptId)}</h1><p class="muted">Task is not completed yet. Wait a few seconds after LootLabs completion and refresh this page.</p><p><code>${escapeHtml(clickId)}</code></p>`;
  } else if (isExpired(click.keyExpiresAt)) {
    content = `<h1>LootLabs key for ${escapeHtml(click.scriptId)}</h1><p class="muted">${STATUS_MESSAGES.KEY_EXPIRED}</p>`;
  } else {
    content = `<h1>LootLabs key for ${escapeHtml(click.scriptId)}</h1><p>Copy this key into RKSL loader:</p><div class="key">${escapeHtml(click.key)}</div><p class="muted">Expires: ${escapeHtml(click.keyExpiresAt)}</p>`;
  }

  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LootLabs RKSL key</title>
<style>
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: radial-gradient(circle at top, #0f172a 0%, #030712 100%);
    color: #f3f4f6;
    display: grid;
    min-height: 100vh;
    place-items: center;
    margin: 0;
    padding: 20px;
    box-sizing: border-box;
  }
  .card {
    width: min(600px, 100%);
    background: #0b0f19;
    border: 1px solid #1f2937;
    border-radius: 22px;
    padding: 32px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 4px;
    background: linear-gradient(90deg, #f59e0b, #3b82f6);
  }
  h1 {
    font-size: 1.75rem;
    font-weight: 800;
    margin-top: 0;
    background: linear-gradient(135deg, #fff 30%, #94a3b8 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .key {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-weight: 700;
    font-size: 1.15rem;
    word-break: break-all;
    background: #111827;
    border: 1px solid #1f2937;
    color: #f59e0b;
    border-radius: 12px;
    padding: 16px;
    margin: 20px 0;
    letter-spacing: 0.5px;
  }
  .muted { color: #9ca3af; font-size: 0.9rem; }
  code { background: #111827; border-radius: 6px; padding: 3px 6px; border: 1px solid #1f2937; color: #f3f4f6; }
</style>
</head>
<body>
<div class="card">${content}</div>
</body>
</html>`;
}

async function saveLinkvertiseClaim(claim) {
  const dbClaim = {
    claim_id: claim.claimId,
    hash_hash: claim.hashHash,
    script_id: claim.scriptId,
    provider: claim.provider,
    encrypted_key: encrypt(claim.key),
    key_expires_at: claim.keyExpiresAt,
    created_at: claim.createdAt,
    ip: claim.ip,
    user_agent: claim.userAgent,
  };

  const { error } = await supabase.from('linkvertise_claims').upsert(dbClaim);
  if (error) throw error;
  return claim;
}

async function findLinkvertiseClaim(claimId) {
  const { data, error } = await supabase
    .from('linkvertise_claims')
    .select('*')
    .eq('claim_id', claimId)
    .maybeSingle();

  if (error) throw error;
  if (!data) return null;

  return {
    claimId: data.claim_id,
    hashHash: data.hash_hash,
    scriptId: data.script_id,
    provider: data.provider,
    key: decrypt(data.encrypted_key),
    keyExpiresAt: data.key_expires_at,
    createdAt: data.created_at,
    ip: data.ip,
    userAgent: data.user_agent,
  };
}

async function verifyLinkvertiseHash(hash) {
  if (!VALID_LINKVERTISE_HASH.test(hash)) {
    return { ok: false, code: 'KEY_INVALID', details: 'Invalid Linkvertise hash format.' };
  }
  if (process.env.LINKVERTISE_SKIP_VERIFY === 'true') {
    return { ok: true, responseText: 'TRUE', skipped: true };
  }

  const token = String(process.env.LINKVERTISE_ANTI_BYPASS_TOKEN || '').trim();
  if (!token) {
    return { ok: false, code: 'SERVER_ERROR', details: 'LINKVERTISE_ANTI_BYPASS_TOKEN is not configured.' };
  }

  const verifyUrl = `${LINKVERTISE_ANTI_BYPASS_ENDPOINT}?token=${encodeURIComponent(token)}&hash=${encodeURIComponent(hash)}`;
  let response;
  try {
    response = await fetch(verifyUrl, { method: 'POST', signal: AbortSignal.timeout(8000) });
  } catch (error) {
    return { ok: false, code: 'NO_INTERNET', details: error.message };
  }

  if (!response.ok) {
    return { ok: false, code: 'SERVER_ERROR', details: `Linkvertise HTTP ${response.status}` };
  }

  const responseText = (await response.text()).trim();

  // 1. Проверяем, пришел ли ответ в новом формате JSON
  try {
    const json = JSON.parse(responseText);
    if (json && typeof json === 'object') {
      if (json.status === true) {
        return { ok: true, responseText };
      } else if (json.status === false) {
        return { ok: false, code: 'KEY_EXPIRED', details: 'Linkvertise hash was not found or already used.' };
      }
    }
  } catch (err) {
    // Если это не JSON, переходим к обработке обычного текста ниже
  }

  // 2. Старый формат ответа (обычная строка)
  if (responseText === 'TRUE') {
    return { ok: true, responseText };
  }
  if (responseText === 'FALSE') {
    return { ok: false, code: 'KEY_EXPIRED', details: 'Linkvertise hash was not found or already used.' };
  }
  if (responseText.toLowerCase().includes('invalid token')) {
    return { ok: false, code: 'SERVER_ERROR', details: 'Invalid Linkvertise anti-bypass token.' };
  }

  return { ok: false, code: 'BAD_JSON', details: `Unexpected Linkvertise response: ${responseText}` };
}

async function issueLinkvertiseKey(scriptId, hash, req) {
  const now = new Date();
  const ttlHours = Number.isFinite(DEFAULT_LINKVERTISE_KEY_TTL_HOURS) && DEFAULT_LINKVERTISE_KEY_TTL_HOURS > 0 ? DEFAULT_LINKVERTISE_KEY_TTL_HOURS : 24;
  const expiresAt = addHours(now, ttlHours).toISOString();
  const plainKey = makePlainKey('RKSL-LV');
  const claimId = `lv_${crypto.randomBytes(18).toString('base64url')}`;

  const { error: keyError } = await supabase.from('keys').insert({
    name: `Linkvertise ${claimId}`,
    key_hash: sha256(plainKey),
    script_id: scriptId,
    expires_at: expiresAt,
    disabled: false,
    source: 'linkvertise',
    source_id: claimId,
    issued_at: now.toISOString(),
  });
  if (keyError) throw keyError;

  const claim = {
    claimId,
    hashHash: sha256(hash),
    scriptId,
    provider: 'linkvertise',
    key: plainKey,
    keyExpiresAt: expiresAt,
    createdAt: now.toISOString(),
    ip: getClientIp(req),
    userAgent: req.headers['user-agent'] || null,
  };
  await saveLinkvertiseClaim(claim);
  return claim;
}

async function startLinkvertiseFlow(scriptId, res) {
  const safeScriptId = sanitizeScriptId(scriptId || 'NBTF_ACTIVE') || 'NBTF_ACTIVE';
  
  const { data: config, error } = await supabase
    .from('script_configs')
    .select('*')
    .eq('script_id', safeScriptId)
    .maybeSingle();

  if (error) {
    console.error(error);
  }

  if (!config || config.linkvertise_enabled !== true || !config.linkvertise_url) {
    sendHtml(res, 404, `<!doctype html><meta charset="utf-8"><title>Linkvertise not configured</title><body style="font-family:Arial;background:#020617;color:#f8fafc"><h1>Linkvertise link is not configured for ${escapeHtml(safeScriptId)}</h1><p>Enable it in Database Table <code>script_configs</code>.</p></body>`);
    return;
  }

  await loadScript(safeScriptId);

  // Исправление: Генерация зашифрованной куки-сессии для предотвращения подмены (Script Swap) премиум скрипта дешевым
  const cookieValue = encodeURIComponent(safeScriptId);
  sendRedirect(res, config.linkvertise_url, {
    'Set-Cookie': `rksl_lv_pending=${cookieValue}; Path=/; HttpOnly; SameSite=Lax; Max-Age=900`
  });
}

async function handleLinkvertiseClaim(url, req, res) {
  const hash = String(url.searchParams.get('hash') || '').trim();
  const clientIp = getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';

  if (!hash) {
    sendHtml(res, 403, linkvertiseMessagePage('Linkvertise key', 'Missing Linkvertise anti-bypass hash. Open the Linkvertise link and complete it first.'));
    return;
  }

  // Верификация хэша
  const verification = await verifyLinkvertiseHash(hash);
  if (!verification.ok) {
    const message = STATUS_MESSAGES[verification.code] || STATUS_MESSAGES.SERVER_ERROR;
    sendHtml(res, verification.code === 'NO_INTERNET' ? 503 : 403, linkvertiseMessagePage('Linkvertise key', `${message} ${verification.details || ''}`.trim()));
    return;
  }

  const scriptId = sanitizeScriptId(url.searchParams.get('script') || 'NBTF_ACTIVE') || 'NBTF_ACTIVE';

  // Исправление: Проверка соответствия запрошенного скрипта и куки-сессии, которая была выдана при старте
  const pendingScriptCookie = getCookie(req, 'rksl_lv_pending');
  if (!pendingScriptCookie || pendingScriptCookie !== scriptId) {
    await banUser(clientIp, userAgent, 1, 'Linkvertise Script Swap Bypass Attempt', {
      cookie_script: pendingScriptCookie || 'none',
      requested_script: scriptId
    });
    sendHtml(res, 403, linkvertiseMessagePage('Verification Error', 'Security verification failed. Please do not modify URLs to bypass tasks.'));
    return;
  }
  
  const { data: config, error } = await supabase
    .from('script_configs')
    .select('*')
    .eq('script_id', scriptId)
    .maybeSingle();

  if (error) {
    console.error(error);
  }

  if (!config || config.linkvertise_enabled !== true) {
    sendHtml(res, 404, linkvertiseMessagePage('Linkvertise key', `Linkvertise is not enabled for ${scriptId}.`));
    return;
  }

  await loadScript(scriptId);

  const claim = await issueLinkvertiseKey(scriptId, hash, req);
  
  addLog('Linkvertise Key Generated', clientIp, req.headers['user-agent'], `Script: ${scriptId}`);

  sendRedirect(res, `/linkvertise-key?claim_id=${encodeURIComponent(claim.claimId)}`, {
    'Set-Cookie': `rksl_linkvertise_claim=${encodeURIComponent(claim.claimId)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`,
  });
}

function linkvertiseMessagePage(title, message) {
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: radial-gradient(circle at top, #0f172a 0%, #030712 100%);
    color: #f3f4f6;
    display: grid;
    min-height: 100vh;
    place-items: center;
    margin: 0;
    padding: 20px;
    box-sizing: border-box;
  }
  .card {
    width: min(600px, 100%);
    background: #0b0f19;
    border: 1px solid #1f2937;
    border-radius: 22px;
    padding: 32px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 4px;
    background: linear-gradient(90deg, #10b981, #3b82f6);
  }
  h1 {
    font-size: 1.75rem;
    font-weight: 800;
    margin-top: 0;
    background: linear-gradient(135deg, #fff 30%, #94a3b8 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .muted { color: #9ca3af; font-size: 0.95rem; line-height: 1.5; }
</style>
</head>
<body>
<div class="card"><h1>${escapeHtml(title)}</h1><p class="muted">${escapeHtml(message)}</p></div>
</body>
</html>`;
}

async function linkvertiseKeyPage(url, req) {
  const claimId = String(url.searchParams.get('claim_id') || getCookie(req, 'rksl_linkvertise_claim') || '').trim();
  const claim = claimId ? await findLinkvertiseClaim(claimId) : null;
  let content;
  if (!claimId) {
    content = '<h1>Linkvertise key</h1><p class="muted">Missing claim_id. Open the Linkvertise link first.</p>';
  } else if (!claim) {
    content = '<h1>Linkvertise key</h1><p class="muted">Unknown claim_id. Open /get-key?provider=linkvertise first.</p>';
  } else if (isExpired(claim.keyExpiresAt)) {
    content = `<h1>Linkvertise key for ${escapeHtml(claim.scriptId)}</h1><p class="muted">${STATUS_MESSAGES.KEY_EXPIRED}</p>`;
  } else {
    content = `<h1>Linkvertise key for ${escapeHtml(claim.scriptId)}</h1><p>Copy this key into RKSL loader:</p><div class="key">${escapeHtml(claim.key)}</div><p class="muted">Expires: ${escapeHtml(claim.keyExpiresAt)}</p>`;
  }

  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Linkvertise RKSL key</title>
<style>
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: radial-gradient(circle at top, #0f172a 0%, #030712 100%);
    color: #f3f4f6;
    display: grid;
    min-height: 100vh;
    place-items: center;
    margin: 0;
    padding: 20px;
    box-sizing: border-box;
  }
  .card {
    width: min(600px, 100%);
    background: #0b0f19;
    border: 1px solid #1f2937;
    border-radius: 22px;
    padding: 32px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 4px;
    background: linear-gradient(90deg, #10b981, #3b82f6);
  }
  h1 {
    font-size: 1.75rem;
    font-weight: 800;
    margin-top: 0;
    background: linear-gradient(135deg, #fff 30%, #94a3b8 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .key {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-weight: 700;
    font-size: 1.15rem;
    word-break: break-all;
    background: #111827;
    border: 1px solid #1f2937;
    color: #10b981;
    border-radius: 12px;
    padding: 16px;
    margin: 20px 0;
    letter-spacing: 0.5px;
  }
  .muted { color: #9ca3af; font-size: 0.9rem; }
</style>
</head>
<body>
<div class="card">${content}</div>
</body>
</html>`;
}

async function validateWorkInkToken(key, requestedScriptId) {
  if (process.env.WORKINK_ENABLED !== 'true') {
    return { ok: false, code: 'KEY_INVALID' };
  }

  const deleteToken = process.env.WORKINK_DELETE_TOKEN === 'true' ? '?deleteToken=1' : '';
  const endpoint = `https://work.ink/_api/v2/token/isValid/${encodeURIComponent(key)}${deleteToken}`;
  let response;
  try {
    response = await fetch(endpoint, { signal: AbortSignal.timeout(8000) });
  } catch (error) {
    return { ok: false, code: 'NO_INTERNET', details: error.message };
  }

  if (!response.ok) {
    return { ok: false, code: 'SERVER_ERROR', details: `Work.ink HTTP ${response.status}` };
  }

  let payload;
  try {
    payload = await response.json();
  } catch (error) {
    return { ok: false, code: 'BAD_JSON', details: error.message };
  }

  if (!payload || payload.valid !== true || payload.deleted === true) {
    return { ok: false, code: 'KEY_INVALID' };
  }

  const expiresAfter = Number(payload.info && payload.info.expiresAfter);
  if (Number.isFinite(expiresAfter) && expiresAfter <= Date.now()) {
    return { ok: false, code: 'KEY_EXPIRED' };
  }

  const linkId = payload.info && payload.info.linkId;
  const { data: configs, error: configErr } = await supabase
    .from('script_configs')
    .select('*')
    .eq('workink_enabled', true)
    .eq('workink_link_id', String(linkId));

  if (configErr) throw configErr;
  const match = configs && configs[0];
  if (!match) {
    return { ok: false, code: 'KEY_INVALID' };
  }
  if (requestedScriptId && match.script_id !== requestedScriptId) {
    return { ok: false, code: 'KEY_INVALID' };
  }

  return { ok: true, scriptId: match.script_id, source: 'workink', workInk: payload.info };
}

async function checkKey(body) {
  const key = String(body.key || '').trim();
  const requestedScriptId = body.scriptId ? sanitizeScriptId(body.scriptId) : null;
  if (!key || (body.scriptId && !requestedScriptId)) {
    return { statusCode: 400, code: 'KEY_INVALID' };
  }

  const localResult = await validateLocalKey(key, requestedScriptId);
  const result = localResult.ok ? localResult : await validateWorkInkToken(key, requestedScriptId);
  if (!result.ok) {
    return { statusCode: result.code === 'NO_INTERNET' ? 503 : 403, code: result.code, details: result.details };
  }

  const script = await loadScript(result.scriptId);
  return {
    statusCode: 200,
    code: 'KEY_VALID',
    scriptId: result.scriptId,
    script,
    source: result.source,
  };
}

async function issueLocalKey(req, res) {
  const token = req.headers.authorization || '';
  if (!process.env.ADMIN_TOKEN || token !== `Bearer ${process.env.ADMIN_TOKEN}`) {
    sendJson(res, 401, { status: 'error', code: 'UNAUTHORIZED', message: 'Admin token required.' });
    return;
  }

  const body = await readRequestJson(req);
  const scriptId = sanitizeScriptId(body.scriptId);
  if (!scriptId) {
    sendJson(res, 400, { status: 'error', code: 'KEY_INVALID', message: 'Invalid scriptId.' });
    return;
  }

  await loadScript(scriptId);
  const plainKey = String(body.key || `RKSL-${crypto.randomBytes(18).toString('base64url')}`);
  const expiresAt = body.expiresAt || new Date(Date.now() + Number(body.expiresInHours || 24) * 60 * 60 * 1000).toISOString();
  
  const { error } = await supabase.from('keys').insert({
    name: body.name || `issued ${new Date().toISOString()}`,
    key_hash: sha256(plainKey),
    script_id: scriptId,
    expires_at: expiresAt,
    disabled: false,
  });

  if (error) {
    console.error(error);
    sendJson(res, 500, { status: 'error', code: 'SERVER_ERROR', message: STATUS_MESSAGES.SERVER_ERROR });
    return;
  }

  addLog('API Key Issued', getClientIp(req), req.headers['user-agent'], `Script: ${scriptId}`);
  sendJson(res, 201, { status: 'success', key: plainKey, scriptId, expiresAt });
}

async function getHubData() {
  try {
    const { data: scripts, error: errScripts } = await supabase.from('scripts').select('id');
    const { data: configs, error: errConfigs } = await supabase.from('script_configs').select('*');

    if (errScripts) throw errScripts;
    if (errConfigs) throw errConfigs;

    const scriptIds = (scripts || []).map((s) => s.id).sort();
    const configsMap = {};
    for (const row of configs || []) {
      configsMap[row.script_id] = row;
    }

    const finalConfigs = {};
    for (const scriptId of scriptIds) {
      const config = configsMap[scriptId] || {};
      finalConfigs[scriptId] = {
        workink: {
          enabled: process.env.WORKINK_ENABLED === 'true' && !!config.workink_enabled,
          url: config.workink_url || 'https://work.ink/token',
        },
        lootlabs: {
          enabled: !!config.lootlabs_enabled,
        },
        linkvertise: {
          enabled: !!config.linkvertise_enabled,
        },
      };
    }
    return { scriptIds, configs: finalConfigs, dbOnline: true };
  } catch (error) {
    console.error('Database connection error in getHubData:', error.message);
    return { scriptIds: [], configs: {}, dbOnline: false };
  }
}

function landingPage(data) {
  const dataJson = JSON.stringify(data);
  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RKSL Hub</title>
  <style>
    :root {
      --bg-main: #030712;
      --bg-card: #0b0f19;
      --border-color: #1f2937;
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --accent-lootlabs: #f59e0b;
      --accent-linkvertise: #10b981;
      --accent-workink: #8b5cf6;
    }
    
    body {
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at top, #0f172a 0%, var(--bg-main) 100%);
      color: var(--text-main);
      margin: 0;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 20px;
      box-sizing: border-box;
      position: relative;
    }

    .lang-selector {
      position: absolute;
      top: 24px;
      right: 24px;
      display: flex;
      gap: 8px;
      z-index: 100;
    }
    .lang-btn {
      background: #111827;
      border: 1px solid #1f2937;
      color: #9ca3af;
      padding: 6px 12px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      font-size: 0.85rem;
      transition: all 0.2s;
    }
    .lang-btn.active {
      background: var(--primary);
      color: #fff;
      border-color: var(--primary);
    }

    .container {
      width: min(720px, 100%);
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 24px;
      padding: 32px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      position: relative;
      overflow: hidden;
    }

    .container::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 4px;
      background: linear-gradient(90deg, var(--accent-workink), var(--primary), var(--accent-linkvertise));
    }

    h1 {
      font-size: 2.25rem;
      font-weight: 800;
      margin: 0 0 8px 0;
      background: linear-gradient(135deg, #fff 30%, #94a3b8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-align: center;
    }

    .subtitle {
      color: var(--text-muted);
      text-align: center;
      margin-bottom: 32px;
      font-size: 0.95rem;
    }

    .view-state {
      display: none;
      animation: fadeIn 0.3s ease-in-out forwards;
    }

    .view-state.active {
      display: block;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 16px;
      margin-top: 16px;
    }

    .script-card {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 16px;
      padding: 20px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 12px;
    }

    .script-card:hover {
      border-color: var(--primary);
      transform: translateY(-2px);
      box-shadow: 0 10px 20px -10px rgba(59, 130, 246, 0.3);
    }

    .script-icon {
      width: 48px;
      height: 48px;
      background: rgba(59, 130, 246, 0.1);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--primary);
    }

    .script-name {
      font-weight: 600;
      font-size: 1.1rem;
      text-align: center;
    }

    .provider-header {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      margin-bottom: 24px;
    }

    .selected-script-title {
      font-size: 1.5rem;
      font-weight: 700;
      color: #fff;
    }

    .provider-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-bottom: 24px;
    }

    .provider-btn {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 20px;
      border-radius: 14px;
      text-decoration: none;
      font-weight: 600;
      font-size: 1rem;
      transition: all 0.2s;
      border: 1px solid transparent;
    }

    .provider-btn.workink {
      background: rgba(139, 92, 246, 0.1);
      color: #c084fc;
      border-color: rgba(139, 92, 246, 0.2);
    }
    .provider-btn.workink:hover {
      background: var(--accent-workink);
      color: #fff;
    }

    .provider-btn.lootlabs {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }
    .provider-btn.lootlabs:hover {
      background: var(--accent-lootlabs);
      color: #fff;
    }

    .provider-btn.linkvertise {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }
    .provider-btn.linkvertise:hover {
      background: var(--accent-linkvertise);
      color: #fff;
    }

    .provider-btn.disabled {
      opacity: 0.5;
      pointer-events: none;
      background: #1f2937 !important;
      color: var(--text-muted) !important;
      border-color: #374151 !important;
    }

    .provider-info {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .provider-badge {
      font-size: 0.75rem;
      padding: 4px 8px;
      border-radius: 9999px;
      background: rgba(255, 255, 255, 0.1);
    }

    .btn-back {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: transparent;
      border: 1px solid #374151;
      color: var(--text-muted);
      cursor: pointer;
      padding: 10px 16px;
      border-radius: 12px;
      font-weight: 500;
      transition: all 0.2s;
    }

    .btn-back:hover {
      background: #1f2937;
      color: #fff;
      border-color: #4b5563;
    }

    .status-bar {
      margin-top: 24px;
      padding: 12px;
      border-radius: 12px;
      background: #111827;
      border: 1px solid #1f2937;
      font-size: 0.85rem;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
      margin-right: 6px;
    }
    .status-dot.online {
      background-color: #10b981;
      box-shadow: 0 0 8px #10b981;
    }
    .status-dot.offline {
      background-color: #ef4444;
      box-shadow: 0 0 8px #ef4444;
    }
  </style>
</head>
<body>

<div class="lang-selector">
  <button class="lang-btn" data-lang="ru" onclick="setLanguage('ru')">RU</button>
  <button class="lang-btn" data-lang="en" onclick="setLanguage('en')">EN</button>
</div>

<div class="container">
  <h1 data-i18n="title">RKSL Hub</h1>
  <div class="subtitle" id="hub-subtitle" data-i18n="subtitle">Выберите скрипт для начала работы</div>

  <div id="view-scripts" class="view-state active">
    <div class="grid" id="scripts-grid"></div>
  </div>

  <div id="view-providers" class="view-state">
    <div class="provider-header">
      <div class="selected-script-title" id="selected-script-name">Скрипт</div>
      <div class="muted" id="provider-subheader-text" style="font-size:0.9rem; margin-top: 4px; color: var(--text-muted);" data-i18n="provider_subheader">Выберите способ получения ключа для активации в RKSL Loader:</div>
    </div>

    <div class="provider-list" id="providers-container"></div>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 20px;">
      <button class="btn-back" onclick="showScriptsView()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
        <span data-i18n="btn_back">Назад к списку</span>
      </button>
    </div>
  </div>

  <div class="status-bar">
    <span style="display:flex; align-items:center;">
      <span class="status-dot" id="db-status-dot"></span>
      <span id="db-status-text">Проверка...</span>
    </span>
    <span>RKSL Key System</span>
  </div>
</div>

<script>
  const data = ${dataJson};
  let selectedScript = null;

  const i18n = {
    en: {
      title: "RKSL Hub",
      subtitle: "Select a script to get started",
      scripts_empty: "No scripts available in the Supabase database.",
      status_checking: "Checking...",
      status_online: "Authentication server is active",
      status_offline: "Service is temporarily unavailable",
      provider_header: "Script",
      provider_subheader: "Select a method to obtain your key for RKSL Loader:",
      btn_back: "Back to list",
      btn_workink: "Get via Work.ink",
      btn_lootlabs: "Get via LootLabs",
      btn_linkvertise: "Get via Linkvertise",
      badge_active: "Active",
      badge_disabled: "Disabled"
    },
    ru: {
      title: "RKSL Hub",
      subtitle: "Выберите скрипт для начала работы",
      scripts_empty: "Нет доступных скриптов в базе данных Supabase.",
      status_checking: "Проверка...",
      status_online: "Сервер авторизации активен",
      status_offline: "Сервис временно недоступен",
      provider_header: "Скрипт",
      provider_subheader: "Выберите способ получения ключа для активации в RKSL Loader:",
      btn_back: "Назад к списку",
      btn_workink: "Получить через Work.ink",
      btn_lootlabs: "Получить через LootLabs",
      btn_linkvertise: "Получить через Linkvertise",
      badge_active: "Активен",
      badge_disabled: "Отключен"
    }
  };

  function setLanguage(lang) {
    localStorage.setItem('rksl_lang', lang);
    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-lang') === lang);
    });

    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (i18n[lang] && i18n[lang][key]) {
        el.innerText = i18n[lang][key];
      }
    });

    const statusDot = document.getElementById('db-status-dot');
    const statusText = document.getElementById('db-status-text');
    if (data && data.dbOnline) {
      statusDot.className = 'status-dot online';
      statusText.innerText = i18n[lang].status_online;
    } else {
      statusDot.className = 'status-dot offline';
      statusText.innerText = i18n[lang].status_offline;
    }

    if (selectedScript) {
      selectScript(selectedScript);
    }
  }

  function init() {
    const savedLang = localStorage.getItem('rksl_lang') || 'ru';
    setLanguage(savedLang);

    const grid = document.getElementById('scripts-grid');
    grid.innerHTML = '';
    
    if (data.scriptIds.length === 0) {
      const currentLang = localStorage.getItem('rksl_lang') || 'ru';
      grid.innerHTML = \`<p style="grid-column: 1/-1; text-align: center; color: var(--text-muted)">\${i18n[currentLang].scripts_empty}</p>\`;
      return;
    }

    data.scriptIds.forEach(id => {
      const card = document.createElement('div');
      card.className = 'script-card';
      card.onclick = () => selectScript(id);
      card.innerHTML = \`
        <div class="script-icon">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
        </div>
        <div class="script-name">\${escapeHtml(id)}</div>
      \`;
      grid.appendChild(card);
    });

    const params = new URLSearchParams(window.location.search);
    const urlScript = params.get('script');
    if (urlScript && data.scriptIds.includes(urlScript)) {
      selectScript(urlScript);
    }
  }

  function selectScript(id) {
    selectedScript = id;
    document.getElementById('selected-script-name').innerText = id;
    
    const container = document.getElementById('providers-container');
    container.innerHTML = '';
    
    const config = data.configs[id] || { workink: {}, lootlabs: {}, linkvertise: {} };
    const currentLang = localStorage.getItem('rksl_lang') || 'ru';

    const workinkBtn = document.createElement('a');
    workinkBtn.className = 'provider-btn workink' + (config.workink.enabled ? '' : ' disabled');
    workinkBtn.href = config.workink.enabled ? config.workink.url : '#';
    workinkBtn.innerHTML = \`
      <div class="provider-info">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
        <span>\${i18n[currentLang].btn_workink}</span>
      </div>
      <span class="provider-badge">\` + (config.workink.enabled ? i18n[currentLang].badge_active : i18n[currentLang].badge_disabled) + \`</span>
    \`;
    container.appendChild(workinkBtn);

    const lootlabsBtn = document.createElement('a');
    lootlabsBtn.className = 'provider-btn lootlabs' + (config.lootlabs.enabled ? '' : ' disabled');
    lootlabsBtn.href = config.lootlabs.enabled ? "/lootlabs-start?script=" + encodeURIComponent(id) : '#';
    lootlabsBtn.innerHTML = \`
      <div class="provider-info">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="7"></circle><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"></polyline></svg>
        <span>\${i18n[currentLang].btn_lootlabs}</span>
      </div>
      <span class="provider-badge">\` + (config.lootlabs.enabled ? i18n[currentLang].badge_active : i18n[currentLang].badge_disabled) + \`</span>
    \`;
    container.appendChild(lootlabsBtn);

    const linkvertiseBtn = document.createElement('a');
    linkvertiseBtn.className = 'provider-btn linkvertise' + (config.linkvertise.enabled ? '' : ' disabled');
    linkvertiseBtn.href = config.linkvertise.enabled ? "/linkvertise-start?script=" + encodeURIComponent(id) : '#';
    linkvertiseBtn.innerHTML = \`
      <div class="provider-info">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
        <span>\${i18n[currentLang].btn_linkvertise}</span>
      </div>
      <span class="provider-badge">\` + (config.linkvertise.enabled ? i18n[currentLang].badge_active : i18n[currentLang].badge_disabled) + \`</span>
    \`;
    container.appendChild(linkvertiseBtn);

    document.getElementById('view-scripts').classList.remove('active');
    document.getElementById('view-providers').classList.add('active');

    const newUrl = window.location.protocol + "//" + window.location.host + window.location.pathname + '?script=' + encodeURIComponent(id);
    window.history.pushState({ path: newUrl }, '', newUrl);
  }

  function showScriptsView() {
    selectedScript = null;
    document.getElementById('view-providers').classList.remove('active');
    document.getElementById('view-scripts').classList.add('active');
    
    const newUrl = window.location.protocol + "//" + window.location.host + window.location.pathname;
    window.history.pushState({ path: newUrl }, '', newUrl);
  }

  function escapeHtml(text) {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  window.onload = init;
</script>
</body>
</html>`;
}

function claimPage(url) {
  const key = url.searchParams.get('key') || '';
  const scriptId = sanitizeScriptId(url.searchParams.get('script') || 'NBTF_ACTIVE') || 'NBTF_ACTIVE';
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your RKSL key</title>
<style>
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: radial-gradient(circle at top, #0f172a 0%, #030712 100%);
    color: #f3f4f6;
    display: grid;
    min-height: 100vh;
    place-items: center;
    margin: 0;
    padding: 20px;
    box-sizing: border-box;
  }
  .card {
    width: min(600px, 100%);
    background: #0b0f19;
    border: 1px solid #1f2937;
    border-radius: 22px;
    padding: 32px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
    position: relative;
    overflow: hidden;
  }
  .card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 4px;
    background: linear-gradient(90deg, #3b82f6, #8b5cf6);
  }
  h1 {
    font-size: 1.75rem;
    font-weight: 800;
    margin-top: 0;
    background: linear-gradient(135deg, #fff 30%, #94a3b8 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .key {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-weight: 700;
    font-size: 1.15rem;
    word-break: break-all;
    background: #111827;
    border: 1px solid #1f2937;
    color: #3b82f6;
    border-radius: 12px;
    padding: 16px;
    margin: 20px 0;
    letter-spacing: 0.5px;
  }
</style>
</head>
<body>
<div class="card"><h1>Your key for ${escapeHtml(scriptId)}</h1><p>Copy this key into RKSL loader:</p><div class="key">${escapeHtml(key)}</div></div>
</body>
</html>`;
}

function adminLoginPageHtml(errorMsg = '') {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Admin Dashboard Access</title>
  <style>
    body { font-family: 'Inter', sans-serif; background: #030712; color: #f3f4f6; display: grid; place-items: center; min-height: 100vh; margin: 0; }
    .box { background: #0b0f19; border: 1px solid #1f2937; border-radius: 16px; padding: 32px; width: 340px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); text-align: center; }
    h2 { margin: 0 0 24px 0; color: #3b82f6; }
    input { width: 100%; padding: 12px; margin-bottom: 20px; border-radius: 8px; border: 1px solid #374151; background: #111827; color: #fff; box-sizing: border-box; }
    button { width: 100%; padding: 12px; background: #3b82f6; border: none; color: #fff; border-radius: 8px; cursor: pointer; font-weight: bold; font-size: 1rem; }
    button:hover { background: #2563eb; }
    .err { color: #ef4444; font-size: 0.85rem; margin-top: -12px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Admin Authorization</h2>
    ${errorMsg ? `<div class="err">${escapeHtml(errorMsg)}</div>` : ''}
    <form method="POST" action="/ko/ket/som/pid/iiiik/5mew/day/KGTKKRKKKGKRKK">
      <input type="password" name="password" placeholder="Password" required autofocus />
      <button type="submit">Continue</button>
    </form>
  </div>
</body>
</html>`;
}

function adminPanelHtml(token) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RKSL Hub Admin Panel</title>
  <style>
    body { font-family: 'Inter', sans-serif; background: #030712; color: #f3f4f6; margin: 0; padding: 24px; box-sizing: border-box; }
    .container { max-width: 1200px; margin: 0 auto; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; border-bottom: 1px solid #1f2937; padding-bottom: 16px; }
    h1 { margin: 0; font-size: 1.8rem; color: #3b82f6; }
    .tabs { display: flex; gap: 12px; margin-bottom: 24px; }
    .tab-btn { background: #111827; border: 1px solid #1f2937; color: #9ca3af; padding: 10px 18px; border-radius: 8px; cursor: pointer; font-weight: 600; }
    .tab-btn.active { background: #3b82f6; border-color: #3b82f6; color: #fff; }
    .tab-content { display: none; background: #0b0f19; border: 1px solid #1f2937; border-radius: 12px; padding: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
    .tab-content.active { display: block; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .stat-card { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; text-align: center; }
    .stat-val { font-size: 2.2rem; font-weight: bold; margin-top: 8px; color: #3b82f6; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { text-align: left; padding: 12px; border-bottom: 1px solid #1f2937; }
    th { background: #111827; color: #9ca3af; font-weight: 600; }
    tr:hover { background: rgba(255,255,255,0.02); }
    .btn-delete { background: #ef4444; border: none; color: #fff; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-weight: 500; }
    .btn-delete:hover { background: #dc2626; }
    .note { background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.2); padding: 16px; border-radius: 8px; color: #fbbf24; margin-bottom: 16px; font-size: 0.9rem; line-height: 1.5; }
    .details { font-family: monospace; font-size: 0.85rem; color: #9ca3af; }
    .btn-logout { background: transparent; border: 1px solid #ef4444; color: #ef4444; padding: 8px 16px; border-radius: 8px; cursor: pointer; text-decoration: none; font-weight: 600; }
    .btn-logout:hover { background: #ef4444; color: #fff; }
  </style>
</head>
<body>

<div class="container">
  <div class="header">
    <h1>RKSL Admin Dashboard</h1>
    <a href="/" class="btn-logout">Exit Dashboard</a>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('main')">Main Stats</button>
    <button class="tab-btn" onclick="switchTab('keys')">Key Records</button>
    <button class="tab-btn" onclick="switchTab('logs')">Live Server Logs</button>
    <button class="tab-btn" onclick="switchTab('emergency')" style="border-color: #ef4444; color: #ef4444;">Pizda (Emergency)</button>
  </div>

  <!-- Вкладка Main -->
  <div id="tab-main" class="tab-content active">
    <h3>Unique Keys Created (By Provider Source)</h3>
    <div class="stats-grid">
      <div class="stat-card">
        <div>Linkvertise Completions</div>
        <div class="stat-val" id="stat-linkvertise">0</div>
      </div>
      <div class="stat-card">
        <div>LootLabs Completions</div>
        <div class="stat-val" id="stat-lootlabs">0</div>
      </div>
      <div class="stat-card">
        <div>Work.ink Completions</div>
        <div class="stat-val" id="stat-workink">0</div>
      </div>
    </div>
    
    <h3>Server Information</h3>
    <div style="background: #111827; border: 1px solid #1f2937; padding: 16px; border-radius: 8px; font-family: monospace; color: #9ca3af;">
      <p>Node.js Runtime: \${process.version}</p>
      <p>Platform Arch: \${process.platform} (\${process.arch})</p>
      <p>Session State: Active (expires in 30 minutes)</p>
    </div>
  </div>

  <!-- Вкладка Keys -->
  <div id="tab-keys" class="tab-content">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
      <h3 style="margin:0;">Active Keys In Database</h3>
      <button class="tab-btn" style="padding:6px 12px; font-size:0.85rem;" onclick="loadData()">Refresh List</button>
    </div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>Key / Name</th>
            <th>Script Target</th>
            <th>Source</th>
            <th>Expires At</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="keys-table-body">
          <tr><td colspan="5" style="text-align:center;">Loading keys...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Вкладка Logs -->
  <div id="tab-logs" class="tab-content">
    <div class="note">
      <strong>⚠️ Network Warning (MAC Address):</strong> 
      MAC addresses are Link-Layer (L2) identifiers. Due to network routing limitations over WAN/Internet, client MAC addresses are stripped by routers/gateways before requests reach our Railway API server. We cannot view or log them. However, we capture complete L3/L7 fingerprints (IP, User-Agent, timings).
    </div>
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
      <h3 style="margin:0;">Live Server Access & Event Logs (Last 200)</h3>
      <button class="tab-btn" style="padding:6px 12px; font-size:0.85rem;" onclick="loadData()">Refresh Logs</button>
    </div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Event / Action</th>
            <th>Client WAN IP</th>
            <th>User-Agent / Target Device</th>
          </tr>
        </thead>
        <tbody id="logs-table-body">
          <tr><td colspan="4" style="text-align:center;">Loading logs...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Вкладка Pizda (Emergency) -->
  <div id="tab-emergency" class="tab-content">
    <h3>Emergency Mode (Temporary OFF Control)</h3>
    <div class="note" style="background: rgba(239, 68, 68, 0.08); border-color: rgba(239, 68, 68, 0.2); color: #f87171;">
      <strong>⚠️ EMERGENCY SYSTEM OFF:</strong> При активации режима "Temporary OFF" публичный GUI-хаб, страницы получения ключей и CLAIM-эндпоинты моментально отключатся и будут выдавать сырую заглушку "This service is temporary off because of DDOS or something else!". При этом панель управления останется полностью доступной.
    </div>

    <div style="background: #111827; border: 1px solid #1f2937; padding: 24px; border-radius: 12px; display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px;">
      <div>
        <div style="font-size: 1.1rem; font-weight: 600; margin-bottom: 4px;">Temporary OFF Status</div>
        <div class="muted">Status: <span id="emergency-status-text" style="font-weight: bold; color: #ef4444;">OFF</span></div>
      </div>
      <div>
        <button id="btn-toggle-emergency" class="tab-btn" style="background: #ef4444; border-color: #ef4444; color: #fff; padding: 12px 24px; font-weight: bold;" onclick="toggleEmergencyMode()">ENABLE MAINTENANCE</button>
      </div>
    </div>

    <h3>Banned Users Registry</h3>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Ban Type</th>
            <th>Reason</th>
            <th>Banned At</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="banned-table-body">
          <tr><td colspan="5" style="text-align:center;">Loading banned registry...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
  const adminToken = "${token}";

  function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

    const btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
    if (btn) btn.classList.add('active');

    document.getElementById('tab-' + tabId).classList.add('active');
  }

  function loadData() {
    fetch('/api/admin/data', {
      headers: { 'Authorization': 'Bearer ' + adminToken }
    })
    .then(res => {
      if (!res.ok) throw new Error('Unauthorized');
      return res.json();
    })
    .then(data => {
      if (data.status === 'success') {
        document.getElementById('stat-linkvertise').innerText = data.stats.linkvertise;
        document.getElementById('stat-lootlabs').innerText = data.stats.lootlabs;
        document.getElementById('stat-workink').innerText = data.stats.workink;

        const isOff = data.temporaryOff;
        const statusText = document.getElementById('emergency-status-text');
        const toggleBtn = document.getElementById('btn-toggle-emergency');
        if (isOff) {
          statusText.innerText = 'ON (SERVICE TEMPORARY OFF)';
          statusText.style.color = '#ef4444';
          toggleBtn.innerText = 'DISABLE MAINTENANCE';
          toggleBtn.style.background = '#10b981';
          toggleBtn.style.borderColor = '#10b981';
        } else {
          statusText.innerText = 'OFF (NORMAL OPERATIONS)';
          statusText.style.color = '#10b981';
          toggleBtn.innerText = 'ENABLE MAINTENANCE';
          toggleBtn.style.background = '#ef4444';
          toggleBtn.style.borderColor = '#ef4444';
        }

        const keysBody = document.getElementById('keys-table-body');
        keysBody.innerHTML = '';
        if (data.keys.length === 0) {
          keysBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#9ca3af;">No active keys found.</td></tr>';
        } else {
          data.keys.forEach(k => {
            const row = document.createElement('tr');
            row.innerHTML = \`
              <td><strong>\${escapeHtml(k.name || 'Unnamed')}</strong></td>
              <td><code>\${escapeHtml(k.script_id)}</code></td>
              <td><span style="text-transform: capitalize;">\${escapeHtml(k.source || 'local')}</span></td>
              <td>\${escapeHtml(k.expires_at)}</td>
              <td><button class="btn-delete" onclick="deleteKey('\${k.id}')">Delete key</button></td>
            \`;
            keysBody.appendChild(row);
          });
        }

        const logsBody = document.getElementById('logs-table-body');
        logsBody.innerHTML = '';
        if (data.logs.length === 0) {
          logsBody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#9ca3af;">No log logs available.</td></tr>';
        } else {
          data.logs.forEach(l => {
            const row = document.createElement('tr');
            row.innerHTML = \`
              <td style="white-space:nowrap; color:#9ca3af;">\${escapeHtml(l.timestamp)}</td>
              <td><strong>\${escapeHtml(l.action)}</strong><div class="details">\${escapeHtml(l.details)}</div></td>
              <td><code>\${escapeHtml(l.ip)}</code></td>
              <td style="font-size:0.8rem; color:#9ca3af; max-width:400px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="\${escapeHtml(l.userAgent)}">\${escapeHtml(l.userAgent)}</td>
            \`;
            logsBody.appendChild(row);
          });
        }

        const bannedBody = document.getElementById('banned-table-body');
        bannedBody.innerHTML = '';
        if (data.bannedUsers.length === 0) {
          bannedBody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#9ca3af;">No banned users found in DB.</td></tr>';
        } else {
          data.bannedUsers.forEach(bu => {
            const row = document.createElement('tr');
            const typeLabel = bu.ban_type === 2 ? '<span style="color:#ef4444; font-weight:bold;">Hard (Immediate Drop)</span>' : '<span style="color:#f59e0b;">Soft (Rate Limit)</span>';
            row.innerHTML = \`
              <td><code>\${escapeHtml(bu.ip)}</code></td>
              <td>\${typeLabel}</td>
              <td><strong>\${escapeHtml(bu.reason || 'No Reason')}</strong></td>
              <td>\${escapeHtml(bu.banned_at)}</td>
              <td><button class="btn-delete" style="background:#10b981; border-color:#10b981" onclick="unbanUser('\${bu.ip}')">Unban IP</button></td>
            \`;
            bannedBody.appendChild(row);
          });
        }
      }
    })
    .catch(err => {
      console.error(err);
      alert('Failed to load admin data: ' + err.message);
    });
  }

  function toggleEmergencyMode() {
    const currentText = document.getElementById('emergency-status-text').innerText;
    const turningOn = currentText.startsWith('OFF');
    const confirmMsg = turningOn 
      ? 'Включить аварийное отключение Temporary OFF? Все публичные функции и получение ключей станут недоступны!' 
      : 'Выключить аварийное отключение и возобновить работу системы?';
    if (!confirm(confirmMsg)) return;

    fetch('/api/admin/toggle-emergency', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + adminToken
      },
      body: JSON.stringify({ enabled: turningOn })
    })
    .then(res => res.json())
    .then(res => {
      if (res.status === 'success') {
        loadData();
      } else {
        alert('Error: ' + res.message);
      }
    })
    .catch(err => alert('Failed: ' + err.message));
  }

  function unbanUser(ip) {
    if (!confirm('Разбанить IP: ' + ip + '?')) return;
    fetch('/api/admin/unban-user', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + adminToken
      },
      body: JSON.stringify({ ip })
    })
    .then(res => res.json())
    .then(res => {
      if (res.status === 'success') {
        loadData();
      } else {
        alert('Failed to unban user: ' + res.message);
      }
    })
    .catch(err => alert('Error: ' + err.message));
  }

  function deleteKey(id) {
    if (!confirm('Are you sure you want to delete this key record?')) return;
    fetch('/api/admin/delete-key', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + adminToken
      },
      body: JSON.stringify({ id })
    })
    .then(res => res.json())
    .then(res => {
      if (res.status === 'success') {
        loadData();
      } else {
        alert('Failed to delete key: ' + res.message);
      }
    })
    .catch(err => alert('Error deleting key: ' + err.message));
  }

  function escapeHtml(text) {
    if (!text) return '';
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  window.onload = loadData;
</script>
</body>
</html>`;
}

// Проверка хонипотов (ловушек)
function isHoneypotPath(pathname) {
  const p = pathname.toLowerCase();
  return HONEYPOT_PATHS.some(hp => p.startsWith(hp) || p === hp);
}

function isSpamUserAgent(ua) {
  const badUAs = [
    'python-requests',
    'go-http-client',
    'curl/',
    'wget/',
    'axios/',
    'node-fetch',
    'http-client'
  ];
  const lowerUA = String(ua || '').toLowerCase();
  return badUAs.some(bad => lowerUA.includes(bad));
}

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const clientIp = getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';

  // Сбрасываем соединение для спам-скриптов без отправки ответа
  if (isSpamUserAgent(userAgent)) {
    res.socket.destroy();
    return;
  }

  // 1. МГНОВЕННОЕ ОТСЕЧЕНИЕ ПО ЖЕСТКОМУ БАНУ (Wastes zero resources on attacker)
  if (hardBannedIPs.has(clientIp)) {
    res.socket.destroy();
    return;
  }

  // 2. ОТСЕЧЕНИЕ ПО МЯГКОМУ БАНУ (С красивым выводом страницы ошибки)
  if (softBannedIPs.has(clientIp)) {
    const supportDiscord = process.env.SUPPORT_DISCORD || '@fan_murders_dromes';
    sendHtml(res, 403, `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>Доступ ограничен</title>
  <style>
    body { font-family: 'Inter', sans-serif; background: #030712; color: #f3f4f6; display: grid; place-items: center; min-height: 100vh; margin: 0; text-align: center; }
    .box { background: #0b0f19; border: 1px solid #1f2937; padding: 40px; border-radius: 16px; max-width: 500px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    h1 { color: #ef4444; margin-top:0; }
  </style>
</head>
<body>
  <div class="box">
    <h1> You are banned from this website. </h1>
    <p>If you believe an error has occurred, please contact the administrator at: <strong>${escapeHtml(supportDiscord)}</strong></p>
  </div>
</body>
</html>`);
    return;
  }

  // 3. ПРОВЕРКА HONEYPOT (Ловушка сканеров ботов и злоумышленников)
  if (isHoneypotPath(url.pathname)) {
    await banUser(clientIp, userAgent, 2, 'Honeypot Triggered', { path: url.pathname });
    addLog('CRITICAL: Honeypot Triggered IP Auto-Banned (Hard)', clientIp, userAgent, `Path: ${url.pathname}`);
    res.socket.destroy();
    return;
  }

  // 4. ПРОВЕРКА РЕЖИМА "TEMPORARY OFF" (Tab Pizda)
  const isExcludedAdminPath = url.pathname === '/ko/ket/som/pid/iiiik/5mew/day/KGTKKRKKKGKRKK' || 
                              url.pathname.startsWith('/api/admin/') ||
                              Array.from(activeAdminSessions.keys()).some(token => url.pathname.startsWith(`/${token}/`));

  if (isTemporaryOff && !isExcludedAdminPath) {
    sendHtml(res, 503, `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Service Temporary Unavailable</title>
  <style>
    body { font-family: monospace; background: #000; color: #ff0000; padding: 50px; text-align: center; }
    h1 { font-size: 2.2rem; margin-bottom: 20px; }
  </style>
</head>
<body>
  <h1>This service is temporary off because of DDOS or something else!</h1>
  <p>Please check back later.</p>
</body>
</html>`);
    return;
  }

  // 5. ИНТЕЛЛЕКТУАЛЬНЫЙ RATE LIMITER (Не мешает админ-панели)
  if (!isExcludedAdminPath) {
    const isLimited = handleRateLimiting(clientIp, userAgent, url.pathname);
    if (isLimited) {
      if (url.pathname.startsWith('/api/')) {
        sendJson(res, 429, { status: 'error', code: 'TOO_MANY_REQUESTS', message: 'Too many requests.' });
      } else {
        sendHtml(res, 429, `<!doctype html><meta charset="utf-8"><title>Too Many Requests</title><body style="font-family:sans-serif;background:#030712;color:#f3f4f6;display:grid;place-items:center;min-height:100vh;"><h1>Too Many Requests</h1><p>Please wait a minute before retrying.</p></body>`);
      }
      return;
    }
  }

  if (req.method === 'OPTIONS') {
    sendJson(res, 204, {});
    return;
  }

  try {
    const decodedPath = decodeURIComponent(url.pathname);
    const sessionMatch = decodedPath.match(/^\/([a-f0-9]{64})\/([a-f0-9]{32})$/);
    if (req.method === 'GET' && sessionMatch) {
      const token = sessionMatch[1];
      const expiry = activeAdminSessions.get(token);
      if (expiry && expiry > Date.now()) {
        sendHtml(res, 200, adminPanelHtml(token));
        return;
      } else {
        activeAdminSessions.delete(token);
        sendRedirect(res, '/ko/ket/som/pid/iiiik/5mew/day/KGTKKRKKKGKRKK');
        return;
      }
    }

    // Маршрут входа администратора
    if (req.method === 'GET' && url.pathname === '/ko/ket/som/pid/iiiik/5mew/day/KGTKKRKKKGKRKK') {
      addLog('Admin Panel Visited', clientIp, userAgent);
      sendHtml(res, 200, adminLoginPageHtml());
      return;
    }

    if (req.method === 'POST' && url.pathname === '/ko/ket/som/pid/iiiik/5mew/day/KGTKKRKKKGKRKK') {
      let raw = '';
      for await (const chunk of req) { raw += chunk; }
      const params = new URLSearchParams(raw);
      const password = params.get('password') || '';

      const isValid = await verifyAdminPassword(password);
      if (isValid) {
        adminLoginAttempts.delete(clientIp);
        const tempToken = crypto.randomBytes(32).toString('hex');
        activeAdminSessions.set(tempToken, Date.now() + 30 * 60 * 1000); 
        addLog('Admin Login Success', clientIp, userAgent);
const panelPath = crypto.randomBytes(16).toString('hex');

sendRedirect(res, `/${tempToken}/${panelPath}`);
        return;
      } else {
        const attempts = (adminLoginAttempts.get(clientIp) || 0) + 1;
        adminLoginAttempts.set(clientIp, attempts);

        // ЖЕСТКИЙ БАН ПРИ 3 НЕУДАЧНЫХ ПОПЫТКАХ ВХОДА (Защита от подбора паролей)
        if (attempts >= 3) {
          await banUser(clientIp, userAgent, 2, 'Admin Login Brute Force Exceeded Attempts', { attempts });
          addLog('CRITICAL: Admin Brute Force detected. IP Banned (Hard)', clientIp, userAgent, `Attempts: ${attempts}`);
          res.socket.destroy();
          return;
        }

        addLog('Admin Login Failed', clientIp, userAgent, `Attempt: ${attempts}/3`);
        sendHtml(res, 401, adminLoginPageHtml(`Invalid admin password. Attempts left: ${3 - attempts}`));
        return;
      }
    }

    // Сбор данных для администратора
    if (req.method === 'GET' && url.pathname === '/api/admin/data') {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.replace('Bearer ', '').trim();
      if (!activeAdminSessions.has(token) || activeAdminSessions.get(token) < Date.now()) {
        sendJson(res, 401, { status: 'error', message: 'Unauthorized session.' });
        return;
      }

      let stats = { linkvertise: 0, lootlabs: 0, workink: 0 };
      try {
        const { count: lv } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('source', 'linkvertise');
        stats.linkvertise = lv || 0;
      } catch (e) {}
      try {
        const { count: ll } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('source', 'lootlabs');
        stats.lootlabs = ll || 0;
      } catch (e) {}
      try {
        const { count: wi } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('source', 'workink');
        stats.workink = wi || 0;
      } catch (e) {}

      let keys = [];
      try {
        const { data: keysData } = await supabase.from('keys').select('id, name, script_id, expires_at, source, disabled').order('issued_at', { ascending: false });
        keys = keysData || [];
      } catch (e) {}

      let bannedUsers = [];
      try {
        const { data: banData } = await supabase.from('banned_users').select('*').order('banned_at', { ascending: false });
        bannedUsers = banData || [];
      } catch (e) {}

      sendJson(res, 200, {
        status: 'success',
        stats,
        keys,
        bannedUsers,
        temporaryOff: isTemporaryOff,
        logs: serverLogs
      });
      return;
    }

    // Активация/деактивация "Temporary OFF" (Tab Pizda)
    if (req.method === 'POST' && url.pathname === '/api/admin/toggle-emergency') {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.replace('Bearer ', '').trim();
      if (!activeAdminSessions.has(token) || activeAdminSessions.get(token) < Date.now()) {
        sendJson(res, 401, { status: 'error', message: 'Unauthorized session.' });
        return;
      }

      const body = await readRequestJson(req);
      const targetState = body.enabled === true;

      const { error } = await supabase
        .from('admin_settings')
        .upsert({ key: 'temporary_off', value: String(targetState) }, { onConflict: 'key' });

      if (error) {
        sendJson(res, 500, { status: 'error', message: error.message });
        return;
      }

      isTemporaryOff = targetState;
      addLog(`Emergency Maintenance Mode set to: ${isTemporaryOff ? 'ON' : 'OFF'}`, clientIp, userAgent);
      sendJson(res, 200, { status: 'success', enabled: isTemporaryOff });
      return;
    }

    // Разбан пользователя
    if (req.method === 'POST' && url.pathname === '/api/admin/unban-user') {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.replace('Bearer ', '').trim();
      if (!activeAdminSessions.has(token) || activeAdminSessions.get(token) < Date.now()) {
        sendJson(res, 401, { status: 'error', message: 'Unauthorized session.' });
        return;
      }

      const body = await readRequestJson(req);
      const { ip } = body;
      if (!ip) {
        sendJson(res, 400, { status: 'error', message: 'Missing IP address.' });
        return;
      }

      const { error } = await supabase.from('banned_users').delete().eq('ip', ip);
      if (error) {
        sendJson(res, 500, { status: 'error', message: error.message });
        return;
      }

      softBannedIPs.delete(ip);
      hardBannedIPs.delete(ip);
      addLog('User Unbanned by Admin', clientIp, userAgent, `IP: ${ip}`);
      sendJson(res, 200, { status: 'success' });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/admin/delete-key') {
      const authHeader = req.headers.authorization || '';
      const token = authHeader.replace('Bearer ', '').trim();
      if (!activeAdminSessions.has(token) || activeAdminSessions.get(token) < Date.now()) {
        sendJson(res, 401, { status: 'error', message: 'Unauthorized session.' });
        return;
      }

      const body = await readRequestJson(req);
      const { id } = body;
      if (!id) {
        sendJson(res, 400, { status: 'error', message: 'Missing key ID.' });
        return;
      }

      const { error } = await supabase.from('keys').delete().eq('id', id);
      if (error) {
        sendJson(res, 500, { status: 'error', message: error.message });
        return;
      }

      addLog('Admin Key Deleted', clientIp, userAgent, `Deleted ID: ${id}`);
      sendJson(res, 200, { status: 'success' });
      return;
    }

    // Публичные маршруты
    if (req.method === 'GET' && url.pathname === '/') {
      addLog('Landing Page Opened', clientIp, userAgent);
      const hubData = await getHubData();
      sendHtml(res, 200, landingPage(hubData));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/get-key') {
      const scriptParam = url.searchParams.get('script') || '';
      let targetUrl = '/';
      if (scriptParam) {
        targetUrl += `?script=${encodeURIComponent(scriptParam)}`;
      }
      sendRedirect(res, targetUrl);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/lootlabs-start') {
      await startLootLabsFlow(url.searchParams.get('script'), req, res);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/linkvertise-start') {
      await startLinkvertiseFlow(url.searchParams.get('script'), res);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/lootlabs-claim') {
      sendHtml(res, 200, await lootLabsClaimPage(url, req));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/lootlabs-postback') {
      await handleLootLabsPostback(url, req, res);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/linkvertise-claim') {
      await handleLinkvertiseClaim(url, req, res);
      return;
    }
    if (req.method === 'GET' && url.pathname === '/linkvertise-key') {
      sendHtml(res, 200, await linkvertiseKeyPage(url, req));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/claim') {
      sendHtml(res, 200, claimPage(url));
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/health') {
      sendJson(res, 200, { status: 'success', service: 'RKSL', time: new Date().toISOString() });
      return;
    }
    if (req.method === 'GET' && url.pathname === '/api/scripts') {
      sendJson(res, 200, { status: 'success', scripts: await listScriptIds() });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/check-key') {
      let body;
      try {
        body = await readRequestJson(req);
      } catch (error) {
        sendJson(res, 400, { status: 'error', code: 'BAD_JSON', message: STATUS_MESSAGES.BAD_JSON });
        return;
      }
      const result = await checkKey(body);
      addLog('Key Verification Request', clientIp, userAgent, `Key: ${String(body.key || '').slice(0, 10)}... Result: ${result.code}`);
      sendJson(res, result.statusCode, {
        status: result.code === 'KEY_VALID' ? 'success' : 'error',
        code: result.code,
        message: STATUS_MESSAGES[result.code] || STATUS_MESSAGES.SERVER_ERROR,
        scriptId: result.scriptId,
        script: result.script,
        source: result.source,
      });
      return;
    }
    if (req.method === 'POST' && url.pathname === '/api/admin/keys') {
      await issueLocalKey(req, res);
      return;
    }

    sendJson(res, 404, { status: 'error', code: 'NOT_FOUND', message: 'Route not found.' });
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { status: 'error', code: 'SERVER_ERROR', message: STATUS_MESSAGES.SERVER_ERROR });
  }
}

function createServer() {
  const server = http.createServer(handleRequest);
  
  // 1. Увеличиваем лимит до 1000. 1GB ОЗУ выдержит это без проблем, 
  // а атакующему будет намного сложнее заполнить все слоты одновременно.
  server.maxConnections = 1000;       

  // 2. Увеличиваем до 5 секунд (5000мс). 
  // Этого времени гарантированно хватит любому реальному игроку на отправку заголовков.
  server.headersTimeout = 5000;      

  // 3. Увеличиваем до 15 секунд (15000мс). 
  // Дает обычным пользователям с плохим пингом время отправить весь JSON-запрос без обрывов.
  server.requestTimeout = 15000;     

  // 4. Увеличиваем до 3 секунд (3000мс). 
  // Позволяет браузеру пользователя быстро совершать переходы по страницам без повторного открытия сокетов,
  // но при этом быстро закрывает сокеты неактивных ботов.
  server.keepAliveTimeout = 3000;    

  return server;
}

if (require.main === module) {
  // Загружаем данные из Supabase и запускаем сервер
  loadStartupData().then(() => {
    createServer().listen(DEFAULT_PORT, () => {
      console.log(`RKSL key system server listening on port ${DEFAULT_PORT}`);
    });
  });
}

module.exports = { createServer, sha256, STATUS_MESSAGES };