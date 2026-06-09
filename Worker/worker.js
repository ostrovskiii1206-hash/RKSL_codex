const DEFAULT_SERVERS_CACHE_TTL_MS = 60_000;

function parseServers(env) {
  return String(env.RKSL_BACKENDS || '')
    .split(',')
    .map((url) => url.trim().replace(/\/+$/, ''))
    .filter(Boolean);
}

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function chooseBackend(request, env, ctx) {
  const servers = parseServers(env);
  if (!servers.length) throw new Error('RKSL_BACKENDS is empty');

  const cacheTtl = Number(env.RKSL_SERVERS_CACHE_TTL_MS || DEFAULT_SERVERS_CACHE_TTL_MS);
  const cacheKey = new Request('https://rksl-worker.local/backend-index');
  const cached = await caches.default.match(cacheKey);
  let index = 0;
  if (cached) {
    const payload = await cached.json();
    index = Number(payload.nextIndex || 0);
  } else if (env.RKSL_SERVERS_KV) {
    index = Number((await env.RKSL_SERVERS_KV.get('next_backend_index')) || 0);
  }

  const selected = servers[index % servers.length];
  const nextIndex = (index + 1) % servers.length;
  const cacheResponse = Response.json({ nextIndex }, { headers: { 'Cache-Control': `max-age=${Math.max(1, Math.floor(cacheTtl / 1000))}` } });
  ctx.waitUntil(caches.default.put(cacheKey, cacheResponse.clone()));
  if (env.RKSL_SERVERS_KV) ctx.waitUntil(env.RKSL_SERVERS_KV.put('next_backend_index', String(nextIndex), { expirationTtl: 300 }));
  return selected;
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    },
  });
}

async function signedProxy(request, env, ctx, backendPath) {
  const backend = await chooseBackend(request, env, ctx);
  const body = request.method === 'GET' ? '' : await request.text();
  const timestamp = String(Date.now());
  const nonce = crypto.randomUUID();
  const secret = String(env.WORKER_HMAC_SECRET || '').trim();
  if (!secret) return jsonResponse({ status: 'error', message: 'WORKER_HMAC_SECRET is not configured.' }, 500);

  const signature = await hmacHex(secret, `${timestamp}.${nonce}.${body}`);
  const target = new URL(backendPath, backend);
  const sourceUrl = new URL(request.url);
  target.search = sourceUrl.search;

  const headers = new Headers(request.headers);
  headers.set('X-RKSL-Worker-Timestamp', timestamp);
  headers.set('X-RKSL-Worker-Nonce', nonce);
  headers.set('X-RKSL-Worker-Signature', signature);
  headers.set('X-RKSL-Worker-Backend', backend);
  headers.set('Content-Type', headers.get('Content-Type') || 'application/json');

  const response = await fetch(target, {
    method: request.method,
    headers,
    body: request.method === 'GET' ? undefined : body,
    redirect: 'manual',
  });

  const responseHeaders = new Headers(response.headers);
  responseHeaders.set('X-RKSL-Selected-Backend', backend);
  return new Response(response.body, { status: response.status, headers: responseHeaders });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return jsonResponse({}, 204);

    if (request.method === 'POST' && url.pathname === '/verify-key') {
      return signedProxy(request, env, ctx, '/api/check-key');
    }

    if (url.pathname === '/health') {
      return signedProxy(request, env, ctx, '/api/health');
    }

    const passthroughRoutes = new Map([
      ['/get-key', '/'],
      ['/lootlabs-start', '/lootlabs-start'],
      ['/lootlabs-claim', '/lootlabs-claim'],
      ['/linkvertise-start', '/linkvertise-start'],
      ['/linkvertise-claim', '/linkvertise-claim'],
      ['/linkvertise-key', '/linkvertise-key'],
      ['/claim', '/claim'],
      ['/', '/'],
    ]);

    const backendPath = passthroughRoutes.get(url.pathname);
    if (backendPath) return signedProxy(request, env, ctx, backendPath);

    return jsonResponse({ status: 'error', message: 'Not found.' }, 404);
  },
};
