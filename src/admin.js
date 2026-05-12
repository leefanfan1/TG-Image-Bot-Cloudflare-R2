// Web management dashboard for the image bed
import { checkRateLimit, secureHeaders, cspHeaders, parseAllowedUsers, generateId, getExtension, isValidImageMime } from './utils.js';
import {
  beginRegistration, completeRegistration,
  beginAuthentication, completeAuthentication,
  listCredentials, deleteCredential,
} from './webauthn.js';

async function handleLogout(request, env) {
  const cookies = parseCookies(request);
  const token = cookies.admin_token;
  if (token) {
    if (token.startsWith("wa:")) {
      await env.IMG_KV.delete("wa:session:" + token);
    } else if (token.startsWith("tg:")) {
      await env.IMG_KV.delete("session:" + token);
    }
  }
  const resp = new Response(JSON.stringify({ ok: true }), {
    headers: { ...secureHeaders({ "Content-Type": "application/json" }), ...cspHeaders() },
  });
  resp.headers.set("Set-Cookie", "admin_token=; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=0");
  return resp;
}

export function handleAdminRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Serve admin page
  if (path === '/admin' || path === '/admin/') {
    if (request.method === 'GET') {
      // Handle one-time login token from bot deep-link auth
      const loginToken = url.searchParams.get('login_token');
      if (loginToken) {
        return handleLoginToken(env, loginToken, request);
      }
      return serveAdminPage(env);
    }
    return new Response('Method not allowed', { status: 405, headers: secureHeaders() });
  }

  // Auth API
  if (path === '/admin/api/check-session' && request.method === 'GET')
    return handleCheckSession(request, env);
  if (path === '/admin/api/tg-login' && request.method === 'POST')
    return handleTelegramLogin(request, env);
  if (path === '/admin/api/logout' && request.method === 'POST')
    return handleLogout(request, env);

  // Image management
  if (path === '/admin/api/images' && request.method === 'GET')
    return handleListImages(request, env);
  if (path === '/admin/api/delete' && request.method === 'POST')
    return handleDeleteImage(request, env);
  if (path === '/admin/api/batch-delete' && request.method === 'POST')
    return handleBatchDelete(request, env);
  if (path === '/admin/api/upload' && request.method === 'POST')
    return handleAdminUpload(request, env);
  if (path === '/admin/api/export' && request.method === 'GET')
    return handleExport(request, env);

  // WebAuthn endpoints
  if (path === '/admin/api/webauthn/register/begin' && request.method === 'POST')
    return handleWebAuthnRegisterBegin(request, env);
  if (path === '/admin/api/webauthn/register/complete' && request.method === 'POST')
    return handleWebAuthnRegisterComplete(request, env);
  if (path === '/admin/api/webauthn/auth/begin' && request.method === 'POST')
    return handleWebAuthnAuthBegin(request, env);
  if (path === '/admin/api/webauthn/auth/complete' && request.method === 'POST')
    return handleWebAuthnAuthComplete(request, env);
  if (path === '/admin/api/webauthn/credentials' && request.method === 'GET')
    return handleWebAuthnCredentials(request, env);
  if (path === '/admin/api/webauthn/credentials/delete' && request.method === 'POST')
    return handleWebAuthnDeleteCredential(request, env);
  if (path === '/admin/api/webauthn/setup-status' && request.method === 'GET')
    return handleWebAuthnSetupStatus(request, env);

  // Account management
  if (path === '/admin/api/delete-account' && request.method === 'POST')
    return handleDeleteAccount(request, env);

  return new Response('Not found', { status: 404, headers: secureHeaders() });
}

// --- Auth helpers ---

function parseCookies(request) {
  const cookie = request.headers.get('Cookie') || '';
  const result = {};
  cookie.split(';').forEach(c => {
    const m = c.trim().match(/^([^=]+)=(.*)$/);
    if (m) result[m[1].trim()] = m[2].trim();
  });
  return result;
}

function isLocalhost(request) {
  const url = new URL(request.url);
  return url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '::1';
}

async function setSessionCookie(response, token, request) {
  const secure = request ? !isLocalhost(request) : true;
  response.headers.set('Set-Cookie',
    `admin_token=${token}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400${secure ? '; Secure' : ''}`);
  return response;
}

async function checkSession(request, env) {
  const cookies = parseCookies(request);
  const token = cookies.admin_token;
  if (!token) return null;

  // WebAuthn session
  if (token.startsWith('wa:')) {
    const waToken = await env.IMG_KV.get('wa:session:' + token);
    if (waToken) return 'webauthn';
    return null;
  }

  // Telegram login session (stored in KV with 24h TTL)
  if (token.startsWith('tg:')) {
    const tgSession = await env.IMG_KV.get('session:' + token);
    if (tgSession) return 'telegram';
  }

  return null;
}

function unauthorized() {
  return new Response(JSON.stringify({ error: 'Unauthorized' }), {
    status: 401,
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

// --- Session Check ---

async function handleCheckSession(request, env) {
  const auth = await checkSession(request, env);
  return new Response(JSON.stringify({ authenticated: !!auth, method: auth }), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

// --- Telegram Login ---

async function handleTelegramLogin(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, `admin-login:${ip}`, 10, 60))) {
    return new Response(JSON.stringify({ error: 'Too many requests' }), {
      status: 429, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  if (!request.headers.get('content-type')?.includes('application/json')) {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  let authData;
  try { authData = await request.json(); } catch {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
  if (!authData || !authData.hash || !authData.id || !authData.auth_date) {
    return new Response(JSON.stringify({ error: 'Invalid auth data' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  // Verify HMAC-SHA256 signature
  const { hash, ...data } = authData;
  const keys = Object.keys(data).sort();
  const dataCheckString = keys.map(k => `${k}=${data[k]}`).join('\n');

  // Compute secret key = SHA-256(BOT_TOKEN)
  const enc = new TextEncoder();
  const secretKeyBytes = await crypto.subtle.digest('SHA-256', enc.encode(env.BOT_TOKEN));
  const secretKey = await crypto.subtle.importKey('raw', secretKeyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', secretKey, enc.encode(dataCheckString));
  const computedHash = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');

  if (computedHash !== hash) {
    return new Response(JSON.stringify({ error: 'Invalid signature' }), {
      status: 403, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  // Verify the auth date is recent (within 5 minutes)
  const authDate = parseInt(authData.auth_date, 10);
  if (Date.now() / 1000 - authDate > 300) {
    return new Response(JSON.stringify({ error: 'Auth data expired' }), {
      status: 403, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  // Check user is authorized (admin panel requires ADMIN_USERNAMES)
  const username = (authData.username || '').toLowerCase();
  const admins = parseAllowedUsers(env.ADMIN_USERNAMES);

  if (!admins || !admins.includes(username)) {
    return new Response(JSON.stringify({ error: 'Not authorized' }), {
      status: 403, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  // Generate random session token stored in KV with 24h TTL
  const sessionId = 'tg:' + toBase64urlBody(crypto.getRandomValues(new Uint8Array(24)));
  await env.IMG_KV.put('session:' + sessionId, '1', { expirationTtl: 86400 });

  const resp = new Response(JSON.stringify({ ok: true }), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
  return await setSessionCookie(resp, sessionId, request);
}

// --- Image listing ---

async function handleListImages(request, env) {
  const auth = await checkSession(request, env);
  if (!auth) return unauthorized();

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, `admin:${ip}`, 60, 60))) {
    return new Response(JSON.stringify({ error: 'Too many requests' }), {
      status: 429, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  const url = new URL(request.url);
  const cursor = url.searchParams.get('cursor') || undefined;
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '50', 10), 100);

  const list = await env.IMG_KV.list({ prefix: 'img:', cursor, limit });
  const images = await Promise.all(
    list.keys.map(async (key) => {
      const val = await env.IMG_KV.get(key.name);
      if (!val) return null;
      try { return JSON.parse(val); } catch { return null; }
    })
  );

  const validImages = images.filter(Boolean);
  validImages.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

  const baseUrl = env.PUBLIC_URL.replace(/\/+$/, '');
  for (const img of validImages) img.publicUrl = `${baseUrl}/${img.r2Key}`;

  return new Response(JSON.stringify({ images: validImages, cursor: list.cursor, complete: list.list_complete }), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

// --- Delete image ---

async function handleDeleteImage(request, env) {
  const auth = await checkSession(request, env);
  if (!auth) return unauthorized();

  const ct = request.headers.get('content-type') || '';
  if (!ct.includes('application/json')) {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, `admin-del:${ip}`, 30, 60))) {
    return new Response(JSON.stringify({ error: 'Too many requests' }), {
      status: 429, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
  const nanoid = body && body.nanoid;
  if (!nanoid || typeof nanoid !== 'string' || !/^[a-z0-9]{8,32}$/.test(nanoid)) {
    return new Response(JSON.stringify({ error: 'Invalid nanoid' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  const imgRef = `img:${nanoid}`;
  const metadataJson = await env.IMG_KV.get(imgRef);
  if (!metadataJson) {
    return new Response(JSON.stringify({ error: 'Image not found' }), {
      status: 404, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  let metadata;
  try { metadata = JSON.parse(metadataJson); } catch {
    return new Response(JSON.stringify({ error: 'Invalid metadata' }), {
      status: 500, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  try { await env.IMG_BUCKET.delete(metadata.r2Key); } catch (err) { console.error('R2 delete error:', err); }

  // Clean up all KV entries
  const keysToDelete = [imgRef];
  if (metadata.chatId && metadata.messageId) keysToDelete.push(`msg:${metadata.chatId}:${metadata.messageId}`);
  if (metadata.chatId && metadata.botMessageIds) {
    metadata.botMessageIds.forEach(mid => keysToDelete.push(`msg:${metadata.chatId}:${mid}`));
  } else if (metadata.chatId && metadata.botMessageId) {
    keysToDelete.push(`msg:${metadata.chatId}:${metadata.botMessageId}`);
  }
  await Promise.all(keysToDelete.map(k => env.IMG_KV.delete(k)));

  return new Response(JSON.stringify({ ok: true }), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

// --- Batch delete images ---

async function handleBatchDelete(request, env) {
  const auth = await checkSession(request, env);
  if (!auth) return unauthorized();

  const ct = request.headers.get('content-type') || '';
  if (!ct.includes('application/json')) {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, `admin-batch:${ip}`, 20, 60))) {
    return new Response(JSON.stringify({ error: 'Too many requests' }), {
      status: 429, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
  const nanoids = body && body.nanoids;
  if (!Array.isArray(nanoids) || nanoids.length === 0 || nanoids.length > 50) {
    return new Response(JSON.stringify({ error: 'Invalid nanoids array (max 50)' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  for (const n of nanoids) {
    if (typeof n !== 'string' || !/^[a-z0-9]{8,32}$/.test(n)) {
      return new Response(JSON.stringify({ error: 'Invalid nanoid' }), {
        status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
      });
    }
  }

  const results = { deleted: 0, failed: 0 };

  await Promise.all(nanoids.map(async (nanoid) => {
    try {
      const imgRef = `img:${nanoid}`;
      const metadataJson = await env.IMG_KV.get(imgRef);
      if (!metadataJson) { results.failed++; return; }

      let metadata;
      try { metadata = JSON.parse(metadataJson); } catch { results.failed++; return; }

      try { await env.IMG_BUCKET.delete(metadata.r2Key); } catch {}

      const keysToDelete = [imgRef];
      if (metadata.chatId && metadata.messageId) keysToDelete.push(`msg:${metadata.chatId}:${metadata.messageId}`);
      if (metadata.chatId && metadata.botMessageIds) {
        metadata.botMessageIds.forEach(mid => keysToDelete.push(`msg:${metadata.chatId}:${mid}`));
      } else if (metadata.chatId && metadata.botMessageId) {
        keysToDelete.push(`msg:${metadata.chatId}:${metadata.botMessageId}`);
      }
      await Promise.all(keysToDelete.map(k => env.IMG_KV.delete(k)));

      results.deleted++;
    } catch { results.failed++; }
  }));

  return new Response(JSON.stringify(results), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

// --- Admin page upload ---

async function handleAdminUpload(request, env) {
  const auth = await checkSession(request, env);
  if (!auth) return unauthorized();

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, `admin-upload:${ip}`, 20, 60))) {
    return new Response(JSON.stringify({ error: 'Too many requests' }), {
      status: 429, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  const ct = request.headers.get('Content-Type') || '';
  if (!ct.includes('multipart/form-data')) {
    return new Response(JSON.stringify({ error: 'Expected multipart/form-data' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  let formData;
  try { formData = await request.formData(); } catch {
    return new Response(JSON.stringify({ error: 'Invalid form data' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  const file = formData.get('image');
  if (!file || typeof file === 'string') {
    return new Response(JSON.stringify({ error: 'No image file provided' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  if (!isValidImageMime(file.type)) {
    return new Response(JSON.stringify({ error: 'Unsupported image format' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  const MAX_SIZE = 50 * 1024 * 1024;
  if (file.size > MAX_SIZE) {
    return new Response(JSON.stringify({ error: 'File too large (max 50MB)' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  const fileBuffer = await file.arrayBuffer();
  const ext = getExtension(file.type);
  const nanoid = await generateId();
  const r2Key = `uploads/${nanoid}.${ext}`;

  await env.IMG_BUCKET.put(r2Key, fileBuffer, {
    httpMetadata: { contentType: file.type },
    customMetadata: { uploader: auth },
  });

  const publicUrl = `${env.PUBLIC_URL.replace(/\/+$/, '')}/${r2Key}`;

  const metadata = {
    nanoid, r2Key,
    fileName: file.name || 'image',
    mimeType: file.type,
    fileSize: fileBuffer.byteLength,
    uploader: auth,
    uploaderId: 0,
    chatId: 0, messageId: 0,
    timestamp: Date.now(),
  };
  await env.IMG_KV.put(`img:${nanoid}`, JSON.stringify(metadata));

  return new Response(JSON.stringify({
    ok: true, url: publicUrl,
    md: `![](${publicUrl})`,
    html: `<img src="${publicUrl}" alt="">`,
    bbcode: `[img]${publicUrl}[/img]`,
  }), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

// --- Batch export URLs ---

async function handleExport(request, env) {
  const auth = await checkSession(request, env);
  if (!auth) return unauthorized();

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, `admin-export:${ip}`, 10, 60))) {
    return new Response(JSON.stringify({ error: 'Too many requests' }), {
      status: 429, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  let cursor = undefined;
  const urls = [];
  const baseUrl = env.PUBLIC_URL.replace(/\/+$/, '');

  do {
    const list = await env.IMG_KV.list({ prefix: 'img:', cursor, limit: 1000 });
    for (const key of list.keys) {
      const val = await env.IMG_KV.get(key.name);
      if (!val) continue;
      try {
        const m = JSON.parse(val);
        urls.push(`${baseUrl}/${m.r2Key}`);
      } catch {}
    }
    cursor = list.cursor;
  } while (cursor);

  return new Response(urls.join('\n'), {
    headers: {
      ...secureHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }),
      ...cspHeaders(),
      'Content-Disposition': 'attachment; filename="images.txt"',
    },
  });
}

// --- WebAuthn Registration ---

async function handleWebAuthnRegisterBegin(request, env) {
  const existing = await env.IMG_KV.list({ prefix: 'wa:cred:' });
  if (existing.keys.length > 0) {
    const auth = await checkSession(request, env);
    if (!auth) return unauthorized();
  } else if (env.TELEGRAM_BOT_USERNAME) {
    // If Telegram login is configured, require authentication even for first PassKey
    const auth = await checkSession(request, env);
    if (!auth) return unauthorized();
  }

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (!(await checkRateLimit(env, "admin-reg:" + ip, 10, 60))) {
    return new Response(JSON.stringify({ error: "Too many requests" }), {
      status: 429, headers: { ...secureHeaders({ "Content-Type": "application/json" }), ...cspHeaders() },
    });
  }

  const url = new URL(request.url);
  const domain = url.hostname;

  const options = await beginRegistration(domain);
  await env.IMG_KV.put(`wa:reg:${options.challenge}`, 'pending', { expirationTtl: 300 });

  return new Response(JSON.stringify(options), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

async function handleWebAuthnRegisterComplete(request, env) {
  const existing = await env.IMG_KV.list({ prefix: 'wa:cred:' });
  if (existing.keys.length > 0) {
    const auth = await checkSession(request, env);
    if (!auth) return unauthorized();
  } else if (env.TELEGRAM_BOT_USERNAME) {
    const auth = await checkSession(request, env);
    if (!auth) return unauthorized();
  }

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (!(await checkRateLimit(env, "admin-reg-complete:" + ip, 10, 60))) {
    return new Response(JSON.stringify({ error: "Too many requests" }), {
      status: 429, headers: { ...secureHeaders({ "Content-Type": "application/json" }), ...cspHeaders() },
    });
  }

  const url = new URL(request.url);
  const domain = url.hostname;

  if (!request.headers.get('content-type')?.includes('application/json')) {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
  try {
    const credId = await completeRegistration(env, body, domain);

    // Auto-create session after successful registration
    const sessionId = 'wa:' + toBase64urlBody(crypto.getRandomValues(new Uint8Array(24)));
    await env.IMG_KV.put(`wa:session:${sessionId}`, '1', { expirationTtl: 86400 });

    const secure = !isLocalhost(request);
    return new Response(JSON.stringify({ ok: true, credId }), {
      headers: {
        ...secureHeaders({ 'Content-Type': 'application/json' }),
        ...cspHeaders(),
        'Set-Cookie': `admin_token=${sessionId}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400${secure ? '; Secure' : ''}`,
      },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
}

// --- WebAuthn Authentication ---

async function handleWebAuthnAuthBegin(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, `admin-wa-begin:${ip}`, 20, 60))) {
    return new Response(JSON.stringify({ error: 'Too many requests' }), {
      status: 429, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  const options = await beginAuthentication(env);
  if (!options) {
    return new Response(JSON.stringify({ error: 'No credentials registered' }), {
      status: 404, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  return new Response(JSON.stringify(options), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

async function handleWebAuthnAuthComplete(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, `admin-wa-complete:${ip}`, 10, 60))) {
    return new Response(JSON.stringify({ error: 'Too many requests' }), {
      status: 429, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  const url = new URL(request.url);
  const domain = url.hostname;

  if (!request.headers.get('content-type')?.includes('application/json')) {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
  try {
    await completeAuthentication(env, body, domain);

    // Create session token
    const sessionId = 'wa:' + toBase64urlBody(crypto.getRandomValues(new Uint8Array(24)));
    await env.IMG_KV.put(`wa:session:${sessionId}`, '1', { expirationTtl: 86400 });

    const secure = !isLocalhost(request);
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        ...secureHeaders({ 'Content-Type': 'application/json' }),
        ...cspHeaders(),
        'Set-Cookie': `admin_token=${sessionId}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400${secure ? '; Secure' : ''}`,
      },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
}

function toBase64urlBody(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// --- WebAuthn credential management ---

async function handleWebAuthnCredentials(request, env) {
  const auth = await checkSession(request, env);
  if (!auth) return unauthorized();

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (!(await checkRateLimit(env, "admin-cred:" + ip, 30, 60))) {
    return new Response(JSON.stringify({ error: "Too many requests" }), {
      status: 429, headers: { ...secureHeaders({ "Content-Type": "application/json" }), ...cspHeaders() },
    });
  }

  const credentials = await listCredentials(env);
  return new Response(JSON.stringify({ credentials }), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

async function handleWebAuthnDeleteCredential(request, env) {
  const auth = await checkSession(request, env);
  if (!auth) return unauthorized();

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (!(await checkRateLimit(env, "admin-cred-del:" + ip, 10, 60))) {
    return new Response(JSON.stringify({ error: "Too many requests" }), {
      status: 429, headers: { ...secureHeaders({ "Content-Type": "application/json" }), ...cspHeaders() },
    });
  }

  if (!request.headers.get('content-type')?.includes('application/json')) {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
  let body;
  try { body = await request.json(); } catch {
    return new Response(JSON.stringify({ error: 'Bad request' }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
  try {
    await deleteCredential(env, body.credId);
    return new Response(JSON.stringify({ ok: true }), {
      headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 400, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }
}

async function handleWebAuthnSetupStatus(request, env) {
  const existing = await env.IMG_KV.list({ prefix: 'wa:cred:' });
  return new Response(JSON.stringify({ canRegister: existing.keys.length === 0 }), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

// --- Delete Account (removes all credentials and sessions) ---

async function handleDeleteAccount(request, env) {
  const auth = await checkSession(request, env);
  if (!auth) return unauthorized();

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await checkRateLimit(env, `admin-del-account:${ip}`, 3, 60))) {
    return new Response(JSON.stringify({ error: 'Too many requests' }), {
      status: 429, headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
    });
  }

  // Delete all WebAuthn credentials
  const credList = await env.IMG_KV.list({ prefix: 'wa:cred:' });
  await Promise.all(credList.keys.map(k => env.IMG_KV.delete(k.name)));

  // Delete all WebAuthn sessions
  const sessionList = await env.IMG_KV.list({ prefix: 'wa:session:' });
  await Promise.all(sessionList.keys.map(k => env.IMG_KV.delete(k.name)));

  // Delete all Telegram sessions
  const tgSessionList = await env.IMG_KV.list({ prefix: 'session:tg:' });
  await Promise.all(tgSessionList.keys.map(k => env.IMG_KV.delete(k.name)));

  const resp = new Response(JSON.stringify({ ok: true }), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
  resp.headers.set("Set-Cookie", "admin_token=; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=0");
  return resp;
}

// --- Login token from bot deep-link auth ---

async function handleLoginToken(env, loginToken, request) {
  const username = await env.IMG_KV.get(`login_token:${loginToken}`);
  if (!username) {
    const url = new URL(request.url);
    return Response.redirect(`${url.origin}/admin`, 302);
  }

  const admins = parseAllowedUsers(env.ADMIN_USERNAMES);
  if (!admins || !admins.includes(username)) {
    const url = new URL(request.url);
    return Response.redirect(`${url.origin}/admin`, 302);
  }

  await env.IMG_KV.delete(`login_token:${loginToken}`);

  const sessionId = 'tg:' + toBase64urlBody(crypto.getRandomValues(new Uint8Array(24)));
  await env.IMG_KV.put('session:' + sessionId, '1', { expirationTtl: 86400 });

  const secure = !isLocalhost(request);
  const url = new URL(request.url);
  const resp = Response.redirect(`${url.origin}/admin`, 302);
  resp.headers.set('Set-Cookie', `admin_token=${sessionId}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400${secure ? '; Secure' : ''}`);
  return resp;
}

// ============================================================
//  Admin HTML page (clean & minimal design)
// ============================================================

function serveAdminPage(env) {
  const hasTelegramLogin = !!env.TELEGRAM_BOT_USERNAME;
  const botUsername = (env.TELEGRAM_BOT_USERNAME || '').replace(/[^a-zA-Z0-9_]/g, '');
  const botId = hasTelegramLogin && env.BOT_TOKEN ? env.BOT_TOKEN.split(':')[0] : '';

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self' https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self' https://static.cloudflareinsights.com; form-action 'self';">
<title>图床管理</title>
<style>
  :root {
    --bg: #f4f5f7;
    --card-bg: #fff;
    --text: #202124;
    --text-secondary: #5f6368;
    --text-muted: #9aa0a6;
    --border: #dadce0;
    --primary: #1a73e8;
    --primary-hover: #1557b0;
    --primary-bg: #e8f0fe;
    --danger: #d93025;
    --danger-bg: #fce8e6;
    --success: #188038;
    --shadow: 0 1px 3px rgba(0,0,0,0.1);
    --radius: 8px;
    --radius-sm: 4px;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #1e1e1e;
      --card-bg: #2d2d2d;
      --text: #e8eaed;
      --text-secondary: #9aa0a6;
      --text-muted: #6b7280;
      --border: #3c4043;
      --primary: #8ab4f8;
      --primary-hover: #aecbfa;
      --primary-bg: #1a3c5a;
      --danger: #f28b82;
      --danger-bg: #3c1a1a;
      --success: #81c995;
      --shadow: 0 1px 3px rgba(0,0,0,0.3);
    }
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Noto Sans SC', sans-serif;
    background: var(--bg); color: var(--text);
    min-height: 100vh; -webkit-font-smoothing: antialiased; font-size: 14px;
  }

  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 4px;
    padding: 8px 16px; border: none; border-radius: var(--radius-sm);
    font-size: 13px; font-weight: 500; cursor: pointer;
    text-decoration: none; white-space: nowrap; user-select: none;
    transition: background 0.15s;
  }
  .btn-primary { background: var(--primary); color: #fff; }
  .btn-primary:hover { background: var(--primary-hover); }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-danger:hover { background: #b3261e; }
  .btn-ghost { background: transparent; color: var(--text-secondary); border: 1px solid var(--border); }
  .btn-ghost:hover { background: var(--primary-bg); color: var(--primary); border-color: var(--primary); }
  .btn-sm { padding: 6px 12px; font-size: 12px; }
  .btn-block { width: 100%; }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }

  /* Login Screen */
  #login-screen {
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 20px;
  }
  .login-card {
    background: var(--card-bg); border: 1px solid var(--border);
    border-radius: var(--radius); box-shadow: var(--shadow);
    padding: 40px 32px; width: 360px; max-width: 100%;
  }
  .login-card h2 { font-size: 22px; font-weight: 600; margin-bottom: 4px; }
  .login-desc { color: var(--text-secondary); font-size: 14px; margin-bottom: 24px; }
  .login-error {
    color: var(--danger); font-size: 13px; margin-bottom: 12px;
    display: none; background: var(--danger-bg); padding: 8px 12px;
    border-radius: var(--radius-sm);
  }
  .login-error.show { display: block; }
  .login-divider {
    display: flex; align-items: center; gap: 12px; margin: 16px 0;
    color: var(--text-muted); font-size: 12px;
  }
  .login-divider::before, .login-divider::after {
    content: ''; flex: 1; border-top: 1px solid var(--border);
  }
  .btn-passkey { background: var(--card-bg); color: var(--text); border: 1px solid var(--border); }
  .btn-passkey:hover { background: var(--primary-bg); border-color: var(--primary); color: var(--primary); }
  .btn-tg-login {
    display: flex; align-items: center; justify-content: center; gap: 8px;
    width: 100%; height: 44px; padding: 0 20px;
    background: #2AABEE; color: #fff; border: none; border-radius: 22px;
    font-size: 15px; font-family: inherit; cursor: pointer; transition: background 0.15s;
    box-sizing: border-box;
  }
  .btn-tg-login:hover { background: #229ED4; }
  .btn-tg-login:active { background: #1E8FC1; }

  /* Header */
  .header {
    background: var(--card-bg); border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 40;
  }
  .header-inner {
    max-width: 1200px; margin: 0 auto;
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 20px; height: 52px;
  }
  .header-left { display: flex; align-items: center; gap: 8px; }
  .header-left h1 { font-size: 16px; font-weight: 600; }
  .header-actions { display: flex; align-items: center; gap: 8px; }

  /* Stats */
  .stats {
    max-width: 1200px; margin: 16px auto 0; padding: 0 20px;
    display: flex; gap: 12px;
  }
  .stat {
    background: var(--card-bg); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 14px 18px;
    flex: 1;
  }
  .stat-value { font-size: 22px; font-weight: 600; line-height: 1.3; }
  .stat-label { font-size: 12px; color: var(--text-secondary); margin-top: 2px; }

  /* Toolbar */
  .toolbar {
    max-width: 1200px; margin: 12px auto 0; padding: 0 20px;
    display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  }
  .toolbar input[type="text"] {
    flex: 1; min-width: 180px; max-width: 320px;
    padding: 8px 12px; border: 1px solid var(--border);
    border-radius: var(--radius-sm); background: var(--card-bg);
    color: var(--text); font-size: 13px; outline: none;
  }
  .toolbar input[type="text"]:focus { border-color: var(--primary); }
  .toolbar input::placeholder { color: var(--text-muted); }
  .toolbar select {
    padding: 7px 10px; border: 1px solid var(--border);
    border-radius: var(--radius-sm); background: var(--card-bg);
    color: var(--text); font-size: 13px; outline: none; cursor: pointer;
  }
  .toolbar select:focus { border-color: var(--primary); }

  /* Gallery */
  .container { max-width: 1200px; margin: 0 auto; padding: 12px 20px 40px; }
  .gallery {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 12px;
  }

  /* Card */
  .card {
    background: var(--card-bg); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
    transition: box-shadow 0.15s;
  }
  .card:hover { box-shadow: var(--shadow); }
  .card.card-selected { border-color: var(--primary); box-shadow: 0 0 0 1px var(--primary); }
  .card-thumb {
    position: relative; width: 100%; aspect-ratio: 16/10;
    background: var(--bg); cursor: pointer; overflow: hidden;
  }
  .card-thumb img { width: 100%; height: 100%; object-fit: cover; }
  .card-check {
    position: absolute; top: 6px; left: 6px; z-index: 2;
  }
  .card-check input[type="checkbox"] {
    width: 16px; height: 16px; cursor: pointer; accent-color: var(--primary);
  }
  .card-body { padding: 10px 12px 12px; }
  .card-name {
    font-size: 13px; font-weight: 500;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    margin-bottom: 2px;
  }
  .card-meta {
    font-size: 11px; color: var(--text-secondary);
    margin-bottom: 8px;
  }
  .card-meta span { color: var(--text-muted); margin: 0 2px; }
  .card-actions { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
  .fmt-btn {
    padding: 3px 8px; border: 1px solid var(--border);
    border-radius: 3px; background: transparent; color: var(--text-secondary);
    font-size: 10px; font-weight: 500; cursor: pointer; letter-spacing: 0.3px;
    transition: all 0.15s; text-transform: uppercase;
  }
  .fmt-btn:hover { background: var(--primary-bg); border-color: var(--primary); color: var(--primary); }
  .fmt-btn.copied { background: var(--success); border-color: var(--success); color: #fff; }
  .del-btn {
    margin-left: auto;
    padding: 3px 8px; border: none; border-radius: 3px;
    background: transparent; color: var(--text-muted);
    font-size: 11px; cursor: pointer; transition: all 0.15s;
  }
  .del-btn:hover { background: var(--danger-bg); color: var(--danger); }

  /* Skeleton */
  .skeleton {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 12px;
  }
  .skeleton-card {
    background: var(--card-bg); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
  }
  .skeleton-thumb {
    width: 100%; aspect-ratio: 16/10;
    background: linear-gradient(90deg, var(--border) 25%, transparent 50%, var(--border) 75%);
    background-size: 200% 100%; animation: shimmer 1.5s infinite;
  }
  .skeleton-line {
    height: 10px; margin: 10px 12px 0; border-radius: 4px;
    background: linear-gradient(90deg, var(--border) 25%, transparent 50%, var(--border) 75%);
    background-size: 200% 100%; animation: shimmer 1.5s infinite;
  }
  .skeleton-line:last-child { width: 60%; margin-bottom: 12px; }
  @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

  .empty-state {
    grid-column: 1 / -1; text-align: center; padding: 60px 20px;
    color: var(--text-secondary);
  }
  .empty-state p { font-size: 14px; }

  .load-more-wrap { text-align: center; padding: 20px 0; }
  .load-msg { color: var(--text-muted); font-size: 13px; padding: 8px 0; }

  /* Preview Overlay */
  .preview-overlay {
    display: none; position: fixed; inset: 0; z-index: 100;
    background: rgba(0,0,0,0.9); align-items: center; justify-content: center;
  }
  .preview-overlay.show { display: flex; }
  .preview-overlay img {
    max-width: 92vw; max-height: 88vh; border-radius: 4px;
    object-fit: contain; user-select: none;
  }
  .preview-close {
    position: fixed; top: 16px; right: 16px;
    width: 36px; height: 36px; border: none; border-radius: 50%;
    background: rgba(255,255,255,0.1); color: #fff;
    font-size: 18px; cursor: pointer; z-index: 101;
    display: flex; align-items: center; justify-content: center;
    transition: background 0.15s;
  }
  .preview-close:hover { background: rgba(255,255,255,0.25); }
  .preview-nav {
    position: fixed; top: 50%; transform: translateY(-50%);
    width: 40px; height: 40px; border: none; border-radius: 50%;
    background: rgba(255,255,255,0.08); color: #fff;
    font-size: 24px; cursor: pointer; z-index: 101;
    display: flex; align-items: center; justify-content: center;
    transition: background 0.15s;
  }
  .preview-nav:hover { background: rgba(255,255,255,0.2); }
  .preview-nav.prev { left: 16px; }
  .preview-nav.next { right: 16px; }
  .preview-nav.hidden { opacity: 0; pointer-events: none; }
  .preview-counter {
    position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
    color: rgba(255,255,255,0.4); font-size: 13px; z-index: 101;
  }

  /* Toast */
  .toast-container {
    position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
    z-index: 200; display: flex; flex-direction: column; gap: 6px;
    align-items: center; pointer-events: none;
  }
  .toast {
    background: var(--card-bg); border: 1px solid var(--border);
    color: var(--text); padding: 8px 16px; border-radius: var(--radius-sm);
    font-size: 13px; box-shadow: var(--shadow);
    opacity: 0; transform: translateY(8px);
    transition: all 0.2s; pointer-events: auto;
  }
  .toast.show { opacity: 1; transform: translateY(0); }
  .toast.success { border-color: var(--success); }
  .toast.error { border-color: var(--danger); }

  /* Settings Modal */
  .modal-overlay {
    display: none; position: fixed; inset: 0; z-index: 150;
    background: rgba(0,0,0,0.4); align-items: center; justify-content: center;
    padding: 20px;
  }
  .modal-overlay.show { display: flex; }
  .modal {
    background: var(--card-bg); border: 1px solid var(--border);
    border-radius: var(--radius); box-shadow: 0 8px 32px rgba(0,0,0,0.15);
    width: 480px; max-width: 100%; max-height: 80vh; overflow-y: auto;
  }
  .modal-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 20px; border-bottom: 1px solid var(--border);
  }
  .modal-header h3 { font-size: 16px; font-weight: 600; }
  .modal-close {
    width: 28px; height: 28px; border: none; border-radius: 4px;
    background: transparent; color: var(--text-secondary); font-size: 18px;
    cursor: pointer; display: flex; align-items: center; justify-content: center;
  }
  .modal-close:hover { background: var(--primary-bg); color: var(--primary); }
  .modal-body { padding: 20px; }
  .modal-section { margin-bottom: 24px; }
  .modal-section:last-child { margin-bottom: 0; }
  .modal-section h4 {
    font-size: 13px; font-weight: 600; color: var(--text-secondary);
    text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px;
  }
  .cred-item {
    display: flex; align-items: center; justify-content: space-between;
    padding: 8px 0; border-bottom: 1px solid var(--border);
  }
  .cred-item:last-child { border-bottom: none; }
  .cred-info { font-size: 13px; }
  .cred-date { font-size: 11px; color: var(--text-muted); margin-top: 2px; }
  .danger-zone {
    border: 1px solid var(--danger); border-radius: var(--radius-sm);
    padding: 16px;
  }
  .danger-zone p { font-size: 13px; color: var(--text-secondary); margin-bottom: 12px; }
  .modal-empty { font-size: 13px; color: var(--text-muted); padding: 8px 0; }

  /* Upload Zone */
  .upload-zone {
    border: 2px dashed var(--border); border-radius: var(--radius);
    padding: 40px 20px; text-align: center; cursor: pointer;
    transition: all 0.15s; color: var(--text-muted); font-size: 14px;
  }
  .upload-zone:hover, .upload-zone.dragover {
    border-color: var(--primary); color: var(--primary); background: var(--primary-bg);
  }
  .upload-preview { margin-top: 12px; text-align: center; }
  .upload-preview img { max-width: 100%; max-height: 200px; border-radius: var(--radius-sm); margin-bottom: 8px; }
  .upload-progress { font-size: 13px; color: var(--text-secondary); padding: 8px; }
  .upload-result { text-align: center; }
  .upload-result input[type="text"] {
    width: 100%; padding: 6px 10px; border: 1px solid var(--border);
    border-radius: var(--radius-sm); font-size: 12px; background: var(--bg);
    color: var(--text); margin-bottom: 8px; outline: none;
  }
  .upload-result-actions { display: flex; gap: 6px; justify-content: center; flex-wrap: wrap; }

  @media (max-width: 640px) {
    .header-inner { padding: 0 14px; }
    .stats { padding: 0 14px; flex-direction: column; gap: 8px; }
    .toolbar { padding: 0 14px; }
    .toolbar input[type="text"] { max-width: 100%; }
    .container { padding: 10px 14px 32px; }
    .gallery { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; }
    .skeleton { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; }
    .card-body { padding: 8px 10px; }
    .login-card { padding: 28px 20px; }
  }
</style>
</head>
<body>

<!-- Login Screen -->
<div id="login-screen">
  <div class="login-card">
    <h2>图床管理</h2>
    <p class="login-desc">登录以管理图片</p>
    <div class="login-error" id="login-error"></div>

    ${hasTelegramLogin ? `
    <button class="btn-tg-login" onclick="telegramLogin()">
      <svg viewBox="0 0 24 24" width="20" height="20" fill="white"><path d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.127.087.527.087.527l-1.523 7.185s-.144.385-.585.396c-.44.01-.651-.34-.651-.34l-2.012-2.999-1.682 1.233a.23.23 0 0 1-.148.05l.355-2.352 3.89-3.493c.163-.147.01-.207-.116-.17l-5.919 2.487-1.731-.583s-.382-.133-.418-.424c-.036-.29.44-.447.44-.447l7.272-2.803s.75-.313 1.284-.06z"/></svg>
      <span>使用 Telegram 登录</span>
    </button>
    <div class="login-divider">或</div>` : ''}

    <button class="btn btn-passkey btn-block" id="passkey-login-btn" style="display:none" onclick="loginPassKey()">使用 PassKey 登录</button>
    <button class="btn btn-passkey btn-block" id="register-first-passkey-btn" style="display:none" onclick="registerFirstPassKey()">注册 PassKey</button>
  </div>
</div>

<!-- Main App -->
<div id="app" style="display:none">

  <!-- Header -->
  <div class="header">
    <div class="header-inner">
      <div class="header-left">
        <h1>图床管理</h1>
      </div>
      <div class="header-actions">
        <button class="btn btn-ghost btn-sm" id="register-passkey-btn" style="display:none" onclick="registerPassKey()">添加 PassKey</button>
        <button class="btn btn-ghost btn-sm" onclick="showUpload()">上传</button>
        <button class="btn btn-ghost btn-sm" onclick="showSettings()">设置</button>
        <button class="btn btn-ghost btn-sm" onclick="exportUrls()">导出</button>
        <button class="btn btn-ghost btn-sm" onclick="logout()">退出登录</button>
      </div>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats">
    <div class="stat">
      <span class="stat-value" id="stat-count">-</span>
      <span class="stat-label">图片总数</span>
    </div>
    <div class="stat">
      <span class="stat-value" id="stat-size">-</span>
      <span class="stat-label">总大小</span>
    </div>
  </div>

  <!-- Toolbar -->
  <div class="toolbar">
    <input type="text" id="search-input" placeholder="搜索文件名..." oninput="onSearchInput()">
    <select id="sort-select" onchange="setSort(this.value)">
      <option value="newest">最新优先</option>
      <option value="oldest">最早优先</option>
    </select>
    <button class="btn btn-danger btn-sm" id="batch-delete-btn" style="display:none" onclick="batchDelete()">删除选中 (<span id="selected-count">0</span>)</button>
    <button class="btn btn-ghost btn-sm" onclick="refreshImages()">刷新</button>
  </div>

  <!-- Gallery -->
  <div class="container">
    <div class="gallery" id="gallery"></div>

    <div class="skeleton" id="skeleton">
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line"></div></div>
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line"></div></div>
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line"></div></div>
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line"></div></div>
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line"></div></div>
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line"></div></div>
    </div>

    <div class="load-more-wrap">
      <p class="load-msg" id="load-msg"></p>
      <button class="btn btn-primary" id="load-more-btn" style="display:none" onclick="loadMore()">加载更多</button>
    </div>
  </div>
</div>

<!-- Settings Modal -->
<div class="modal-overlay" id="settings-modal">
  <div class="modal">
    <div class="modal-header">
      <h3>设置</h3>
      <button class="modal-close" onclick="closeSettings()">&#x2715;</button>
    </div>
    <div class="modal-body">
      <div class="modal-section">
        <h4>PassKey 管理</h4>
        <div id="credential-list">
          <p class="modal-empty">加载中...</p>
        </div>
      </div>
      <div class="modal-section">
        <h4>危险操作</h4>
        <div class="danger-zone">
          <p>删除账号将清除所有 PassKey 凭证和登录会话，此操作不可撤销。</p>
          <button class="btn btn-danger btn-sm" onclick="deleteAccount()">删除账号</button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Upload Modal -->
<div class="modal-overlay" id="upload-modal">
  <div class="modal" style="width:400px">
    <div class="modal-header">
      <h3>上传图片</h3>
      <button class="modal-close" onclick="closeUpload()">&#x2715;</button>
    </div>
    <div class="modal-body">
      <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()">
        <p>点击或拖拽图片到此处</p>
        <input type="file" id="file-input" accept="image/*" onchange="onFileSelected(this.files)">
      </div>
      <div class="upload-preview" id="upload-preview" style="display:none">
        <img id="upload-img" src="" alt="">
        <div class="upload-progress" id="upload-progress"></div>
        <div class="upload-result" id="upload-result" style="display:none">
          <input type="text" id="upload-url" readonly onclick="this.select()">
          <div class="upload-result-actions">
            <button class="btn btn-sm btn-primary" onclick="copyUploadResult('url')">复制 URL</button>
            <button class="btn btn-sm btn-ghost" onclick="copyUploadResult('md')">复制 MD</button>
            <button class="btn btn-sm btn-ghost" onclick="copyUploadResult('html')">复制 HTML</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Preview Overlay -->
<div class="preview-overlay" id="preview">
  <button class="preview-close" onclick="closePreview()">&#x2715;</button>
  <button class="preview-nav prev" id="prev-btn" onclick="prevImage()">&#8249;</button>
  <img id="preview-img" src="" alt="preview">
  <button class="preview-nav next" id="next-btn" onclick="nextImage()">&#8250;</button>
  <div class="preview-counter" id="preview-counter"></div>
</div>

<!-- Toast -->
<div class="toast-container" id="toast"></div>

<script>
let cursor = null;
let complete = false;
let webauthnAvailable = false;
let allImages = [];
let previewIndex = -1;
let currentSort = 'newest';
let searchQuery = '';
let selectedNanoids = new Set();

// Handle Telegram OAuth redirect callback
(function() {
  if (!window.location.hash) return;
  const params = new URLSearchParams(window.location.hash.slice(1));
  if (!params.get('hash') || !params.get('id')) return;
  const data = {};
  for (const [k, v] of params) data[k] = v;
  (async function() {
    try {
      const r = await fetch('/admin/api/tg-login', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data),
      });
      if (r.ok) {
        window.location.replace('/admin');
      } else {
        const d = await r.json();
        document.getElementById('login-error').textContent = 'TG 登录失败：' + (d.error || r.status);
        document.getElementById('login-error').classList.add('show');
        window.location.hash = '';
      }
    } catch (e) {
      document.getElementById('login-error').textContent = '网络错误，请重试';
      document.getElementById('login-error').classList.add('show');
      window.location.hash = '';
    }
  })();
})();

// Auto-check session on page load
(async function checkSession() {
  try {
    const resp = await fetch('/admin/api/check-session');
    const data = await resp.json();
    if (data.authenticated) {
      onLoginSuccess();
    }
  } catch {}
})();

// WebAuthn check
const telegramConfigured = ${hasTelegramLogin};
if (window.PublicKeyCredential) {
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(avail => {
    webauthnAvailable = avail;
    if (avail) {
      fetch('/admin/api/webauthn/setup-status').then(r => r.json()).then(status => {
        if (status.canRegister) {
          // Only allow first-time PassKey registration from login screen when no Telegram configured
          if (!telegramConfigured) {
            document.getElementById('register-first-passkey-btn').style.display = 'block';
          }
        } else {
          document.getElementById('passkey-login-btn').style.display = 'block';
        }
      }).catch(() => {
        document.getElementById('passkey-login-btn').style.display = 'block';
      });
    }
  });
}

// Telegram Login — 跳转到 Telegram OAuth，授权后自动跳回
const tgBotId = '${botId}';

function telegramLogin() {
  const origin = window.location.origin;
  const returnTo = encodeURIComponent(origin + '/admin');
  window.location.href = 'https://oauth.telegram.org/auth?bot_id=' + tgBotId + '&origin=' + encodeURIComponent(origin) + '&return_to=' + returnTo;
}

// Listen for auth callback from Telegram OAuth popup
window.addEventListener('message', function(e) {
  if (e.origin === 'https://oauth.telegram.org' && e.data && e.data.hash) {
    const err = document.getElementById('login-error');
    fetch('/admin/api/tg-login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(e.data),
    }).then(r => {
      if (r.ok) { onLoginSuccess(); }
      else { r.json().then(d => { err.textContent = 'TG 认证失败：' + (d.error || '未知错误'); err.classList.add('show'); }); }
    }).catch(() => { err.textContent = '网络错误，请重试'; err.classList.add('show'); });
  }
});

// PassKey Login
async function loginPassKey() {
  const err = document.getElementById('login-error');
  err.classList.remove('show');
  try {
    const beginResp = await fetch('/admin/api/webauthn/auth/begin', { method: 'POST' });
    if (!beginResp.ok) {
      const d = await beginResp.json();
      err.textContent = d.error || '无法开始认证';
      err.classList.add('show'); return;
    }
    const options = await beginResp.json();
    options.challenge = base64ToArray(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map(c => ({ ...c, id: base64ToArray(c.id) }));
    }
    const cred = await navigator.credentials.get({ publicKey: options });
    const resp = await fetch('/admin/api/webauthn/auth/complete', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(formatWebAuthnResponse(cred)),
    });
    if (resp.ok) { onLoginSuccess(); }
    else { const d = await resp.json(); err.textContent = d.error || '认证失败'; err.classList.add('show'); }
  } catch (e) {
    if (e.name === 'NotAllowedError') return;
    err.textContent = 'PassKey 认证失败'; err.classList.add('show');
  }
}

// PassKey Registration
async function registerPassKey() {
  const btn = document.getElementById('register-passkey-btn');
  btn.disabled = true; btn.textContent = '注册中...';
  try {
    const beginResp = await fetch('/admin/api/webauthn/register/begin', { method: 'POST' });
    if (!beginResp.ok) {
      const d = await beginResp.json();
      showToast('注册失败: ' + (d.error || '无法开始注册'), 'error');
      btn.disabled = false; btn.textContent = '添加 PassKey'; return;
    }
    const options = await beginResp.json();
    options.challenge = base64ToArray(options.challenge);
    options.user.id = base64ToArray(options.user.id);
    const cred = await navigator.credentials.create({ publicKey: options });
    const resp = await fetch('/admin/api/webauthn/register/complete', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(formatWebAuthnResponse(cred)),
    });
    if (resp.ok) { showToast('PassKey 注册成功', 'success'); btn.textContent = '已注册'; }
    else { const d = await resp.json(); showToast('注册失败: ' + (d.error || '未知错误'), 'error'); btn.textContent = '添加 PassKey'; }
    btn.disabled = false;
    setTimeout(() => { btn.textContent = '添加 PassKey'; btn.disabled = false; }, 2500);
  } catch (e) {
    if (e.name === 'AbortError' || e.name === 'NotAllowedError') { btn.textContent = '添加 PassKey'; btn.disabled = false; return; }
    showToast('注册失败', 'error'); btn.textContent = '添加 PassKey'; btn.disabled = false;
  }
}

// First-time PassKey registration from login screen
async function registerFirstPassKey() {
  const btn = document.getElementById('register-first-passkey-btn');
  btn.disabled = true; btn.textContent = '注册中...';
  try {
    const beginResp = await fetch('/admin/api/webauthn/register/begin', { method: 'POST' });
    if (!beginResp.ok) {
      const d = await beginResp.json();
      showToast('注册失败: ' + (d.error || '无法开始注册'), 'error');
      btn.disabled = false; btn.textContent = '注册 PassKey'; return;
    }
    const options = await beginResp.json();
    options.challenge = base64ToArray(options.challenge);
    options.user.id = base64ToArray(options.user.id);
    const cred = await navigator.credentials.create({ publicKey: options });
    const resp = await fetch('/admin/api/webauthn/register/complete', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(formatWebAuthnResponse(cred)),
    });
    if (resp.ok) { onLoginSuccess(); }
    else { const d = await resp.json(); showToast('注册失败: ' + (d.error || '未知错误'), 'error'); btn.disabled = false; btn.textContent = '注册 PassKey'; }
  } catch (e) {
    if (e.name === 'AbortError' || e.name === 'NotAllowedError') { btn.textContent = '注册 PassKey'; btn.disabled = false; return; }
    showToast('注册失败', 'error'); btn.textContent = '注册 PassKey'; btn.disabled = false;
  }
}

// Login Success
function onLoginSuccess() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  if (webauthnAvailable) document.getElementById('register-passkey-btn').style.display = 'inline-flex';
  loadImages();
}

// WebAuthn Helpers
function formatWebAuthnResponse(cred) {
  const response = {};
  if (cred.response.clientDataJSON) response.clientDataJSON = arrayToBase64(cred.response.clientDataJSON);
  if (cred.response.attestationObject) response.attestationObject = arrayToBase64(cred.response.attestationObject);
  if (cred.response.authenticatorData) response.authenticatorData = arrayToBase64(cred.response.authenticatorData);
  if (cred.response.signature) response.signature = arrayToBase64(cred.response.signature);
  if (cred.response.userHandle) response.userHandle = arrayToBase64(cred.response.userHandle);
  if (cred.response.transports) response.transports = cred.response.transports;
  return { id: cred.id, rawId: arrayToBase64(cred.rawId), type: cred.type, response };
}
function base64ToArray(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str); const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function arrayToBase64(arr) {
  return btoa(String.fromCharCode(...new Uint8Array(arr)))
    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}

// Card Selection
function onImageCheck(checkbox) {
  const nanoid = checkbox.dataset.nanoid;
  const card = checkbox.closest('.card');
  if (checkbox.checked) {
    selectedNanoids.add(nanoid);
    card.classList.add('card-selected');
  } else {
    selectedNanoids.delete(nanoid);
    card.classList.remove('card-selected');
  }
  updateBatchDeleteBtn();
}

function updateBatchDeleteBtn() {
  const btn = document.getElementById('batch-delete-btn');
  const count = selectedNanoids.size;
  document.getElementById('selected-count').textContent = count;
  btn.style.display = count > 0 ? 'inline-flex' : 'none';
}

async function batchDelete() {
  const count = selectedNanoids.size;
  if (count === 0) return;
  if (!confirm(\`确定删除选中的 \${count} 张图片？此操作不可撤销。\`)) return;
  const btn = document.getElementById('batch-delete-btn');
  btn.disabled = true; btn.textContent = '删除中...';
  try {
    const resp = await fetch('/admin/api/batch-delete', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ nanoids: [...selectedNanoids] }),
    });
    if (resp.ok) {
      showToast(\`已删除 \${count} 张图片\`, 'success');
      selectedNanoids.clear();
      refreshImages();
    } else {
      const d = await resp.json();
      showToast('批量删除失败: ' + (d.error || ''), 'error');
      btn.disabled = false; btn.innerHTML = '删除选中 (<span id="selected-count">' + count + '</span>)';
    }
  } catch {
    showToast('批量删除失败', 'error');
    btn.disabled = false; btn.innerHTML = '删除选中 (<span id="selected-count">' + count + '</span>)';
  }
}

// Image Gallery
async function loadImages() {
  const skel = document.getElementById('skeleton');
  skel.style.display = 'grid';
  try {
    const url = '/admin/api/images?limit=50' + (cursor ? '&cursor=' + encodeURIComponent(cursor) : '');
    const resp = await fetch(url);
    if (resp.status === 401) { logout(); return; }
    if (resp.status === 429) { showToast('请求过于频繁', 'error'); skel.style.display = 'none'; return; }
    const data = await resp.json();
    cursor = data.cursor || null;
    complete = data.complete;
    skel.style.display = 'none';
    renderImages(data.images);
    updateLoadMore();
    updateStats();
  } catch { skel.style.display = 'none'; showToast('加载失败', 'error'); }
}

function renderImages(images) {
  const gallery = document.getElementById('gallery');
  if (images.length === 0 && !gallery.children.length) {
    gallery.innerHTML = '<div class="empty-state"><p>暂无图片</p></div>';
    return;
  }
  for (const img of images) {
    allImages.push(img);
    const idx = allImages.length - 1;
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = \`
      <div class="card-thumb" onclick="openPreview(\${idx})">
        <img src="\${img.publicUrl}" alt="" loading="lazy">
        <div class="card-check"><input type="checkbox" class="img-check" data-nanoid="\${img.nanoid}" onclick="event.stopPropagation()" onchange="onImageCheck(this)"></div>
      </div>
      <div class="card-body">
        <div class="card-name" title="\${escHtml(img.fileName || img.r2Key)}">\${escHtml(img.fileName || img.r2Key)}</div>
        <div class="card-meta">
          \${formatSize(img.fileSize)}
          <span>·</span>
          \${formatTime(img.timestamp)}
          <span>·</span>
          \${escHtml(img.uploader || '?')}
        </div>
        <div class="card-actions">
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="url">URL</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="md">MD</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="html">HTML</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="bbcode">BBC</button>
          <button class="del-btn" data-nanoid="\${img.nanoid}" title="删除">删除</button>
        </div>
      </div>
    \`;
    gallery.appendChild(card);
  }
}

function updateLoadMore() {
  const btn = document.getElementById('load-more-btn');
  const msg = document.getElementById('load-msg');
  if (complete) {
    btn.style.display = 'none';
    msg.textContent = allImages.length > 0 ? '已加载全部图片' : '';
  } else {
    btn.style.display = 'inline-block';
    btn.disabled = false; btn.textContent = '加载更多';
    msg.textContent = '';
  }
}

async function loadMore() {
  const btn = document.getElementById('load-more-btn');
  btn.disabled = true; btn.textContent = '加载中...';
  await loadImages();
}

function updateStats() {
  let totalSize = 0;
  for (const img of allImages) { if (img.fileSize) totalSize += img.fileSize; }
  document.getElementById('stat-count').textContent = allImages.length;
  document.getElementById('stat-size').textContent = formatSize(totalSize);
}

// Search & Sort
function onSearchInput() {
  searchQuery = document.getElementById('search-input').value.toLowerCase().trim();
  applyFilter();
}

function setSort(sort) {
  currentSort = sort;
  applyFilter();
}

function applyFilter() {
  const gallery = document.getElementById('gallery');
  let filtered = [...allImages];
  if (searchQuery) filtered = filtered.filter(img => (img.fileName || '').toLowerCase().includes(searchQuery));
  filtered.sort((a, b) => {
    const ta = a.timestamp || 0, tb = b.timestamp || 0;
    return currentSort === 'newest' ? tb - ta : ta - tb;
  });
  gallery.innerHTML = '';
  if (filtered.length === 0) {
    gallery.innerHTML = '<div class="empty-state"><p>' + (searchQuery ? '没有匹配的图片' : '暂无图片') + '</p></div>';
    document.getElementById('load-more-btn').style.display = 'none';
    document.getElementById('load-msg').textContent = '';
    return;
  }
  const indices = filtered.map(img => allImages.indexOf(img));
  for (const idx of indices) {
    const img = allImages[idx];
    const card = document.createElement('div');
    card.innerHTML = \`
      <div class="card-thumb" onclick="openPreview(\${idx})">
        <img src="\${img.publicUrl}" alt="" loading="lazy">
        <div class="card-check"><input type="checkbox" class="img-check" data-nanoid="\${img.nanoid}" onclick="event.stopPropagation()" onchange="onImageCheck(this)"></div>
      </div>
      <div class="card-body">
        <div class="card-name" title="\${escHtml(img.fileName || img.r2Key)}">\${escHtml(img.fileName || img.r2Key)}</div>
        <div class="card-meta">
          \${formatSize(img.fileSize)}
          <span>·</span>
          \${formatTime(img.timestamp)}
          <span>·</span>
          \${escHtml(img.uploader || '?')}
        </div>
        <div class="card-actions">
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="url">URL</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="md">MD</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="html">HTML</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="bbcode">BBC</button>
          <button class="del-btn" data-nanoid="\${img.nanoid}" title="删除">删除</button>
        </div>
      </div>
    \`;
    gallery.appendChild(card);
  }
  document.querySelectorAll('.img-check').forEach(cb => {
    if (selectedNanoids.has(cb.dataset.nanoid)) {
      cb.checked = true;
      cb.closest('.card').classList.add('card-selected');
    }
  });
  updateLoadMore();
}

async function refreshImages() {
  cursor = null; complete = false; allImages = []; selectedNanoids.clear();
  document.getElementById('gallery').innerHTML = '';
  updateBatchDeleteBtn();
  await loadImages();
}

// Copy Format
function copyFormat(url, filename, format, btn) {
  let text = '';
  switch (format) {
    case 'url': text = url; break;
    case 'md': text = '![' + filename + '](' + url + ')'; break;
    case 'html': text = '<img src="' + url + '" alt="' + filename + '">'; break;
    case 'bbcode': text = '[img]' + url + '[/img]'; break;
  }
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'OK';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1200);
    showToast('已复制 ' + format.toUpperCase(), 'success');
  }).catch(() => showToast('复制失败', 'error'));
}

// Delete
async function deleteImg(nanoid) {
  if (!confirm('确定删除这张图片？此操作不可撤销。')) return;
  try {
    const resp = await fetch('/admin/api/delete', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({nanoid}),
    });
    if (resp.ok) { showToast('已删除', 'success'); location.reload(); }
    else { showToast('删除失败', 'error'); }
  } catch { showToast('删除失败', 'error'); }
}

// Preview
function openPreview(idx) {
  if (!allImages[idx]) return;
  previewIndex = idx;
  const img = allImages[idx];
  document.getElementById('preview-img').src = img.publicUrl;
  document.getElementById('preview').classList.add('show');
  document.getElementById('preview-counter').textContent = (idx + 1) + ' / ' + allImages.length;
  updateNavButtons();
}

function closePreview() {
  document.getElementById('preview').classList.remove('show');
  document.getElementById('preview-img').src = '';
}

function prevImage() { if (previewIndex > 0) openPreview(previewIndex - 1); }
function nextImage() { if (previewIndex < allImages.length - 1) openPreview(previewIndex + 1); }
function updateNavButtons() {
  document.getElementById('prev-btn').classList.toggle('hidden', previewIndex <= 0);
  document.getElementById('next-btn').classList.toggle('hidden', previewIndex >= allImages.length - 1);
}

document.addEventListener('keydown', function(e) {
  const el = document.getElementById('preview');
  if (!el.classList.contains('show')) return;
  if (e.key === 'Escape') closePreview();
  if (e.key === 'ArrowLeft') prevImage();
  if (e.key === 'ArrowRight') nextImage();
});

document.getElementById('preview').addEventListener('click', function(e) {
  if (e.target === this) closePreview();
});

document.getElementById('gallery').addEventListener('click', function(e) {
  const target = e.target.closest('.fmt-btn, .del-btn');
  if (!target) return;
  if (target.classList.contains('fmt-btn')) {
    copyFormat(target.dataset.url, target.dataset.name, target.dataset.format, target);
  } else if (target.classList.contains('del-btn')) {
    deleteImg(target.dataset.nanoid);
  }
});

// Settings
function showSettings() {
  document.getElementById('settings-modal').classList.add('show');
  loadCredentials();
}
function closeSettings() {
  document.getElementById('settings-modal').classList.remove('show');
}

async function loadCredentials() {
  const list = document.getElementById('credential-list');
  list.innerHTML = '<p class="modal-empty">加载中...</p>';
  try {
    const resp = await fetch('/admin/api/webauthn/credentials');
    if (!resp.ok) { list.innerHTML = '<p class="modal-empty">加载失败</p>'; return; }
    const data = await resp.json();
    if (!data.credentials || data.credentials.length === 0) {
      list.innerHTML = '<p class="modal-empty">暂无已注册的 PassKey</p>';
      return;
    }
    list.innerHTML = '';
    for (const cred of data.credentials) {
      const item = document.createElement('div');
      item.className = 'cred-item';
      const date = cred.createdAt ? new Date(cred.createdAt).toLocaleString('zh-CN') : '未知';
      const info = document.createElement('div');
      info.className = 'cred-info';
      info.innerHTML = 'PassKey<div class="cred-date">注册于 ' + date + '</div>';
      const delBtn = document.createElement('button');
      delBtn.className = 'btn btn-danger btn-sm';
      delBtn.textContent = '删除';
      delBtn.dataset.credid = cred.id;
      delBtn.onclick = function() { deleteCredential(this.dataset.credid); };
      item.appendChild(info);
      item.appendChild(delBtn);
      list.appendChild(item);
    }
  } catch { list.innerHTML = '<p class="modal-empty">加载失败</p>'; }
}

async function deleteCredential(credId) {
  if (!confirm('确定删除此 PassKey？')) return;
  try {
    const resp = await fetch('/admin/api/webauthn/credentials/delete', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ credId }),
    });
    if (resp.ok) { showToast('已删除', 'success'); loadCredentials(); }
    else { showToast('删除失败', 'error'); }
  } catch { showToast('删除失败', 'error'); }
}

async function deleteAccount() {
  if (!confirm('确定删除整个账号？所有 PassKey 凭证和登录会话将被清除。')) return;
  if (!confirm('此操作不可撤销！确定要继续？')) return;
  try {
    const resp = await fetch('/admin/api/delete-account', { method: 'POST' });
    if (resp.ok) {
      showToast('账号已删除', 'success');
      setTimeout(() => { location.reload(); }, 1500);
    } else { showToast('删除失败', 'error'); }
  } catch { showToast('删除失败', 'error'); }
}

// Upload
function showUpload() {
  document.getElementById('upload-modal').classList.add('show');
  document.getElementById('upload-preview').style.display = 'none';
  document.getElementById('upload-result').style.display = 'none';
  document.getElementById('upload-zone').style.display = 'block';
  document.getElementById('file-input').value = '';
}
function closeUpload() {
  document.getElementById('upload-modal').classList.remove('show');
}

// Drag-and-drop upload zone
const uploadZone = document.getElementById('upload-zone');
document.addEventListener('dragenter', (e) => {
  if (document.getElementById('upload-modal').classList.contains('show')) {
    uploadZone.classList.add('dragover');
  }
});
uploadZone.addEventListener('dragover', (e) => { e.preventDefault(); uploadZone.classList.add('dragover'); });
uploadZone.addEventListener('dragleave', () => { uploadZone.classList.remove('dragover'); });
uploadZone.addEventListener('drop', (e) => {
  e.preventDefault();
  uploadZone.classList.remove('dragover');
  if (e.dataTransfer.files.length) onFileSelected(e.dataTransfer.files);
});

async function onFileSelected(files) {
  if (!files || !files.length) return;
  const file = files[0];
  if (!file.type.startsWith('image/')) { showToast('请选择图片文件', 'error'); return; }
  if (file.size > 50 * 1024 * 1024) { showToast('文件超过 50MB 限制', 'error'); return; }

  document.getElementById('upload-zone').style.display = 'none';
  const preview = document.getElementById('upload-preview');
  preview.style.display = 'block';
  document.getElementById('upload-progress').textContent = '上传中...';
  document.getElementById('upload-result').style.display = 'none';

  // Show local preview
  const reader = new FileReader();
  reader.onload = (e) => { document.getElementById('upload-img').src = e.target.result; };
  reader.readAsDataURL(file);

  const formData = new FormData();
  formData.append('image', file);

  try {
    const resp = await fetch('/admin/api/upload', { method: 'POST', body: formData });
    const data = await resp.json();
    if (resp.ok && data.ok) {
      document.getElementById('upload-progress').textContent = '上传成功';
      document.getElementById('upload-url').value = data.url;
      document.getElementById('upload-result').style.display = 'block';
      window._lastUploadResult = data;
      refreshImages();
    } else {
      document.getElementById('upload-progress').textContent = '上传失败: ' + (data.error || '未知错误');
    }
  } catch {
    document.getElementById('upload-progress').textContent = '上传失败: 网络错误';
  }
}

async function copyUploadResult(format) {
  const data = window._lastUploadResult;
  if (!data) return;
  const text = data[format] || data.url;
  try {
    await navigator.clipboard.writeText(text);
    showToast('已复制 ' + format.toUpperCase(), 'success');
  } catch { showToast('复制失败', 'error'); }
}

// Export URLs
async function exportUrls() {
  try {
    const resp = await fetch('/admin/api/export');
    if (!resp.ok) { showToast('导出失败', 'error'); return; }
    const text = await resp.text();
    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'images.txt';
    a.click();
    URL.revokeObjectURL(a.href);
    showToast('已导出 ' + text.split('\\n').length + ' 个 URL', 'success');
  } catch { showToast('导出失败', 'error'); }
}

// Logout (call API to invalidate server-side session)
async function logout() {
  await fetch('/admin/api/logout', { method: 'POST' }).catch(() => {});
  const secure = location.protocol === 'https:';
  document.cookie = 'admin_token=; Path=/admin; Max-Age=0' + (secure ? '; Secure' : '');
  location.reload();
}

// Format Helpers
function formatSize(bytes) {
  if (!bytes) return '?';
  const kb = bytes / 1024;
  if (kb < 1024) return kb.toFixed(1) + ' KB';
  const mb = kb / 1024;
  if (mb < 1024) return mb.toFixed(1) + ' MB';
  return (mb / 1024).toFixed(1) + ' GB';
}
function formatTime(ts) {
  if (!ts) return '?';
  const d = new Date(ts);
  return d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-'
    + String(d.getDate()).padStart(2,'0') + ' '
    + String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0');
}
function escHtml(s) {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

// Toast
function showToast(msg, type) {
  const container = document.getElementById('toast');
  const el = document.createElement('div');
  el.className = 'toast' + (type ? ' ' + type : '');
  el.textContent = msg;
  container.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 200);
  }, 2000);
}
<\/script>
</body>
</html>`;

  return new Response(html, {
    headers: {
      ...secureHeaders({ 'Content-Type': 'text/html; charset=utf-8' }),
      ...cspHeaders(),
    },
  });
}
