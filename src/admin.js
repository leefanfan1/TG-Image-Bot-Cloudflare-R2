// Web management dashboard for the image bed
import { checkRateLimit, secureHeaders, cspHeaders, parseAllowedUsers } from './utils.js';
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

  // PassKey login works without Telegram config — just render the page
  // Telegram login widget will be hidden if TELEGRAM_BOT_USERNAME is not set

  // Serve admin page
  if (path === '/admin' || path === '/admin/') {
    if (request.method === 'GET') return serveAdminPage(env);
    return new Response('Method not allowed', { status: 405, headers: secureHeaders() });
  }

  // Auth API
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

// --- WebAuthn Registration ---

async function handleWebAuthnRegisterBegin(request, env) {
  // Only allow first-time bootstrap without auth; subsequent registrations require login
  const existing = await env.IMG_KV.list({ prefix: 'wa:cred:' });
  if (existing.keys.length > 0) {
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
  // Store challenge for verification
  await env.IMG_KV.put(`wa:reg:${options.challenge}`, 'pending', { expirationTtl: 300 });

  return new Response(JSON.stringify(options), {
    headers: { ...secureHeaders({ 'Content-Type': 'application/json' }), ...cspHeaders() },
  });
}

async function handleWebAuthnRegisterComplete(request, env) {
  // Only allow first-time bootstrap without auth; subsequent registrations require login
  const existing = await env.IMG_KV.list({ prefix: 'wa:cred:' });
  if (existing.keys.length > 0) {
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

// ============================================================
//  Admin HTML page (rendered inline)
// ============================================================

function serveAdminPage(env) {
  const hasTelegramLogin = !!env.TELEGRAM_BOT_USERNAME && !!env.BOT_TOKEN;
  const botUsername = (env.TELEGRAM_BOT_USERNAME || '').replace(/[^a-zA-Z0-9_]/g, '');

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src 'self' https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://telegram.org; connect-src 'self'; form-action 'self'; frame-src https://telegram.org https://oauth.telegram.org;">
<title>图床管理</title>
<style>
  :root {
    --bg: #f0f2f5;
    --bg-card: #ffffff;
    --bg-hover: #f8f9fa;
    --bg-elevated: #ffffff;
    --text: #1a1a2e;
    --text-muted: #6b6b80;
    --text-dim: #a0a0b4;
    --accent: #6c5ce7;
    --accent-hover: #7d6ff0;
    --accent-glow: rgba(108,92,231,0.12);
    --danger: #e74c5c;
    --danger-hover: #c0394b;
    --success: #2ecc71;
    --border: rgba(0,0,0,0.08);
    --radius: 10px;
    --radius-sm: 6px;
    --shadow: 0 2px 12px rgba(0,0,0,0.08);
    --transition: 0.2s ease;
    --header-gradient: linear-gradient(135deg, #1a1a2e 0%, #2d1b69 50%, #1a1a2e 100%);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0d0d1a;
      --bg-card: #16162a;
      --bg-hover: #1e1e3a;
      --bg-elevated: #1a1a32;
      --text: #e8e8f0;
      --text-muted: #8888a8;
      --text-dim: #5c5c7a;
      --border: rgba(255,255,255,0.06);
      --shadow: 0 2px 16px rgba(0,0,0,0.35);
      --header-gradient: linear-gradient(135deg, #0d0d1a 0%, #1a0a2e 50%, #0d0d1a 100%);
      --accent-glow: rgba(108,92,231,0.25);
    }
  }
  *,*::before,*::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Noto Sans SC', sans-serif;
    background: var(--bg); color: var(--text); min-height: 100vh;
    -webkit-font-smoothing: antialiased;
  }

  /* ── Login Screen ── */
  #login-screen {
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; padding: 20px;
    background: var(--bg);
  }
  .login-card {
    background: var(--bg-card); border: 1px solid var(--border);
    padding: 48px 40px; border-radius: 16px;
    box-shadow: var(--shadow); width: 380px; max-width: 100%;
    text-align: center;
  }
  .login-icon { font-size: 48px; margin-bottom: 16px; line-height: 1; }
  .login-card h2 { font-size: 24px; font-weight: 700; margin-bottom: 4px; color: var(--text); }
  .login-desc { color: var(--text-muted); font-size: 14px; margin-bottom: 28px; }
  .login-error {
    color: var(--danger); font-size: 13px; margin-bottom: 12px;
    display: none; background: rgba(231,76,92,0.1); padding: 8px 12px;
    border-radius: var(--radius-sm);
  }
  .login-error.show { display: block; }
  .tg-login-container { display: flex; justify-content: center; margin-bottom: 16px; }
  .tg-login-container iframe { max-width: 100%; }
  .tg-login-container + .btn-passkey { margin-top: 12px; }

  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 6px;
    padding: 10px 20px; border: none; border-radius: var(--radius-sm);
    font-size: 14px; font-weight: 500; cursor: pointer;
    transition: all var(--transition); text-decoration: none;
    white-space: nowrap; user-select: none;
  }
  .btn:active { transform: scale(0.97); }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { background: var(--accent-hover); box-shadow: 0 0 20px var(--accent-glow); }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-danger:hover { background: var(--danger-hover); }
  .btn-ghost { background: transparent; color: var(--text-muted); border: 1px solid var(--border); }
  .btn-ghost:hover { background: var(--bg-hover); color: var(--text); }
  .btn-sm { padding: 6px 12px; font-size: 12px; }
  .btn-xs { padding: 4px 10px; font-size: 11px; border-radius: 4px; }
  .btn-block { width: 100%; }
  .btn-passkey { background: #1a6d4a; color: #fff; margin-top: 8px; }
  .btn-passkey:hover { background: #21885d; }

  .btn-icon {
    width: 28px; height: 28px; padding: 0; display: inline-flex;
    align-items: center; justify-content: center;
    border: none; border-radius: 4px; cursor: pointer;
    font-size: 16px; line-height: 1; transition: all var(--transition);
    background: transparent; color: var(--text-muted);
  }
  .btn-icon:hover { background: var(--bg-hover); color: var(--text); }

  /* ── Card Selection ── */
  .card-check { position: absolute; top: 8px; left: 8px; z-index: 3; }
  .card-check input[type="checkbox"] { width: 18px; height: 18px; cursor: pointer; accent-color: var(--accent); }
  .card.card-selected { box-shadow: 0 0 0 2px var(--accent), var(--shadow); }
  .card-selected .card-thumb::after { content: ''; position: absolute; inset: 0; background: rgba(108,92,231,0.1); pointer-events: none; z-index: 1; }

  /* ── Header ── */
  .header {
    background: var(--header-gradient);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 40;
    backdrop-filter: blur(12px);
  }
  .header-inner {
    max-width: 1280px; margin: 0 auto;
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 24px; gap: 12px;
  }
  .header-left { display: flex; align-items: center; gap: 12px; }
  .header-left h1 { font-size: 18px; font-weight: 700; letter-spacing: -0.3px; }
  .header-badge {
    font-size: 11px; background: var(--accent); color: #fff;
    padding: 2px 8px; border-radius: 10px; font-weight: 500;
  }
  .header-actions { display: flex; align-items: center; gap: 8px; }

  /* ── Stats Bar ── */
  .stats-bar {
    max-width: 1280px; margin: 16px auto 0; padding: 0 24px;
    display: flex; gap: 16px;
  }
  .stat {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 14px 20px;
    display: flex; align-items: center; gap: 12px; flex: 1;
  }
  .stat-icon {
    width: 36px; height: 36px; border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
  }
  .stat-icon.blue { background: rgba(108,92,231,0.15); }
  .stat-icon.green { background: rgba(46,204,113,0.15); }
  .stat-info { display: flex; flex-direction: column; }
  .stat-value { font-size: 20px; font-weight: 700; line-height: 1.2; }
  .stat-label { font-size: 12px; color: var(--text-muted); }

  /* ── Toolbar ── */
  .toolbar {
    max-width: 1280px; margin: 12px auto 0; padding: 0 24px;
    display: flex; align-items: center; gap: 12px;
  }
  .search-box {
    position: relative; flex: 1; max-width: 360px;
  }
  .search-box input {
    width: 100%; padding: 9px 14px 9px 36px;
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius-sm); color: var(--text);
    font-size: 14px; outline: none; transition: border var(--transition);
  }
  .search-box input:focus { border-color: var(--accent); }
  .search-box input::placeholder { color: var(--text-dim); }
  .search-icon {
    position: absolute; left: 12px; top: 50%; transform: translateY(-50%);
    color: var(--text-muted); font-size: 14px; pointer-events: none;
  }
  .sort-group { display: flex; border: 1px solid var(--border); border-radius: var(--radius-sm); overflow: hidden; }
  .sort-btn {
    padding: 8px 14px; border: none; background: transparent;
    color: var(--text-muted); font-size: 13px; cursor: pointer;
    transition: all var(--transition);
  }
  .sort-btn:hover { color: var(--text); background: var(--bg-hover); }
  .sort-btn.active { background: var(--accent); color: #fff; }
  .btn-refresh {
    padding: 8px 12px; border: 1px solid var(--border); border-radius: var(--radius-sm);
    background: transparent; color: var(--text-muted); cursor: pointer;
    font-size: 16px; transition: all var(--transition); line-height: 1;
  }
  .btn-refresh:hover { background: var(--bg-hover); color: var(--text); }
  .btn-refresh.spin { animation: spin 0.6s; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Gallery Grid ── */
  .container { max-width: 1280px; margin: 0 auto; padding: 16px 24px 40px; }
  .gallery {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 16px;
  }

  /* ── Card ── */
  .card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
    transition: transform var(--transition), box-shadow var(--transition);
  }
  .card:hover { transform: translateY(-2px); box-shadow: var(--shadow); }
  .card-thumb {
    position: relative; width: 100%; aspect-ratio: 16/10;
    background: var(--bg-elevated); cursor: pointer; overflow: hidden;
  }
  .card-thumb img {
    width: 100%; height: 100%; object-fit: cover;
    transition: transform 0.3s ease;
  }
  .card:hover .card-thumb img { transform: scale(1.05); }
  .card-thumb .overlay {
    position: absolute; inset: 0;
    background: rgba(0,0,0,0.4); opacity: 0;
    display: flex; align-items: center; justify-content: center;
    transition: opacity var(--transition);
  }
  .card:hover .card-thumb .overlay { opacity: 1; }
  .card-thumb .overlay span {
    color: #fff; font-size: 13px; font-weight: 500;
    background: rgba(0,0,0,0.5); padding: 6px 14px; border-radius: 20px;
  }

  .card-body { padding: 12px 14px 14px; }
  .card-name {
    font-size: 13px; font-weight: 500;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    margin-bottom: 4px;
  }
  .card-meta {
    font-size: 11px; color: var(--text-muted);
    display: flex; align-items: center; gap: 4px; margin-bottom: 10px;
  }
  .card-meta .dot { color: var(--text-dim); margin: 0 2px; }

  .card-actions {
    display: flex; flex-wrap: wrap; gap: 4px;
  }
  .card-actions .fmt-btn {
    padding: 4px 8px; border: 1px solid var(--border);
    border-radius: 4px; background: transparent; color: var(--text-muted);
    font-size: 10px; font-weight: 500; cursor: pointer;
    transition: all var(--transition); letter-spacing: 0.3px;
    text-transform: uppercase;
  }
  .card-actions .fmt-btn:hover {
    background: var(--accent); border-color: var(--accent); color: #fff;
  }
  .card-actions .fmt-btn.copied {
    background: var(--success); border-color: var(--success); color: #fff;
  }
  .card-actions .del-btn {
    margin-left: auto;
    padding: 4px 8px; border: none; border-radius: 4px;
    background: transparent; color: var(--text-dim);
    font-size: 11px; cursor: pointer; transition: all var(--transition);
  }
  .card-actions .del-btn:hover { background: rgba(231,76,92,0.15); color: var(--danger); }

  /* ── Loading States ── */
  .skeleton-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 16px;
  }
  .skeleton-card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
  }
  .skeleton-thumb {
    width: 100%; aspect-ratio: 16/10;
    background: linear-gradient(90deg, var(--bg-elevated) 25%, var(--bg-hover) 50%, var(--bg-elevated) 75%);
    background-size: 200% 100%; animation: shimmer 1.5s infinite;
  }
  .skeleton-line {
    height: 12px; margin: 12px 14px 0;
    background: linear-gradient(90deg, var(--bg-elevated) 25%, var(--bg-hover) 50%, var(--bg-elevated) 75%);
    background-size: 200% 100%; animation: shimmer 1.5s infinite;
    border-radius: 4px;
  }
  .skeleton-line.short { width: 60%; }
  .skeleton-line:last-child { margin-bottom: 14px; }
  @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }

  .empty-state {
    grid-column: 1 / -1; text-align: center; padding: 60px 20px;
    color: var(--text-muted);
  }
  .empty-state .empty-icon { font-size: 48px; margin-bottom: 12px; }
  .empty-state p { font-size: 15px; }

  .load-more-wrap { text-align: center; padding: 20px 0 40px; }
  .load-more-wrap .msg { color: var(--text-muted); font-size: 13px; padding: 12px 0; }

  /* ── Preview Overlay ── */
  .preview-overlay {
    display: none; position: fixed; inset: 0; z-index: 100;
    background: rgba(0,0,0,0.92);
    align-items: center; justify-content: center;
  }
  .preview-overlay.show { display: flex; }
  .preview-overlay img {
    max-width: 92vw; max-height: 88vh; border-radius: 6px;
    object-fit: contain; box-shadow: 0 8px 40px rgba(0,0,0,0.5);
    user-select: none;
  }
  .preview-close {
    position: fixed; top: 20px; right: 20px;
    width: 40px; height: 40px; border: none; border-radius: 50%;
    background: rgba(255,255,255,0.1); color: #fff;
    font-size: 20px; cursor: pointer; z-index: 101;
    display: flex; align-items: center; justify-content: center;
    transition: background var(--transition);
  }
  .preview-close:hover { background: rgba(255,255,255,0.2); }
  .preview-nav {
    position: fixed; top: 50%; transform: translateY(-50%);
    width: 44px; height: 44px; border: none; border-radius: 50%;
    background: rgba(255,255,255,0.08); color: #fff;
    font-size: 28px; cursor: pointer; z-index: 101;
    display: flex; align-items: center; justify-content: center;
    transition: background var(--transition);
  }
  .preview-nav:hover { background: rgba(255,255,255,0.18); }
  .preview-nav.prev { left: 20px; }
  .preview-nav.next { right: 20px; }
  .preview-nav.hidden { opacity: 0; pointer-events: none; }
  .preview-counter {
    position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
    color: rgba(255,255,255,0.5); font-size: 13px; z-index: 101;
  }

  /* ── Toast ── */
  .toast-container {
    position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
    z-index: 200; display: flex; flex-direction: column; gap: 8px;
    align-items: center; pointer-events: none;
  }
  .toast {
    background: var(--bg-elevated); border: 1px solid var(--border);
    color: var(--text); padding: 10px 20px; border-radius: var(--radius-sm);
    font-size: 13px; box-shadow: var(--shadow);
    opacity: 0; transform: translateY(10px);
    transition: all 0.25s ease; pointer-events: auto;
  }
  .toast.show { opacity: 1; transform: translateY(0); }
  .toast.success { border-color: var(--success); }
  .toast.error { border-color: var(--danger); color: var(--danger); }

  /* ── Responsive ── */
  @media (max-width: 768px) {
    .header-inner { padding: 12px 16px; }
    .stats-bar { padding: 0 16px; flex-direction: column; gap: 8px; }
    .toolbar { padding: 0 16px; flex-wrap: wrap; }
    .search-box { max-width: 100%; }
    .container { padding: 12px 16px 32px; }
    .gallery { grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; }
    .skeleton-grid { grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; }
    .card-body { padding: 10px 12px 12px; }
    .card-actions .fmt-btn { font-size: 9px; padding: 3px 6px; }
    .preview-nav { width: 36px; height: 36px; font-size: 22px; }
    .preview-nav.prev { left: 8px; }
    .preview-nav.next { right: 8px; }
    .login-card { padding: 28px 20px; }
  }
  @media (max-width: 480px) {
    .gallery { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; }
    .skeleton-grid { grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; }
  }
</style>
</head>
<body>

<!-- ═══ Login Screen ═══ -->
<div id="login-screen">
  <div class="login-card">
    <div class="login-icon">🖼</div>
    <h2>图床管理</h2>
    <p class="login-desc">验证身份后管理你的图片</p>
    <div class="login-error" id="login-error"></div>

    ${hasTelegramLogin ? `
    <div class="tg-login-container">
      <script async src="https://telegram.org/js/telegram-widget.js?22"
        data-telegram-login="${botUsername}"
        data-size="large"
        data-onauth="onTelegramAuth(user)"
        data-request-access="read">
      <\/script>
    </div>` : ''}

    <button class="btn btn-passkey btn-block" id="passkey-login-btn" style="display:none" onclick="loginPassKey()">
      🔑 使用 PassKey 登录
    </button>
    <button class="btn btn-passkey btn-block" id="register-first-passkey-btn" style="display:none" onclick="registerFirstPassKey()">
      🔑 注册 PassKey
    </button>
  </div>
</div>

<!-- ═══ Main App ═══ -->
<div id="app" style="display:none">

  <!-- Header -->
  <div class="header">
    <div class="header-inner">
      <div class="header-left">
        <h1>图床管理</h1>
        <span class="header-badge">v1</span>
      </div>
      <div class="header-actions">
        <button class="btn btn-ghost btn-sm" id="register-passkey-btn" style="display:none" onclick="registerPassKey()">
          🔑 注册 PassKey
        </button>
        <button class="btn btn-ghost btn-sm" onclick="logout()">退出</button>
      </div>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-bar">
    <div class="stat">
      <div class="stat-icon blue">🖼</div>
      <div class="stat-info">
        <span class="stat-value" id="stat-count">-</span>
        <span class="stat-label">图片总数</span>
      </div>
    </div>
    <div class="stat">
      <div class="stat-icon green">💾</div>
      <div class="stat-info">
        <span class="stat-value" id="stat-size">-</span>
        <span class="stat-label">总大小</span>
      </div>
    </div>
  </div>

  <!-- Toolbar -->
  <div class="toolbar">
    <div class="search-box">
      <span class="search-icon">🔍</span>
      <input type="text" id="search-input" placeholder="搜索文件名..." oninput="onSearchInput()">
    </div>
    <div class="sort-group">
      <button class="sort-btn active" id="sort-newest" onclick="setSort('newest')">最新</button>
      <button class="sort-btn" id="sort-oldest" onclick="setSort('oldest')">最早</button>
    </div>
    <button class="btn btn-danger btn-sm" id="batch-delete-btn" style="display:none" onclick="batchDelete()">🗑 删除选中 (<span id="selected-count">0</span>)</button>
    <button class="btn-refresh" onclick="refreshImages()" id="refresh-btn">↻</button>
  </div>

  <!-- Gallery -->
  <div class="container">
    <div class="gallery" id="gallery"></div>

    <!-- Skeleton -->
    <div class="skeleton-grid" id="skeleton">
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line short"></div></div>
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line short"></div></div>
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line short"></div></div>
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line short"></div></div>
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line short"></div></div>
      <div class="skeleton-card"><div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line short"></div></div>
    </div>

    <!-- Load more -->
    <div class="load-more-wrap">
      <div class="msg" id="load-msg"></div>
      <button class="btn btn-primary" id="load-more-btn" style="display:none" onclick="loadMore()">加载更多</button>
    </div>
  </div>
</div>

<!-- ═══ Preview Overlay ═══ -->
<div class="preview-overlay" id="preview">
  <button class="preview-close" onclick="closePreview()">✕</button>
  <button class="preview-nav prev" id="prev-btn" onclick="prevImage()">‹</button>
  <img id="preview-img" src="" alt="preview">
  <button class="preview-nav next" id="next-btn" onclick="nextImage()">›</button>
  <div class="preview-counter" id="preview-counter"></div>
</div>

<!-- ═══ Toast ═══ -->
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

// ── WebAuthn check ──
if (window.PublicKeyCredential) {
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(avail => {
    webauthnAvailable = avail;
    if (avail) {
      // Check setup status to show the right button
      fetch('/admin/api/webauthn/setup-status').then(r => r.json()).then(status => {
        if (status.canRegister) {
          document.getElementById('register-first-passkey-btn').style.display = 'block';
        } else {
          document.getElementById('passkey-login-btn').style.display = 'block';
        }
      }).catch(() => {
        document.getElementById('passkey-login-btn').style.display = 'block';
      });
    }
  });
}

// ── Telegram Login ──
${hasTelegramLogin ? `
async function onTelegramAuth(user) {
  const err = document.getElementById('login-error');
  err.classList.remove('show');
  try {
    const resp = await fetch('/admin/api/tg-login', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(user),
    });
    if (resp.ok) { onLoginSuccess(); }
    else {
      const d = await resp.json();
      err.textContent = 'TG 认证失败：' + (d.error || '未知错误');
      err.classList.add('show');
    }
  } catch { err.textContent = '网络错误，请重试'; err.classList.add('show'); }
}` : ''}

// ── PassKey Login ──
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

// ── PassKey Registration ──
async function registerPassKey() {
  const btn = document.getElementById('register-passkey-btn');
  btn.disabled = true; btn.textContent = '⏳ 注册中...';
  try {
    const beginResp = await fetch('/admin/api/webauthn/register/begin', { method: 'POST' });
    if (!beginResp.ok) {
      const d = await beginResp.json();
      showToast('注册失败: ' + (d.error || '无法开始注册'), 'error');
      btn.disabled = false; btn.textContent = '🔑 注册 PassKey'; return;
    }
    const options = await beginResp.json();
    options.challenge = base64ToArray(options.challenge);
    options.user.id = base64ToArray(options.user.id);
    const cred = await navigator.credentials.create({ publicKey: options });
    const resp = await fetch('/admin/api/webauthn/register/complete', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(formatWebAuthnResponse(cred)),
    });
    if (resp.ok) { showToast('PassKey 注册成功 ✅', 'success'); btn.textContent = '✅ 已注册'; }
    else { const d = await resp.json(); showToast('注册失败: ' + (d.error || '未知错误'), 'error'); btn.textContent = '🔑 注册 PassKey'; }
    btn.disabled = false;
    setTimeout(() => { btn.textContent = '🔑 注册 PassKey'; btn.disabled = false; }, 2500);
  } catch (e) {
    if (e.name === 'AbortError' || e.name === 'NotAllowedError') { btn.textContent = '🔑 注册 PassKey'; btn.disabled = false; return; }
    showToast('注册失败', 'error'); btn.textContent = '🔑 注册 PassKey'; btn.disabled = false;
  }
}

// ── First-time PassKey registration from login screen ──
async function registerFirstPassKey() {
  const btn = document.getElementById('register-first-passkey-btn');
  btn.disabled = true; btn.textContent = '⏳ 注册中...';
  try {
    const beginResp = await fetch('/admin/api/webauthn/register/begin', { method: 'POST' });
    if (!beginResp.ok) {
      const d = await beginResp.json();
      showToast('注册失败: ' + (d.error || '无法开始注册'), 'error');
      btn.disabled = false; btn.textContent = '🔑 注册 PassKey'; return;
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
    else { const d = await resp.json(); showToast('注册失败: ' + (d.error || '未知错误'), 'error'); btn.disabled = false; btn.textContent = '🔑 注册 PassKey'; }
  } catch (e) {
    if (e.name === 'AbortError' || e.name === 'NotAllowedError') { btn.textContent = '🔑 注册 PassKey'; btn.disabled = false; return; }
    showToast('注册失败', 'error'); btn.textContent = '🔑 注册 PassKey'; btn.disabled = false;
  }
}

// ── Login Success ──
function onLoginSuccess() {
  document.getElementById('login-screen').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  if (webauthnAvailable) document.getElementById('register-passkey-btn').style.display = 'inline-flex';
  loadImages();
}

// ── WebAuthn Helpers ──
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

// ── Card Selection ──
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
  btn.disabled = true;
  btn.textContent = '⏳ 删除中...';

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
      btn.disabled = false;
      btn.innerHTML = '🗑 删除选中 (<span id="selected-count">' + count + '</span>)';
    }
  } catch {
    showToast('批量删除失败', 'error');
    btn.disabled = false;
    btn.innerHTML = '🗑 删除选中 (<span id="selected-count">' + count + '</span>)';
  }
}

// ── Image Gallery ──
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
    gallery.innerHTML = '<div class="empty-state"><div class="empty-icon">📭</div><p>暂无图片</p></div>';
    return;
  }
  for (const img of images) {
    allImages.push(img);
    const card = document.createElement('div');
    card.className = 'card';
    card.dataset.nanoid = img.nanoid;
    const idx = allImages.length - 1;
    card.innerHTML = \`
      <div class="card-thumb" onclick="openPreview(\${idx})">
        <img src="\${img.publicUrl}" alt="" loading="lazy">
        <div class="overlay"><span>🔍 预览</span></div>
        <div class="card-check"><input type="checkbox" class="img-check" data-nanoid="\${img.nanoid}" onclick="event.stopPropagation()" onchange="onImageCheck(this)"></div>
      </div>
      <div class="card-body">
        <div class="card-name" title="\${escHtml(img.fileName || img.r2Key)}">\${escHtml(img.fileName || img.r2Key)}</div>
        <div class="card-meta">
          \${formatSize(img.fileSize)}
          <span class="dot">·</span>
          \${formatTime(img.timestamp)}
          <span class="dot">·</span>
          \${escHtml(img.uploader || '?')}
        </div>
        <div class="card-actions">
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="url">URL</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="md">MD</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="html">HTML</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="bbcode">BBC</button>
          <button class="del-btn" data-nanoid="\${img.nanoid}" title="删除">🗑</button>
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
    btn.disabled = false;
    btn.textContent = '加载更多';
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

// ── Search & Sort ──
function onSearchInput() {
  searchQuery = document.getElementById('search-input').value.toLowerCase().trim();
  applyFilter();
}

function setSort(sort) {
  currentSort = sort;
  document.querySelectorAll('.sort-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(sort === 'newest' ? 'sort-newest' : 'sort-oldest').classList.add('active');
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
    gallery.innerHTML = '<div class="empty-state"><div class="empty-icon">🔍</div><p>' + (searchQuery ? '没有匹配的图片' : '暂无图片') + '</p></div>';
    document.getElementById('load-more-btn').style.display = 'none';
    document.getElementById('load-msg').textContent = '';
    return;
  }
  // Re-render filtered images using stored data (simple approach: rebuild cards from stored arr)
  const indices = filtered.map(img => allImages.indexOf(img));
  for (const idx of indices) {
    const img = allImages[idx];
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = \`
      <div class="card-thumb" onclick="openPreview(\${idx})">
        <img src="\${img.publicUrl}" alt="" loading="lazy">
        <div class="overlay"><span>🔍 预览</span></div>
        <div class="card-check"><input type="checkbox" class="img-check" data-nanoid="\${img.nanoid}" onclick="event.stopPropagation()" onchange="onImageCheck(this)"></div>
      </div>
      <div class="card-body">
        <div class="card-name" title="\${escHtml(img.fileName || img.r2Key)}">\${escHtml(img.fileName || img.r2Key)}</div>
        <div class="card-meta">
          \${formatSize(img.fileSize)}
          <span class="dot">·</span>
          \${formatTime(img.timestamp)}
          <span class="dot">·</span>
          \${escHtml(img.uploader || '?')}
        </div>
        <div class="card-actions">
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="url">URL</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="md">MD</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="html">HTML</button>
          <button class="fmt-btn" data-url="\${img.publicUrl}" data-name="\${escHtml(img.fileName || 'image')}" data-format="bbcode">BBC</button>
          <button class="del-btn" data-nanoid="\${img.nanoid}" title="删除">🗑</button>
        </div>
      </div>
    \`;
    gallery.appendChild(card);
  }
  // Restore selection state after re-render
  document.querySelectorAll('.img-check').forEach(cb => {
    if (selectedNanoids.has(cb.dataset.nanoid)) {
      cb.checked = true;
      cb.closest('.card').classList.add('card-selected');
    }
  });
  updateLoadMore();
}

async function refreshImages() {
  const btn = document.getElementById('refresh-btn');
  btn.classList.add('spin');
  cursor = null; complete = false; allImages = []; selectedNanoids.clear();
  document.getElementById('gallery').innerHTML = '';
  updateBatchDeleteBtn();
  await loadImages();
  setTimeout(() => btn.classList.remove('spin'), 600);
}

// ── Copy Format ──
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
    btn.textContent = '✓';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1200);
    showToast('已复制 ' + format.toUpperCase(), 'success');
  }).catch(() => showToast('复制失败', 'error'));
}

// ── Delete ──
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

// ── Preview with keyboard nav ──
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

function prevImage() {
  if (previewIndex > 0) openPreview(previewIndex - 1);
}
function nextImage() {
  if (previewIndex < allImages.length - 1) openPreview(previewIndex + 1);
}
function updateNavButtons() {
  document.getElementById('prev-btn').classList.toggle('hidden', previewIndex <= 0);
  document.getElementById('next-btn').classList.toggle('hidden', previewIndex >= allImages.length - 1);
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
  const preview = document.getElementById('preview');
  if (!preview.classList.contains('show')) return;
  if (e.key === 'Escape') closePreview();
  if (e.key === 'ArrowLeft') prevImage();
  if (e.key === 'ArrowRight') nextImage();
});

// Click outside image to close preview
document.getElementById('preview').addEventListener('click', function(e) {
  if (e.target === this) closePreview();
});


// Delegate clicks on format/delete buttons (eliminates inline onclick XSS)
document.getElementById('gallery').addEventListener('click', function(e) {
  const target = e.target.closest('.fmt-btn, .del-btn');
  if (!target) return;
  if (target.classList.contains('fmt-btn')) {
    copyFormat(target.dataset.url, target.dataset.name, target.dataset.format, target);
  } else if (target.classList.contains('del-btn')) {
    deleteImg(target.dataset.nanoid);
  }
});

// ── Logout ──
function logout() {
  const secure = location.protocol === 'https:';
  document.cookie = 'admin_token=; Path=/admin; Max-Age=0' + (secure ? '; Secure' : '');
  location.reload();
}

// ── Format Helpers ──
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

// ── Toast ──
function showToast(msg, type) {
  const container = document.getElementById('toast');
  const el = document.createElement('div');
  el.className = 'toast' + (type ? ' ' + type : '');
  el.textContent = msg;
  container.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 250);
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
