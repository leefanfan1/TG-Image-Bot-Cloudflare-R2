// Generate a short unique ID using Web Crypto API
export async function generateId(length = 12) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  // Rejection sampling to avoid modulo bias (256 % 36 !== 0)
  const maxValid = 256 - (256 % chars.length); // 252
  let id = '';
  while (id.length < length) {
    const rand = new Uint8Array(length - id.length);
    crypto.getRandomValues(rand);
    for (let i = 0; i < rand.length && id.length < length; i++) {
      if (rand[i] < maxValid) {
        id += chars[rand[i] % chars.length];
      }
    }
  }
  return id;
}

const MIME_EXT = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'image/webp': 'webp',
  'image/bmp': 'bmp',
  'image/tiff': 'tiff',
  'image/avif': 'avif',
  // SVG intentionally excluded — see VALID_MIME_TYPES below
};

// Supported image MIME types — SVG excluded to prevent XSS via embedded scripts
const VALID_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/tiff', 'image/avif'];

export function getExtension(mimeType) {
  return MIME_EXT[mimeType] || 'bin';
}

export function isValidImageMime(mimeType) {
  return VALID_MIME_TYPES.some(m => mimeType === m);
}

export function buildTelegramUrl(token, method) {
  return `https://api.telegram.org/bot${token}/${method}`;
}

export function parseAllowedUsers(envValue) {
  if (!envValue) return null; // null means allow all
  return envValue.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}

export function isAllowedUser(username, allowedUsers) {
  if (allowedUsers === null) return true;
  return allowedUsers.includes(username.toLowerCase());
}

// Rate limiting using KV with TTL
export async function checkRateLimit(env, key, limit, windowSeconds) {
  if (!limit || limit <= 0) return true; // no limit configured

  const now = Math.floor(Date.now() / 1000);
  const windowKey = Math.floor(now / windowSeconds);
  const rateKey = `rl:${key}:${windowKey}`;

  const current = await env.IMG_KV.get(rateKey);
  const count = current ? parseInt(current, 10) : 0;

  if (count >= limit) {
    return false; // rate limited
  }

  if (count === 0) {
    await env.IMG_KV.put(rateKey, '1', { expirationTtl: windowSeconds + 60 });
  } else {
    await env.IMG_KV.put(rateKey, String(count + 1), { expirationTtl: windowSeconds + 60 });
  }
  return true;
}

// Validate webhook secret token from Telegram
export function verifyWebhookSecret(request, env) {
  const expected = env.WEBHOOK_SECRET;
  if (!expected) {
    // WEBHOOK_SECRET not configured — skip check (backward compat)
    return true;
  }
  const actual = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
  if (!actual || actual !== expected) {
    return false;
  }
  return true;
}

// Security headers for all responses
export function secureHeaders(headers = {}) {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    ...headers,
  };
}

// CSP headers for admin page
// Note: Telegram Login Widget requires https://telegram.org in script-src and frame-src
export function cspHeaders() {
  return {
    'Content-Security-Policy':
      "default-src 'self'; "
      + "img-src 'self' https:; "
      + "style-src 'self' 'unsafe-inline'; "
      + "script-src 'self' 'unsafe-inline' https://telegram.org; "
      + "connect-src 'self'; "
      + "form-action 'self'; "
      + "frame-src https://telegram.org;",
  };
}
