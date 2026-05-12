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

// Generate timestamp + short random suffix storage key
export async function generateStorageKey(ext) {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  const rand = await generateId(8);
  return `uploads/${y}-${m}-${d}_${rand}.${ext}`;
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

// Reverse map: extension → MIME type
const EXT_MIME = {};
for (const [mime, ext] of Object.entries(MIME_EXT)) {
  EXT_MIME[ext] = mime;
}

// Supported image MIME types — SVG excluded to prevent XSS via embedded scripts
const VALID_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/tiff', 'image/avif'];

export function getExtension(mimeType) {
  return MIME_EXT[mimeType] || 'bin';
}

// Detect MIME type from Telegram file path or response header.
// The file path extension is more reliable than Telegram's file server content-type header.
export function detectMimeType(filePath, responseContentType) {
  const ext = filePath.split('.').pop()?.toLowerCase();
  if (ext && EXT_MIME[ext]) return EXT_MIME[ext];
  // Fallback to response header
  if (responseContentType && isValidImageMime(responseContentType)) return responseContentType;
  return 'application/octet-stream';
}

export function isValidImageMime(mimeType) {
  return VALID_MIME_TYPES.some(m => mimeType === m);
}

// Magic bytes for image format validation
const MAGIC_BYTES = {
  jpg:  [0xFF, 0xD8, 0xFF],
  png:  [0x89, 0x50, 0x4E, 0x47],
  gif:  [0x47, 0x49, 0x46, 0x38],
  bmp:  [0x42, 0x4D],
};

export function isValidImageContent(buffer, ext) {
  if (buffer.byteLength < 4) return false;
  const bytes = new Uint8Array(buffer);

  // Check formats with fixed headers
  const sig = MAGIC_BYTES[ext];
  if (sig) {
    for (let i = 0; i < sig.length; i++) {
      if (bytes[i] !== sig[i]) return false;
    }
    return true;
  }

  // WebP: RIFF + .... + WEBP
  if (ext === 'webp') {
    if (buffer.byteLength < 12) return false;
    if (bytes[0] !== 0x52 || bytes[1] !== 0x49 || bytes[2] !== 0x46 || bytes[3] !== 0x46) return false;
    if (bytes[8] !== 0x57 || bytes[9] !== 0x45 || bytes[10] !== 0x42 || bytes[11] !== 0x50) return false;
    return true;
  }

  // TIFF: little-endian (II) or big-endian (MM)
  if (ext === 'tiff') {
    if (buffer.byteLength < 4) return false;
    return (bytes[0] === 0x49 && bytes[1] === 0x49 && bytes[2] === 0x2A && bytes[3] === 0x00)
        || (bytes[0] === 0x4D && bytes[1] === 0x4D && bytes[2] === 0x00 && bytes[3] === 0x2A);
  }

  // AVIF/AVIS: ISO BMFF container with ftyp box
  if (ext === 'avif') {
    if (buffer.byteLength < 12) return false;
    for (let i = 0; i <= buffer.byteLength - 12; i++) {
      if (bytes[i+4] === 0x66 && bytes[i+5] === 0x74 && bytes[i+6] === 0x79 && bytes[i+7] === 0x70) {
        const brand = String.fromCharCode(bytes[i+8], bytes[i+9], bytes[i+10], bytes[i+11]);
        if (brand === 'avif' || brand === 'avis') return true;
      }
    }
    return false;
  }

  return true; // unknown extension, skip check
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
export function cspHeaders() {
  return {
    'Content-Security-Policy':
      "default-src 'self'; "
      + "img-src 'self' https:; "
      + "style-src 'self' 'unsafe-inline'; "
      + "script-src 'self' 'unsafe-inline' https://telegram.org; "
      + "frame-src https://oauth.telegram.org; "
      + "connect-src 'self' https://static.cloudflareinsights.com; "
      + "form-action 'self';",
  };
}
