import {
  generateId, getExtension, buildTelegramUrl,
  parseAllowedUsers, isAllowedUser, checkRateLimit,
  verifyWebhookSecret, isValidImageMime, secureHeaders,
} from './utils.js';
import { handleAdminRequest } from './admin.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Route: admin dashboard
    if (url.pathname.startsWith('/admin')) {
      return handleAdminRequest(request, env);
    }

    // Route: serve uploaded images from R2 (when Worker is on the custom domain)
    if (url.pathname.startsWith('/uploads/')) {
      const r2Key = url.pathname.slice(1); // remove leading /
      const obj = await env.IMG_BUCKET.get(r2Key);
      if (!obj) return new Response('Not found', { status: 404, headers: secureHeaders() });
      return new Response(obj.body, {
        headers: {
          ...secureHeaders(),
          'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
          'Cache-Control': 'public, max-age=31536000, immutable',
          'Accept-Ranges': 'bytes',
        },
      });
    }

    // Route: Telegram webhook (POST /webhook only)
    if (request.method !== 'POST' || url.pathname !== '/webhook') {
      return new Response('Not found', { status: 404, headers: secureHeaders() });
    }

    // Security: verify webhook origin via secret token
    if (!verifyWebhookSecret(request, env)) {
      console.warn('Forbidden webhook call: invalid secret token');
      return new Response('Forbidden', { status: 403, headers: secureHeaders() });
    }

    const allowedUsers = parseAllowedUsers(env.ALLOWED_USERS);

    try {
      const update = await request.json();
      await handleUpdate(update, env, allowedUsers);
    } catch (err) {
      console.error('handleUpdate error:', err);
    }

    return new Response('OK', { headers: secureHeaders() });
  },
};

async function handleUpdate(update, env, allowedUsers) {
  const msg = update.message;
  if (!msg || !msg.from) return;

  const chatId = msg.chat.id;
  const fromUsername = (msg.from.username || '').toLowerCase();
  const from = { id: msg.from.id, username: fromUsername, displayName: msg.from.username || msg.from.first_name || 'unknown' };

  // Permission check: user whitelist
  if (!isAllowedUser(fromUsername, allowedUsers)) {
    await sendMessage(env.BOT_TOKEN, chatId, '❌ 你没有权限使用此 Bot。', msg.message_id);
    return;
  }

  // Rate limiting: max 30 requests per minute per user
  const allowed = await checkRateLimit(env, `tg:${from.id}`, 30, 60);
  if (!allowed) {
    console.warn(`Rate limited: user ${fromUsername} (${from.id})`);
    await sendMessage(env.BOT_TOKEN, chatId, '⏱ 请求过于频繁，请稍后再试。', msg.message_id);
    return;
  }

  // Route: Delete command (in groups, Telegram appends @BotUsername to commands)
  if (msg.text && msg.reply_to_message && msg.text.split('@')[0] === '/delete') {
    await handleDelete(env, chatId, msg, from);
    return;
  }

  // Route: Image upload (photo or document)
  const fileId = getFileId(msg);
  if (fileId) {
    await handleUpload(env, chatId, msg, from, fileId);
  }
}

function getFileId(msg) {
  // Photo - use the largest size
  if (msg.photo && msg.photo.length > 0) {
    const photos = msg.photo;
    return photos[photos.length - 1].file_id;
  }
  // Document with image type
  if (msg.document && msg.document.mime_type) {
    // Validate MIME type server-side
    if (!isValidImageMime(msg.document.mime_type)) {
      return null;
    }
    return msg.document.file_id;
  }
  return null;
}

async function handleUpload(env, chatId, msg, from, fileId) {
  // Get file path from Telegram
  const fileResp = await fetch(buildTelegramUrl(env.BOT_TOKEN, `getFile?file_id=${fileId}`), { signal: AbortSignal.timeout(10000) });
  const fileData = await fileResp.json();
  if (!fileData.ok) {
    await sendMessage(env.BOT_TOKEN, chatId, '❌ 获取文件失败。', msg.message_id);
    return;
  }

  const filePath = fileData.result.file_path;
  const fileName = filePath.split('/').pop() || 'image';

  // Enforce max file size: Telegram reports file_size in getFile response
  // Max 50MB to stay well within Worker limits
  const MAX_SIZE = 50 * 1024 * 1024;
  if (fileData.result.file_size && fileData.result.file_size > MAX_SIZE) {
    await sendMessage(env.BOT_TOKEN, chatId, `❌ 文件过大（上限 ${MAX_SIZE / 1024 / 1024}MB）。`, msg.message_id);
    return;
  }

  // Download file from Telegram (note: URL format is file/bot<TOKEN>/<path>, NOT bot<TOKEN>/file/<path>)
  const fileUrl = `https://api.telegram.org/file/bot${env.BOT_TOKEN}/${filePath}`;
  const fileResp2 = await fetch(fileUrl, { signal: AbortSignal.timeout(30000) });
  if (!fileResp2.ok) {
    console.error(`File download failed: ${fileResp2.status} ${fileResp2.statusText} for ${filePath}`);
    await sendMessage(env.BOT_TOKEN, chatId, '❌ 下载文件失败。', msg.message_id);
    return;
  }

  // Size check via Content-Length (when Telegram omits file_size in getFile response)
  const contentLength = fileResp2.headers.get('Content-Length');
  if (contentLength && parseInt(contentLength) > MAX_SIZE) {
    await sendMessage(env.BOT_TOKEN, chatId, `❌ 文件过大（上限 ${MAX_SIZE / 1024 / 1024}MB）。`, msg.message_id);
    return;
  }

  const fileBuffer = await fileResp2.arrayBuffer();
  const contentType = fileResp2.headers.get('content-type') || 'application/octet-stream';
  const ext = getExtension(contentType);

  // Reject non-image or unknown types
  if (ext === 'bin' || !isValidImageMime(contentType)) {
    await sendMessage(env.BOT_TOKEN, chatId, '❌ 不支持的文件类型，请上传图片。', msg.message_id);
    return;
  }

  const nanoid = await generateId();
  const r2Key = `uploads/${nanoid}.${ext}`;

  // Upload to R2
  await env.IMG_BUCKET.put(r2Key, fileBuffer, {
    httpMetadata: { contentType },
    customMetadata: { uploader: from.username },
  });

  // Build public URL
  const publicUrl = `${env.PUBLIC_URL.replace(/\/+$/, '')}/${r2Key}`;

  // Save metadata to KV
  const metadata = {
    nanoid,
    r2Key,
    fileName,
    mimeType: contentType,
    fileSize: fileBuffer.byteLength,
    uploader: from.username,
    uploaderId: from.id,
    chatId,
    messageId: msg.message_id,
    timestamp: Date.now(),
  };
  // Reverse index saved after bot replies below
  // Save reverse index: user message -> img:nanoid
  await env.IMG_KV.put(`msg:${chatId}:${msg.message_id}`, `img:${nanoid}`);

  // Send 3 separate messages for easy copying
  const sizeStr = `(${(fileBuffer.byteLength / 1024).toFixed(1)} KB)`;
  const sizeMsg = `✅ 上传成功 ${sizeStr}\n\n${publicUrl}`;
  const mdMsg  = `![${fileName}](${publicUrl})`;
  const htmlMsg = `<img src="${publicUrl}" alt="${fileName}">`;

  const [urlResp, mdResp, htmlResp] = await Promise.all([
    sendMessage(env.BOT_TOKEN, chatId, sizeMsg, msg.message_id, null),
    sendMessage(env.BOT_TOKEN, chatId, mdMsg, msg.message_id, null),
    sendMessage(env.BOT_TOKEN, chatId, htmlMsg, msg.message_id, null),
  ]);

  // Save reverse indexes: all 3 bot messages -> img:nanoid (for reply-to-delete)
  const botMsgIds = [];
  for (const resp of [urlResp, mdResp, htmlResp]) {
    if (resp.ok && resp.result && resp.result.message_id) {
      botMsgIds.push(resp.result.message_id);
      await env.IMG_KV.put(`msg:${chatId}:${resp.result.message_id}`, `img:${nanoid}`);
    }
  }
  metadata.botMessageIds = botMsgIds;
  if (botMsgIds.length > 0) {
    metadata.botMessageId = botMsgIds[0];
  }
  await env.IMG_KV.put(`img:${nanoid}`, JSON.stringify(metadata));
}

async function handleDelete(env, chatId, msg, from) {
  const repliedMsgId = msg.reply_to_message.message_id;

  // Look up reverse index
  const indexKey = `msg:${chatId}:${repliedMsgId}`;
  const imgRef = await env.IMG_KV.get(indexKey);
  if (!imgRef) {
    await sendMessage(env.BOT_TOKEN, chatId, '❌ 此消息不是图床上传的图片。', msg.message_id);
    return;
  }

  // Get full metadata
  const metadataJson = await env.IMG_KV.get(imgRef);
  if (!metadataJson) {
    await sendMessage(env.BOT_TOKEN, chatId, '❌ 未找到图片记录。', msg.message_id);
    return;
  }

  let metadata;
  try { metadata = JSON.parse(metadataJson); } catch {
    await sendMessage(env.BOT_TOKEN, chatId, '❌ 数据异常。', msg.message_id);
    return;
  }

  // Permission check: only uploader or admin can delete
  const admins = parseAllowedUsers(env.ADMIN_USERNAMES);
  const isAdmin = admins && admins.includes(from.username);
  const isOwner = metadata.uploader === from.username || metadata.uploaderId === from.id;

  if (!isOwner && !isAdmin) {
    await sendMessage(env.BOT_TOKEN, chatId, '❌ 你无权删除此图片。', msg.message_id);
    return;
  }

  // Delete from R2
  try {
    await env.IMG_BUCKET.delete(metadata.r2Key);
  } catch (err) {
    console.error('R2 delete error:', err);
  }

  // Delete from KV — clean up both reverse indexes
  const keysToDelete = [imgRef, indexKey];
  if (metadata.messageId) keysToDelete.push(`msg:${chatId}:${metadata.messageId}`);
  if (metadata.botMessageIds) {
    metadata.botMessageIds.forEach(mid => keysToDelete.push(`msg:${chatId}:${mid}`));
  } else if (metadata.botMessageId) {
    keysToDelete.push(`msg:${chatId}:${metadata.botMessageId}`);
  }
  await Promise.all(keysToDelete.map(k => env.IMG_KV.delete(k)));

  await sendMessage(env.BOT_TOKEN, chatId, '✅ 图片已删除。', msg.message_id);
}

async function sendMessage(token, chatId, text, replyTo, parseMode) {
  const body = {
    chat_id: chatId,
    text,
    reply_to_message_id: replyTo,
    disable_web_page_preview: true,
  };
  // parseMode=null → plain text, parseMode=undefined → Markdown (default)
  if (parseMode !== null) {
    body.parse_mode = parseMode || 'Markdown';
  }

  const resp = await fetch(buildTelegramUrl(token, 'sendMessage'), {
    signal: AbortSignal.timeout(10000),
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const result = await resp.json();
  if (!result.ok) {
    console.error('sendMessage failed:', JSON.stringify(result));
  }
  return result;
}
