/**
 * Set Telegram Bot Webhook URL
 *
 * Usage:
 *   BOT_TOKEN=xxx WEBHOOK_SECRET=xxx WEBHOOK_URL=https://your-worker.example.com/webhook node scripts/set-webhook.js
 *
 * WEBHOOK_SECRET is optional but strongly recommended.
 * It must match the WEBHOOK_SECRET you set via: wrangler secret put WEBHOOK_SECRET
 */

const config = {
  token: process.env.BOT_TOKEN || '',
  url: process.env.WEBHOOK_URL || '',
  secret: process.env.WEBHOOK_SECRET || '',
};

async function main() {
  if (!config.token || !config.url) {
    console.error('Error: BOT_TOKEN and WEBHOOK_URL are required.');
    console.error('');
    console.error('Usage: BOT_TOKEN=xxx WEBHOOK_SECRET=xxx WEBHOOK_URL=https://xxx.workers.dev/webhook node scripts/set-webhook.js');
    process.exit(1);
  }

  const body = {
    url: config.url,
    allowed_updates: ['message'],
    max_connections: 20,
  };

  if (config.secret) {
    body.secret_token = config.secret;
    console.log('   Using secret_token: yes');
  } else {
    console.warn('   Warning: no WEBHOOK_SECRET set. Set one via wrangler secret put WEBHOOK_SECRET');
  }

  const resp = await fetch(`https://api.telegram.org/bot${config.token}/setWebhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const result = await resp.json();
  if (result.ok) {
    console.log('✅ Webhook set successfully!');
    console.log(`   URL: ${config.url}`);
  } else {
    console.error('❌ Failed to set webhook:', result.description);
    process.exit(1);
  }
}

main().catch(console.error);
