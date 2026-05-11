# TG Image Bot — Cloudflare R2

> 把 Telegram Bot 变成你的个人图床 — 发送图片，自动上传到 Cloudflare R2，秒回直链。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Wrangler](https://img.shields.io/badge/Wrangler-4.x-orange)](https://developers.cloudflare.com/workers/wrangler/)
[![Platform](https://img.shields.io/badge/Platform-Cloudflare%20Workers-blue)](https://workers.cloudflare.com/)

---

## 功能一览

| 功能 | 说明 |
|------|------|
| 📤 **一键上传** | 发送图片给 Bot，自动上传至 R2 并返回直链 |
| 📋 **三格式输出** | 每条消息单独输出 **直链** / **Markdown** / **HTML**，长按即可复制 |
| 🗑 **回复删除** | 回复 Bot 的任意一条消息并发送 `/delete`，图片即删 |
| 🌐 **Web 管理面板** | 浏览器访问管理页面，搜索、预览、批量管理图片 |
| 🔐 **双因子登录** | 支持 **Telegram 快捷登录** 和 **PassKey（生物识别/硬件密钥）** |
| 🚦 **速率限制** | 防止刷图，安全有保障 |
| 🖥 **全平台部署** | 基于 Cloudflare Workers，无需维护服务器 |

---

## 快速开始

### 前置准备

- [Cloudflare](https://dash.cloudflare.com) 账号（免费版即可）
- [Telegram](https://t.me) 账号
- GitHub 账号（用于部署）

### 1. 创建 Telegram Bot

在 Telegram 中搜索 [@BotFather](https://t.me/BotFather)，发送 `/newbot` 按提示创建。

创建后会收到 **Bot Token**（格式如 `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`），**保存好**。

### 2. 准备 R2 存储

<details>
<summary><b>已有 R2 Bucket？直接复用</b></summary>

- 打开 Cloudflare Dashboard → **R2**，找到你的 Bucket
- 确认已绑定自定义域名（否则直链无法访问）
- 记下 **Bucket 名称** 和 **自定义域名**
- Bot 上传的文件放在 `uploads/` 路径，不会影响现有文件
</details>

<details>
<summary><b>还没有 R2？新建一个</b></summary>

1. Cloudflare Dashboard → **R2** → **创建 Bucket**
2. 名称取 `tg-images` 或任意你喜欢的名字
3. 进入 Bucket → **设置** → **公开访问** → **绑定自定义域名**

> R2 默认不公开，必须绑定自定义域名才能生成可访问的直链。
</details>

### 3. 创建 KV 命名空间

Cloudflare Dashboard → **Workers 和 Pages** → **KV** → **创建命名空间**

- 名称填 `IMG_KV`
- 创建后复制 **命名空间 ID**

### 4. 配置并部署

编辑 `wrangler.toml`，填入你的资源信息：

```toml
[[r2_buckets]]
binding = "IMG_BUCKET"
bucket_name = "你的R2-Bucket名称"

[[kv_namespaces]]
binding = "IMG_KV"
id = "你的KV命名空间ID"
preview_id = "你的KV命名空间ID"

[vars]
ALLOWED_USERS    = "你的TG用户名"     # 允许使用的用户，逗号分隔，留空=所有人可用
ADMIN_USERNAMES  = "你的TG用户名"     # 管理员用户名，可删任意图片
PUBLIC_URL       = "https://你的R2域名"
TELEGRAM_BOT_USERNAME = "你的Bot用户名"  # 不含 @，如 myimagebot
```

推送到 GitHub，在 Cloudflare Dashboard 中连接到 Git 仓库，自动部署。

### 5. 设置加密变量

部署后，进入 Worker 详情页 → **设置** → **变量**，添加加密变量：

| 变量名 | 说明 |
|--------|------|
| `BOT_TOKEN` | Telegram Bot Token（**必填**） |
| `WEBHOOK_SECRET` | 任意随机字符串，用于验证 Webhook（**强烈建议**） |

### 6. 设置 Webhook

浏览器访问以下链接（替换实际值）：

```
https://api.telegram.org/bot<BOT_TOKEN>/setWebhook?url=https://<你的Worker域名>/webhook&secret_token=<WEBHOOK_SECRET>
```

返回 `{"ok": true}` 即成功。

### 7. 配置 Bot 域名（可选，用于管理面板 Telegram 登录）

在 [@BotFather](https://t.me/BotFather) 执行：
```
/setdomain → 选择你的 Bot → 输入你的 Worker 域名
```

---

## 管理面板

部署成功后，浏览器访问 `https://<你的Worker域名>/admin`：

- **PassKey 登录** — 最安全，支持指纹/面部识别/Windows Hello
- **Telegram 登录** — 最方便，一键授权
- **搜索过滤** — 按文件名搜索图片
- **多格式复制** — 每个图片卡片支持 **URL** / **Markdown** / **HTML** / **BBCode** 一键复制
- **图片预览** — 点击缩略图全屏预览，支持键盘 ← → 切换和 ESC 关闭
- **统计概览** — 顶部显示图片总数和总大小

> 如果想把管理面板放在独立子域名（如 `admin.example.com`），在 Cloudflare Worker 触发器设置中添加自定义域名即可。

---

## 使用指南

### 上传图片

```
用户 → [发送图片] → Bot
Bot  → [回复消息 1] ✅ 上传成功 (245.6 KB)
                     https://r2.example.com/uploads/abc123.jpg
Bot  → [回复消息 2] ![](https://r2.example.com/uploads/abc123.jpg)
Bot  → [回复消息 3] <img src="..." alt="...">
```

三条独立消息，每条只包含你需要的内容，长按即可复制。

### 删除图片

回复 Bot 发来的任意一条消息，输入：
```
/delete
```

### 管理面板删除

在管理面板点击图片卡片的 🗑 按钮即可删除。

---

## 项目结构

```
├── src/
│   ├── index.js        # Worker 入口 — 路由、上传、删除、Webhook
│   ├── admin.js        # 管理面板 — 登录验证、图片管理、HTML 渲染
│   ├── utils.js        # 工具函数 — ID生成、MIME校验、限流、安全头
│   └── webauthn.js     # WebAuthn/PassKey — 注册、认证、凭据管理
├── scripts/
│   └── set-webhook.js  # 设置 Telegram Webhook 的脚本
├── wrangler.toml       # Cloudflare Workers 配置
├── package.json
└── README.md
```

---

## 安全设计

| 措施 | 说明 |
|------|------|
| **Webhook 验证** | `X-Telegram-Bot-Api-Secret-Token` 校验，仅 Telegram 能调用 Worker |
| **速率限制** | 基于 Cloudflare KV 的滑动窗口限流 |
| **文件校验** | 双重 MIME 类型检查（消息阶段 + 下载阶段） |
| **HMAC 会话** | Web Crypto API 生成 HMAC 签名令牌 |
| **CSP 头** | Content-Security-Policy 严格限制资源加载 |
| **WebAuthn** | 公钥认证，支持硬件密钥和生物识别 |
| **Cookie 安全** | HttpOnly + SameSite=Strict + 条件 Secure 标记 |

---

## 开发

```bash
# 安装依赖
npm install

# 本地开发
npm run dev

# 部署
npm run deploy

# 查看日志
npm run tail

# 设置 webhook
BOT_TOKEN=xxx WEBHOOK_URL=https://xxx.workers.dev/webhook node scripts/set-webhook.js
```

---

## 许可证

[MIT](LICENSE)
