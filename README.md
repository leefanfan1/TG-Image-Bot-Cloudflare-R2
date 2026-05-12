<p align="center">
  <br>
  <b><span style="font-size: 1.5em">TG Image Bot — Cloudflare R2</span></b><br>
  <span style="font-size: 1.1em">把 Telegram Bot 变成你的个人图床</span><br>
  发送图片给 Bot，自动上传到 Cloudflare R2，秒回直链
</p>

<p align="center">
  <a href="https://deploy.workers.cloudflare.com"><img src="https://deploy.workers.cloudflare.com/button" alt="Deploy to Cloudflare"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Runtime-Cloudflare_Workers-f38020?logo=cloudflare&logoColor=white" alt="Runtime">
  <img src="https://img.shields.io/badge/Storage-Cloudflare_R2-ef7b2b?logo=cloudflare&logoColor=white" alt="Storage">
  <img src="https://img.shields.io/badge/Language-JavaScript-f7df1e?logo=javascript&logoColor=black" alt="Language">
  <img src="https://img.shields.io/badge/Auth-Telegram_%2B_WebAuthn-26a5e4?logo=telegram&logoColor=white" alt="Auth">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/badge/Wrangler-4.x-orange" alt="Wrangler">
</p>

---

## 📋 功能一览

| | 功能 | 说明 |
|--|------|------|
| 📤 | **Bot 上传** | 发送图片给 Bot，自动上传至 R2 并返回直链 |
| 📋 | **三格式输出** | 每条消息同时输出 **直链** / **Markdown** / **HTML** |
| 🗑 | **回复删除** | 回复 Bot 任意消息并发送 `/delete`，图片即删 |
| 🌐 | **Web 管理面板** | 浏览器管理图片：搜索、预览、删除、上传 |
| 🖥 | **页面上传** | 管理面板内直接拖拽或选择图片上传 |
| 📦 | **批量导出** | 一键导出所有图片 URL 列表 |
| 🔐 | **Telegram 登录** | 抛弃传统密码，直接使用 Telegram 授权登录 |
| 🔑 | **PassKey 认证** | 支持指纹 / 面部识别 / 硬件密钥 |
| 👤 | **账号管理** | 添加 / 删除 PassKey，删除账号 |
| 🚦 | **速率限制** | 防止恶意刷图 |

---

## 🚀 快速开始

### 📋 前置准备

- ☁️ [Cloudflare](https://dash.cloudflare.com) 账号（免费版即可）
- ✈️ [Telegram](https://t.me) 账号

---

### 1. 创建 Telegram Bot

在 Telegram 搜索 [@BotFather](https://t.me/BotFather)，发送 `/newbot` 按提示创建。

创建后会收到 **Bot Token**，格式如：

```
123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
```

> 💡 保存好 Token，后续部署需要用到。

---

### 2. 准备 R2 Bucket

确保你有一个可用的 R2 Bucket：

**新建 R2 Bucket**

Cloudflare Dashboard → **R2** → **创建 Bucket**

- 名称随意（如 `tg-images`）
- 进入 Bucket → **设置** → **公开访问** → **绑定自定义域名**

**已有 R2 Bucket**

如果你是迁移或复用已有的图床，直接使用现有 Bucket 名称即可。确保：

- Bucket 已绑定公开自定义域名（否则直链不可访问）
- 记下你的 **Bucket 名称** 和 **公开域名**，后续配置需要

> ⚠️ R2 默认不公开，必须绑定自定义域名才能生成可访问的直链。

---

### 3. 创建 KV 命名空间

Cloudflare Dashboard → **Workers 和 Pages** → **KV** → **创建命名空间**

- 名称填 `IMG_KV`
- 创建后复制 **命名空间 ID**

---

### 4. 导入代码（私有仓库）

> ⚠️ 本项目涉及敏感配置，**不要直接 Fork 或 Clone 后公开推送**。

| 步骤 | 操作 |
|------|------|
| ① | 打开 [GitHub Import](https://github.com/new/import)，在 **Your old repository's clone URL** 填入本仓库地址 |
| ② | 导入后**立即将仓库设为 Private**：仓库 → **Settings** → **Danger Zone** → **Change visibility** → **Make private** |
| ③ | 在私有仓库中编辑 `wrangler.toml`，填入资源信息 |

**`wrangler.toml` 配置参考：**

```toml
# ═══════════════════════════════════════════
# R2 — 图片存储
# ═══════════════════════════════════════════
[[r2_buckets]]
binding = "IMG_BUCKET"
bucket_name = "你的R2-Bucket名称"

# ═══════════════════════════════════════════
# KV — 元数据存储
# ═══════════════════════════════════════════
[[kv_namespaces]]
binding = "IMG_KV"
id = "你的KV命名空间ID"
preview_id = "你的KV命名空间ID"

# ═══════════════════════════════════════════
# 环境变量
# ═══════════════════════════════════════════
[vars]
ALLOWED_USERS         = "你的TG用户名"      # 逗号分隔，留空=所有人可用
ADMIN_USERNAMES       = "你的TG用户名"      # 管理面板管理员，逗号分隔
PUBLIC_URL            = "https://你的R2域名" # R2 绑定的公开域名，不要尾部斜杠
TELEGRAM_BOT_USERNAME = "你的Bot用户名"     # 不含 @，如 myimagebot
ADMIN_URL             = ""                 # 仅域名不同时需配置，留空自动使用 Worker 域名
```

---

### 5. 部署

**方式一（推荐）：Cloudflare Workers Git 集成**

Cloudflare Dashboard → **Workers & Pages** → **创建** → 选择 **Import from Git** → 连接你的私有仓库 → 保存后自动部署。

<details>
<summary><b>方式二：本地部署（适合开发调试）</b></summary>

```bash
# 克隆你自己的私有仓库到本地
git clone <你的私有仓库>
cd tuchuang
npm install
npm run deploy
```
</details>

部署完成后会输出 **Worker 域名**，如 `tg-image-r2.xxx.workers.dev`。

---

### 6. 设置加密变量

Cloudflare Dashboard → 进入 Worker → **设置** → **变量** → 添加加密变量：

| 变量名 | 说明 |
|--------|------|
| `BOT_TOKEN` | Telegram Bot Token（**必填**） |
| `WEBHOOK_SECRET` | 任意随机字符串，用于验证 Webhook（强烈建议） |
| `ADMIN_URL` | Worker 域名。仅 Bot 和 R2 域名不同时需配置。不设置时 Bot 登录链接会用 PUBLIC_URL |

---

### 7. 设置 Webhook

浏览器访问以下链接（替换为实际值）：

```
https://api.telegram.org/bot<BOT_TOKEN>/setWebhook?url=https://<Worker域名>/webhook&secret_token=<WEBHOOK_SECRET>
```

返回 `{"ok": true}` 即成功。

---

### 8. 完成 🎉

浏览器访问 `https://<Worker域名>/admin` 进入管理面板。

---

## 🖥 管理面板

### 🔐 登录流程

**配置了 Telegram（`TELEGRAM_BOT_USERNAME` 已设置）：**

```
Telegram 登录 → 注册 PassKey → 以后可任选其一
```

1. 页面显示 **Telegram 登录** 按钮
2. 必须先通过 Telegram 登录（验证 `ADMIN_USERNAMES` 中的白名单）
3. 登录后进入管理面板，可通过顶栏 **添加 PassKey** 注册生物识别 / 硬件密钥
4. 以后再次登录，可以选择 **Telegram 登录** 或 **PassKey 登录**

> 💡 这样设计的原因是：首次注册 PassKey 需要先确认管理员身份，而 Telegram 登录是唯一验证你是管理员的途径。

**未配置 Telegram（`TELEGRAM_BOT_USERNAME` 未设置）：**

```
无法登录管理面板
```

管理面板需要 `TELEGRAM_BOT_USERNAME` 配置才能使用。请设置该环境变量后重新部署。

---

### 登录方式

| 方式 | 说明 |
|------|------|
| **Telegram 登录** | 点击按钮，优先唤醒 Telegram App 授权；未安装 App 时 2 秒后自动回退网页 OAuth |
| **PassKey 登录** | 首次需通过以上方式认证后注册，后续可用指纹 / 面部识别 / 硬件密钥 |

---

### 👤 账号管理

| 功能 | 说明 |
|------|------|
| **添加 PassKey** | 登录后点击顶栏 **添加 PassKey** 注册 |
| **查看 / 删除 PassKey** | 顶栏 **设置** → PassKey 管理，列表显示已注册的凭证，可逐个删除 |
| **删除账号** | 顶栏 **设置** → 危险操作 → 清除所有 PassKey 凭证和登录会话 |
| **删除账号后** | 回到初始状态，重新走完整登录流程 |

---

### 🖼 图片管理

| 功能 | 说明 |
|------|------|
| 搜索 / 排序 | 顶部工具栏按文件名搜索，按时间排序 |
| 预览 | 点击缩略图全屏预览，键盘 ← → 切换，ESC 关闭 |
| 单张删除 | 卡片右下角删除按钮 |
| 批量删除 | 勾选多张图片，点击 **删除选中** |
| 页面上传 | 顶栏 **上传** 按钮，支持拖拽或选择图片文件 |
| 导出 URL | 顶栏 **导出** 按钮，自动下载所有图片 URL 列表 |

---

## 📖 使用指南

### 📤 上传图片

向 Bot 发送图片（支持 JPEG / PNG / GIF / WebP / BMP / TIFF / AVIF）：

```
用户 → [发送图片] → Bot

Bot → 消息 1  ✅ 上传成功 (245.6 KB)
               https://img.example.com/uploads/abc123.jpg

Bot → 消息 2  ![](https://img.example.com/uploads/abc123.jpg)

Bot → 消息 3  <img src="https://img.example.com/uploads/abc123.jpg" alt="">
```

> 💡 **群聊**：在群组中发送图片时，必须在图片描述（caption）中 `@Bot用户名`，Bot 才会处理。不加 @ 的图片会被忽略，防止群内无关图片被上传。

### 🗑 删除图片

回复 Bot 发来的任意一条消息，输入 `/delete`（仅上传者或管理员可删）。

### 🔑 登录管理面板

打开管理面板，点击 **Telegram 登录** 按钮即可。

---

## 📁 项目结构

```
src/
├── index.js        # Worker 入口 — 路由、上传、删除、Webhook
├── admin.js        # 管理面板 — 登录、图片管理、HTML 渲染
├── utils.js        # 工具函数 — ID 生成、MIME 校验、限流、安全头
└── webauthn.js     # WebAuthn / PassKey — 注册、认证、凭据管理

scripts/
└── set-webhook.js  # Webhook 设置脚本

wrangler.toml       # Workers 配置
package.json        # 依赖管理
```

---

## 🛡 安全设计

| 措施 | 说明 |
|------|------|
| **Webhook 验证** | `X-Telegram-Bot-Api-Secret-Token` 校验 |
| **速率限制** | KV 固定窗口限流 |
| **文件校验** | 双重 MIME 类型检查 |
| **HMAC 签名** | Telegram OAuth 数据 HMAC-SHA256 防篡改 |
| **CSP** | Content-Security-Policy 限制资源加载 |
| **WebAuthn** | 公钥认证，防钓鱼 |
| **PassKey 注册保护** | 配置 Telegram 后，首次 PassKey 需已认证才能注册，防止未授权绑定 |
| **Cookie** | HttpOnly + SameSite=Strict + Secure |

---

## 🛠 开发

```bash
npm run dev      # 本地开发
npm run deploy   # 部署
npm run tail     # 查看日志
```

---

## 📄 许可证

[MIT](LICENSE)

---

<p align="center">
  <sub>Built with ❤️ using Cloudflare Workers • R2 • Telegram Bot API • WebAuthn</sub>
</p>
