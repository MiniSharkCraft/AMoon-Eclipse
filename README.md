<div align="center">

```
 █████╗ ███╗   ███╗ ██████╗  ██████╗ ███╗   ██╗
██╔══██╗████╗ ████║██╔═══██╗██╔═══██╗████╗  ██║
███████║██╔████╔██║██║   ██║██║   ██║██╔██╗ ██║
██╔══██║██║╚██╔╝██║██║   ██║██║   ██║██║╚██╗██║
██║  ██║██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═══╝
         E C L I P S E
```

**End-to-End Encrypted Messenger — Web · Mobile · Desktop**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go)](https://go.dev)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)](https://react.dev)
[![Expo](https://img.shields.io/badge/Expo-51-000020?logo=expo)](https://expo.dev)

</div>

---

## What is AMoon Eclipse?

AMoon Eclipse is a **zero-knowledge, end-to-end encrypted** messaging platform. The server stores only ciphertext it cannot read. Your private key never leaves your device.

- **Web** — React 18 + Vite + Tailwind CSS
- **Mobile** — React Native + Expo (Android & iOS)
- **Desktop** — Wails v2 (Go + React, single binary — no Electron)
- **Backend** — Go + Chi router + MySQL/MariaDB + WebSocket hub

Every message is encrypted client-side with **AES-256-GCM** before transmission. The session key is wrapped per-recipient using **RSA-2048-OAEP**. The server is a blind relay.

---

## Support This Project

If AMoon Eclipse helped you or you want to keep development going:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/G2G11UYLFQ)

---

## Security Architecture

```
┌──────────────────────────────────────────────────┐
│                  SENDER DEVICE                   │
│                                                  │
│  plaintext ──► AES-256-GCM ──► ciphertext        │
│                      ▲                           │
│           ephemeral session key (random)         │
│                      │                           │
│      RSA-OAEP wrap × N recipients                │
│      sessionKeys = { userId: encryptedKey, … }   │
└─────────────────────┬────────────────────────────┘
                      │  { sessionKeys, payload }
                      ▼
┌──────────────────────────────────────────────────┐
│               GO SERVER  (BLIND)                 │
│                                                  │
│  Stores bundle as opaque TEXT in MySQL.          │
│  Forwards via WebSocket hub.                     │
│  Cannot read any message. Zero-knowledge.        │
└─────────────────────┬────────────────────────────┘
                      │  same bundle
                      ▼
┌──────────────────────────────────────────────────┐
│                RECIPIENT DEVICE                  │
│                                                  │
│  sessionKeys[myId] ──► RSA-OAEP unwrap           │
│                              ▼                   │
│             session key ──► AES-256-GCM decrypt  │
│                              ▼                   │
│                        plaintext ✓               │
└──────────────────────────────────────────────────┘
```

### Key Storage per Platform

| Platform | Storage | Backed by |
|----------|----------|-----------|
| Web | IndexedDB (`idb`) | Browser origin |
| Desktop (Wails) | IndexedDB | WebView2 / WebKitGTK |
| Mobile | `expo-secure-store` | Android Keystore / iOS Keychain |

### Server-side Hardening

- **Scanner auto-ban** — detects vulnerability probes (`.env`, `.php`, `wp-admin`, etc.), bans IPs after 8 hits in 60 s for 2 hours, serves a honeypot page
- **Rate limiting** — separate limits for auth, API, and WebSocket
- **Security headers** — CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **Body size cap** — 512 KB max
- **Field-level encryption** — PII (emails) encrypted with AES-256-GCM at rest using a server-side key

---

## Monorepo Structure

```
amoon-eclipse/
├── apps/
│   ├── web/                    # React + Vite + Tailwind
│   ├── mobile/                 # React Native + Expo
│   └── desktop/                # Wails v2 (Go + React)
│
└── packages/
    ├── common/
    │   └── src/
    │       └── crypto-engine.ts  # Shared E2EE — runs on all 3 platforms
    │
    └── server/                 # Go backend
        ├── cmd/server/main.go  # Router, middleware, graceful shutdown
        └── internal/
            ├── auth/           # Register, login, OAuth, TOTP, key management
            ├── messages/       # E2EE message store + WebSocket push
            ├── rooms/          # DM and group rooms
            ├── friends/        # Friend requests
            ├── users/          # Profile, search
            ├── notes/          # Self-destructing notes
            ├── calls/          # WebRTC TURN credentials (Cloudflare)
            ├── blocks/         # User blocking
            ├── moderation/     # Chat bans, harassment tracking
            ├── pending/        # Pending messages (pre-friend)
            ├── ws/             # WebSocket hub (rooms + P2P signaling)
            ├── middleware/     # JWT auth, rate limit, scanner ban, security headers
            ├── crypto/         # AES-GCM field encryption, HMAC tokens
            ├── db/             # MySQL connection + schema
            ├── email/          # SMTP mailer
            └── config/         # Env + .env file loader
```

---

## Features

| Feature | Status |
|---------|--------|
| End-to-end encrypted DM | ✅ |
| End-to-end encrypted group chat | ✅ |
| WebRTC P2P voice/video calls | ✅ |
| Real-time WebSocket delivery | ✅ |
| Friend system | ✅ |
| Pending messages (pre-friend) | ✅ |
| Self-destructing notes | ✅ |
| Google OAuth | ✅ |
| TOTP two-factor authentication | ✅ |
| Passphrase key backup & recovery | ✅ |
| User blocking | ✅ |
| Admin moderation tools | ✅ |
| Web app | ✅ |
| Android / iOS (Expo) | ✅ |
| Desktop — Windows / macOS / Linux (Wails) | ✅ |

---

## Quick Start

### Prerequisites

- Go 1.22+
- Node.js 20+ and pnpm 9+
- MySQL 8+ or MariaDB 10.6+

### 1. Clone & Install

```bash
git clone https://github.com/your-org/amoon-eclipse
cd amoon-eclipse
pnpm install
```

### 2. Database

```sql
CREATE DATABASE amoon CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'amoon'@'%' IDENTIFIED BY 'yourpassword';
GRANT ALL PRIVILEGES ON amoon.* TO 'amoon'@'%';
```

```bash
mysql -u amoon -p amoon < packages/server/internal/db/schema.sql
```

### 3. Backend

```bash
cd packages/server
```

Create a `.env` file:

```env
DB_DSN=amoon:yourpassword@tcp(localhost:3306)/amoon?parseTime=true&charset=utf8mb4
JWT_SECRET=<output of: openssl rand -hex 32>
DB_ENCRYPTION_KEY=<output of: openssl rand -hex 32>
DB_HMAC_KEY=<output of: openssl rand -hex 32>
PORT=8080
BASE_URL=http://localhost:8080
ALLOWED_ORIGINS=http://localhost:5173

# Optional
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
CF_TURN_TOKEN_ID=
CF_TURN_API_TOKEN=
```

Build and run:

```bash
go build -o amoon-server ./cmd/server/
./amoon-server
# → AMoon Eclipse server running on :8080
```

### 4. Web

```bash
cd apps/web
echo "VITE_API_URL=http://localhost:8080" > .env.local
pnpm dev
```

### 5. Mobile

```bash
cd apps/mobile
echo "EXPO_PUBLIC_API_URL=http://YOUR_LOCAL_IP:8080" > .env
npx expo start
```

### 6. Desktop (Wails)

```bash
# Requires Wails CLI: go install github.com/wailsapp/wails/v2/cmd/wails@latest
cd apps/desktop/wails-app
wails dev
```

---

## Environment Variables

| Variable | Required | Description |
|----------|:--------:|-------------|
| `DB_DSN` | ✅ | MySQL DSN |
| `JWT_SECRET` | ✅ | Token signing key |
| `DB_ENCRYPTION_KEY` | ✅ | 64-char hex — AES-256 for PII at rest |
| `DB_HMAC_KEY` | ✅ | 64-char hex — HMAC for email lookup tokens |
| `PORT` | — | HTTP listen port (default: `8080`, or `P_SERVER_PORT`) |
| `BASE_URL` | — | Public URL for OAuth redirect URIs |
| `ALLOWED_ORIGINS` | — | CORS origins, comma-separated (default: `*`) |
| `GOOGLE_CLIENT_ID/SECRET` | — | Google OAuth |
| `CF_TURN_TOKEN_ID/API_TOKEN` | — | Cloudflare TURN for WebRTC |
| `SMTP_*` | — | Email (password reset, verification) |
| `FACEBOOK_APP_ID` | — | Facebook token verification |

> The server reads `.env` from the working directory at startup. Real environment variables always override `.env` values.

---

## Deployment

### Manual (Linux / VPS)

```bash
# Cross-compile for Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -o amoon-server ./cmd/server/

# Upload binary + .env to server
scp amoon-server .env user@yourhost:/opt/amoon/

# Run (use systemd, PM2, or your preferred process manager)
cd /opt/amoon && ./amoon-server
```

### Pterodactyl Panel

Works with the **Generic Go** egg out of the box:

- Set `EXECUTABLE` → `amoon-server`
- Startup command: `./${EXECUTABLE}`
- Drop a `.env` file into the container — the server loads it automatically
- `PORT` falls back to `P_SERVER_PORT` (Pterodactyl's primary allocation port) if not explicitly set

---

## Contributing

Pull requests are welcome. For major changes please open an issue first to discuss.

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Commit your changes
4. Open a Pull Request

> **Important:** Do not break the E2EE bundle format. The `packages/common/src/crypto-engine.ts` format must remain compatible across Web, Mobile, and Desktop. Any change to `encryptMessage` / `decryptMessage` must be reflected on all three platforms.

---

## License

Copyright (C) 2026 AMoon Team & CongMC Dev Team

This project is licensed under the **GNU Affero General Public License v3.0**.
See [LICENSE](LICENSE) for the full text.

In short: you are free to use, modify, and distribute this software, but any modified version you deploy as a network service **must also be released as open source** under the same license.

---

<div align="center">

Built with ❤️ by **AMoon Team & CongMC Dev Team**

*The server is blind. The key is yours.*

</div>
