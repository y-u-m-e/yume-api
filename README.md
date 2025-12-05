# Yume API

A Cloudflare Worker that serves as the backend API for Yume's Tools - a suite of utilities for OSRS clan management.

## 🌐 Live URLs

| Environment | URL |
|-------------|-----|
| Production | https://api.itai.gg |
| Staging | https://api-staging.itai.gg |

---

## 📋 Table of Contents

- [Features](#-features)
- [API Endpoints](#-api-endpoints)
- [Database Schema](#-database-schema)
- [Authentication](#-authentication)
- [CDN Proxy](#-cdn-proxy)
- [DevOps](#-devops)
- [Local Development](#-local-development)
- [Configuration](#-configuration)

---

## ✨ Features

- **Discord Webhook Relay** - Forward formatted messages to Discord
- **Attendance Database** - CRUD operations for event attendance tracking
- **Discord OAuth2** - Secure authentication with user whitelist
- **CDN Proxy** - Serve widget scripts with instant cache invalidation
- **Health Monitoring** - Built-in health check endpoint
- **Leaderboard API** - Get top attendees with date filtering

---

## 🔌 API Endpoints

### Health Check

```
GET /health
```

Returns API health status including database connectivity.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-05T23:00:40.344Z",
  "environment": "production",
  "version": "1.0.0",
  "checks": {
    "database": {
      "status": "healthy",
      "latency_ms": 12
    }
  },
  "response_time_ms": 15
}
```

---

### Discord Webhook

```
POST /
```

Relays a Discord embed message to the configured webhook.

**Request Body:**
```json
{
  "username": "Events Logger",
  "avatar_url": "https://example.com/avatar.png",
  "embeds": [...],
  "content": "Message content"
}
```

---

### Authentication

#### Login
```
GET /auth/login
```
Redirects to Discord OAuth2 authorization.

#### Callback
```
GET /auth/callback?code=...
```
Handles OAuth2 callback, sets auth cookie.

#### Get Current User
```
GET /auth/me
```
Returns authenticated user info.

**Response:**
```json
{
  "authenticated": true,
  "authorized": true,
  "user": {
    "id": "166201366228762624",
    "username": "yume",
    "avatar": "abc123"
  }
}
```

#### Logout
```
GET /auth/logout
```
Clears auth cookie and redirects to home.

---

### Attendance Records

#### List Records
```
GET /attendance/records?name=&event=&start=&end=&page=1&limit=20
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Filter by player name (partial match) |
| `event` | string | Filter by event name (partial match) |
| `start` | date | Start date (YYYY-MM-DD) |
| `end` | date | End date (YYYY-MM-DD) |
| `page` | number | Page number (default: 1) |
| `limit` | number | Results per page (default: 20, max: 5000) |

**Response:**
```json
{
  "results": [
    { "id": 1, "name": "y u m e", "event": "Wildy Wednesday", "date": "2025-12-01" }
  ],
  "total": 150,
  "page": 1,
  "limit": 20
}
```

#### Create Record
```
POST /attendance/records
Content-Type: application/json

{
  "name": "y u m e",
  "event": "Wildy Wednesday",
  "date": "2025-12-05"
}
```

#### Update Record
```
PUT /attendance/records/:id
Content-Type: application/json

{
  "name": "y u m e",
  "event": "Wildy Wednesday",
  "date": "2025-12-05"
}
```

#### Delete Record
```
DELETE /attendance/records/:id
```

---

### Leaderboard

```
GET /attendance?top=10&start=2025-01-01&end=2025-12-31
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `top` | number | Number of top attendees (default: 10) |
| `start` | date | Start date filter |
| `end` | date | End date filter |

**Response:**
```json
{
  "results": [
    { "name": "y u m e", "count": 45 },
    { "name": "Player2", "count": 38 }
  ]
}
```

---

### CDN Proxy

Serves widget JavaScript files from GitHub with instant cache invalidation.

```
GET /cdn/nav-bar.js
GET /cdn/mention-widget.js
GET /cdn/event-parser-widget.js
GET /cdn/cruddy-panel.js
```

Files are fetched from jsDelivr using Git SHAs configured in environment variables, bypassing jsDelivr's cache.

---

## 🗄️ Database Schema

Using Cloudflare D1 (SQLite).

```sql
CREATE TABLE attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,      -- Player name
  event TEXT NOT NULL,     -- Event name
  date TEXT NOT NULL       -- Date (YYYY-MM-DD format)
);

CREATE INDEX idx_attendance_name ON attendance(name);
CREATE INDEX idx_attendance_event ON attendance(event);
CREATE INDEX idx_attendance_date ON attendance(date);
```

### Database Operations

```bash
# Export database
npx wrangler d1 export event_tracking --output=backup.sql

# Import/restore database
npx wrangler d1 execute event_tracking --file=backup.sql

# Run a query
npx wrangler d1 execute event_tracking --command="SELECT COUNT(*) FROM attendance"
```

---

## 🔐 Authentication

Authentication uses Discord OAuth2 with a whitelist of allowed user IDs.

### Flow
1. User clicks "Login with Discord"
2. Redirected to Discord OAuth2
3. On callback, user ID is checked against `ALLOWED_USER_IDS`
4. If allowed, a signed cookie (`yume_auth`) is set
5. Cookie is valid for 7 days

### Adding Authorized Users

Edit `wrangler.jsonc`:
```json
{
  "vars": {
    "ALLOWED_USER_IDS": "USER_ID_1, USER_ID_2, USER_ID_3"
  }
}
```

Then redeploy: `npx wrangler deploy`

---

## 🚀 DevOps

### Environments

| Environment | Branch | Domain | Purpose |
|-------------|--------|--------|---------|
| Production | `main` | api.itai.gg | Live site |
| Staging | `staging` | api-staging.itai.gg | Testing |

### CI/CD Pipeline

GitHub Actions automatically:
1. **On push to `main`**: Run tests → Deploy to production → Health check
2. **On push to `staging`**: Run tests → Deploy to staging → Health check
3. **On PR to `main`**: Run tests → Deploy to staging for review

### Deployment Commands

```bash
# Deploy to production
npx wrangler deploy

# Deploy to staging
npx wrangler deploy --env staging

# Using the helper script (Windows)
.\scripts\deploy.ps1 production
.\scripts\deploy.ps1 staging
```

### Automated Backups

Database is automatically backed up daily at 2 AM UTC via GitHub Actions.

```bash
# Manual backup
.\scripts\backup.ps1

# Or using wrangler directly
npx wrangler d1 export event_tracking --output=backup.sql
```

### Health Monitoring

Health checks run every 5 minutes via GitHub Actions.

Manual check:
```bash
curl https://api.itai.gg/health
```

---

## 💻 Local Development

### Prerequisites
- Node.js 20+
- npm
- Wrangler CLI (`npm install -g wrangler`)
- Cloudflare account

### Setup

```bash
# Clone the repo
git clone https://github.com/y-u-m-e/yume-api.git
cd yume-api

# Install dependencies
npm install

# Login to Cloudflare
npx wrangler login

# Start local dev server
npx wrangler dev
```

### Running Tests

```bash
npm test
```

---

## ⚙️ Configuration

### Environment Variables (`wrangler.jsonc`)

| Variable | Description |
|----------|-------------|
| `ENVIRONMENT` | `production` or `staging` |
| `SHA_CRUDDY_PANEL` | Git SHA for cruddy-panel.js |
| `SHA_EVENT_PARSER` | Git SHA for event-parser-widget.js |
| `SHA_MENTION_WIDGET` | Git SHA for mention-widget.js |
| `SHA_NAV_BAR` | Git SHA for nav-bar.js |
| `DISCORD_CLIENT_ID` | Discord OAuth2 application ID |
| `DISCORD_REDIRECT_URI` | OAuth2 callback URL |
| `ALLOWED_USER_IDS` | Comma-separated Discord user IDs |

### Secrets

Set via Wrangler CLI:

```bash
# Discord OAuth2 client secret
npx wrangler secret put DISCORD_CLIENT_SECRET

# Discord webhook URL (for event logging)
npx wrangler secret put DISCORD_WEBHOOK_URL
```

### GitHub Actions Secrets

Required in GitHub repo settings:

| Secret | Description |
|--------|-------------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token with Workers access |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare account ID |

---

## 📁 Project Structure

```
yume-api/
├── .github/
│   └── workflows/
│       ├── deploy.yml        # CI/CD pipeline
│       ├── backup.yml        # Automated backups
│       └── health-check.yml  # Health monitoring
├── scripts/
│   ├── deploy.ps1            # Deployment helper
│   └── backup.ps1            # Backup helper
├── src/
│   └── index.js              # Main worker code
├── test/
│   └── index.spec.js         # Tests
├── schema.sql                # Database schema
├── wrangler.jsonc            # Wrangler configuration
└── package.json
```

---

## 🔗 Related Projects

- [yume-tools](https://github.com/y-u-m-e/yume-tools) - Frontend widgets
- [Carrd Site](https://yumes-tools.itai.gg) - Live website

---

## 📝 License

MIT

