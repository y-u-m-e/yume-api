# Local Development Setup

Set up your local environment for Yume Tools development.

## Prerequisites

- [Node.js 18+](https://nodejs.org/)
- [Git](https://git-scm.com/)
- [Cloudflare account](https://cloudflare.com/)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

## Clone Repositories

```bash
# API backend
git clone https://github.com/y-u-m-e/yume-api.git
cd yume-api
npm install

# Frontend widgets (separate repo)
git clone https://github.com/y-u-m-e/yume-tools.git
```

## Wrangler Setup

### Login to Cloudflare

```bash
npx wrangler login
```

### Verify Configuration

```bash
npx wrangler whoami
```

## Local Development Server

```bash
# Start local worker with D1 binding
npx wrangler dev
```

This runs the worker locally at `http://localhost:8787`.

## Environment Variables

For local development, create a `.dev.vars` file:

```
DISCORD_CLIENT_SECRET=your_secret_here
```

This file is gitignored and not committed.

## Testing Locally

### Test API Endpoints

```bash
# Health check
curl http://localhost:8787/health

# Get records
curl http://localhost:8787/attendance/records
```

### Test with Widgets

Modify widget options to point to local:

```javascript
CruddyPanel.mount('#root', {
  apiBase: 'http://localhost:8787'
});
```

## Database Setup

### Create D1 Database

```bash
npx wrangler d1 create yume-attendance
```

### Initialize Schema

```bash
npx wrangler d1 execute yume-attendance --file=schema.sql
```

### Seed Test Data

```bash
npx wrangler d1 execute yume-attendance --command="INSERT INTO attendance (name, event, date) VALUES ('TestUser', 'TestEvent', '2025-12-05')"
```

## Common Issues

### "Database not found"

Ensure `database_id` in `wrangler.jsonc` matches your D1 database.

### "CORS errors"

Local dev server handles CORS, but ensure your frontend runs on the expected origin.

### "Auth not working"

OAuth2 requires valid redirect URIs. For local testing, add `http://localhost:8787/auth/callback` to Discord app settings.

