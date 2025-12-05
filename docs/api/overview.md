# API Overview

The Yume API is a Cloudflare Worker that provides backend services for Yume Tools.

## Base URLs

| Environment | URL |
|-------------|-----|
| Production | `https://api.itai.gg` |
| Staging | `https://api-staging.itai.gg` |

## Endpoints Summary

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | [Health check](health.md) |
| GET | `/auth/login` | [Start Discord OAuth](authentication.md) |
| GET | `/auth/callback` | [OAuth callback](authentication.md) |
| GET | `/auth/me` | [Get current user](authentication.md) |
| GET | `/auth/logout` | [Logout](authentication.md) |
| GET | `/attendance` | [Leaderboard](leaderboard.md) |
| GET | `/attendance/records` | [List records](attendance.md) |
| POST | `/attendance/records` | [Create record](attendance.md) |
| PUT | `/attendance/records/:id` | [Update record](attendance.md) |
| DELETE | `/attendance/records/:id` | [Delete record](attendance.md) |
| GET | `/cdn/:file` | [CDN proxy](cdn.md) |
| POST | `/` | Discord webhook relay |

## CORS

All endpoints support CORS with:
- Dynamic `Access-Control-Allow-Origin` (mirrors request origin)
- Credentials allowed
- Methods: GET, POST, PUT, DELETE, OPTIONS

## Response Format

All API responses are JSON:

```json
{
  "results": [...],
  "total": 100,
  "page": 1,
  "limit": 20
}
```

## Error Responses

```json
{
  "error": "Error message here"
}
```

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 400 | Bad request (invalid input) |
| 401 | Unauthorized |
| 404 | Not found |
| 500 | Server error |

