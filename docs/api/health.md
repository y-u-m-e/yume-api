# Health Check

Monitor the API's operational status.

## Endpoint

```http
GET /health
```

## Response

```json
{
  "status": "healthy",
  "environment": "production",
  "timestamp": "2025-12-05T15:30:00.000Z",
  "database": "connected"
}
```

## Fields

| Field | Description |
|-------|-------------|
| `status` | `healthy` or `unhealthy` |
| `environment` | `production` or `staging` |
| `timestamp` | ISO 8601 timestamp |
| `database` | `connected` or `error: message` |

## Use Cases

### Manual Check

```bash
curl https://api.itai.gg/health
```

### Uptime Monitoring

Add to external monitoring services like UptimeRobot or Pingdom.

### Deployment Verification

```bash
curl -s https://api.itai.gg/health | jq '.status'
```

