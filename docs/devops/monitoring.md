# Monitoring

Keep track of API health and performance.

## Health Endpoint

The `/health` endpoint provides real-time status:

```bash
curl https://api.itai.gg/health
```

```json
{
  "status": "healthy",
  "environment": "production",
  "timestamp": "2025-12-05T15:30:00.000Z",
  "database": "connected"
}
```

## Automated Health Checks

### GitHub Actions (Every 5 Minutes)

`.github/workflows/health-check.yml`:

```yaml
name: Health Check

on:
  schedule:
    - cron: '*/5 * * * *'

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - name: Check Production
        run: |
          response=$(curl -sf https://api.itai.gg/health)
          status=$(echo $response | jq -r '.status')
          if [ "$status" != "healthy" ]; then
            echo "Production unhealthy!"
            exit 1
          fi
```

### UptimeRobot (Recommended)

Free external monitoring:

1. Sign up at [uptimerobot.com](https://uptimerobot.com)
2. Add new monitor:
   - Type: HTTP(s)
   - URL: `https://api.itai.gg/health`
   - Interval: 5 minutes
3. Set up alerts (email, Discord webhook, etc.)

## Cloudflare Analytics

View worker metrics in Cloudflare dashboard:

1. Go to Workers & Pages
2. Select `yume-api`
3. View Analytics tab

Metrics available:
- Requests per second
- Error rate
- CPU time
- Duration percentiles

## Log Monitoring

View real-time logs:

```bash
npx wrangler tail
```

Filter by status:

```bash
npx wrangler tail --format=json | jq 'select(.outcome == "exception")'
```

## Alerting

### Discord Webhook Alert

Add to health check workflow:

```yaml
- name: Alert Discord
  if: failure()
  run: |
    curl -X POST "${{ secrets.DISCORD_WEBHOOK }}" \
      -H "Content-Type: application/json" \
      -d '{"content": "⚠️ API Health Check Failed!"}'
```

## Incident Response

1. Check `/health` endpoint
2. Review Cloudflare analytics
3. Check `wrangler tail` for errors
4. Redeploy if necessary
5. Document incident

