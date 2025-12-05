# Environments

The API supports multiple deployment environments.

## Production

| Property | Value |
|----------|-------|
| URL | `https://api.itai.gg` |
| Branch | `main` |
| Database | `yume-attendance` |

Production receives all traffic from the live Carrd site.

## Staging

| Property | Value |
|----------|-------|
| URL | `https://api-staging.itai.gg` |
| Branch | `staging` |
| Database | `yume-attendance` (shared) |

Staging is for testing before production deployment.

### DNS Setup

Add a CNAME record in Cloudflare DNS:

```
Type: CNAME
Name: api-staging
Target: yume-api-staging.<your-subdomain>.workers.dev
Proxy status: Proxied
```

## Environment Variables

Both environments share the same config with one difference:

```json
{
  "vars": {
    "ENVIRONMENT": "production"  // or "staging"
  }
}
```

The `ENVIRONMENT` variable is returned in the `/health` endpoint.

## Deployment Flow

```
Feature branch
      ↓
PR to staging branch
      ↓
Auto-deploy to staging
      ↓
Test on staging URL
      ↓
Merge to main
      ↓
Auto-deploy to production
```

## Testing on Staging

Point widgets to staging for testing:

```html
<script>
  CruddyPanel.mount('#root', {
    apiBase: 'https://api-staging.itai.gg'
  });
</script>
```

## Rollback

If production breaks:

```bash
# Revert to previous commit
git revert HEAD
git push origin main

# Or deploy specific version
npx wrangler deploy --env production
```

