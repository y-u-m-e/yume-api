# CI/CD Pipeline

Automated deployment using GitHub Actions.

## Workflow Overview

```
Push to main/staging
        ↓
GitHub Actions triggered
        ↓
Run tests (if any)
        ↓
Deploy to Cloudflare
        ↓
Health check
        ↓
Done ✓
```

## Workflow File

`.github/workflows/deploy.yml`:

```yaml
name: Deploy

on:
  push:
    branches: [main, staging]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          
      - name: Install dependencies
        run: npm ci
        
      - name: Deploy to Cloudflare
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          command: deploy --env ${{ github.ref_name == 'main' && 'production' || 'staging' }}
          
      - name: Health Check
        run: |
          sleep 10
          curl -f https://api.itai.gg/health
```

## Required Secrets

Add these in GitHub repo settings → Secrets:

| Secret | Description |
|--------|-------------|
| `CLOUDFLARE_API_TOKEN` | Workers deploy token |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare account ID |

### Creating API Token

1. Go to [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Create Token → Use template "Edit Cloudflare Workers"
3. Set permissions:
   - Account: Workers Scripts - Edit
   - Zone: Workers Routes - Edit
4. Copy token to GitHub secrets

## Manual Deploy

If needed, deploy manually:

```powershell
# Production
npx wrangler deploy

# Staging
npx wrangler deploy --env staging
```

## Monitoring Deploys

- GitHub Actions tab shows all deployments
- Each commit shows deploy status
- Failed deploys don't affect production

