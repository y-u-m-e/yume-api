# Configuration

All configuration is managed in `wrangler.jsonc`.

## Full Configuration Reference

```jsonc
{
  "name": "yume-api",
  "main": "src/index.js",
  "compatibility_date": "2024-11-27",
  
  // Custom domain
  "routes": [
    { "pattern": "api.itai.gg", "custom_domain": true }
  ],
  
  // D1 Database
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "yume-attendance",
      "database_id": "your-database-id"
    }
  ],
  
  // Environment variables
  "vars": {
    // CDN SHAs
    "SHA_NAV_BAR": "commit-sha",
    "SHA_MENTION_WIDGET": "commit-sha",
    "SHA_EVENT_PARSER": "commit-sha",
    "SHA_CRUDDY_PANEL": "commit-sha",
    
    // Discord OAuth
    "DISCORD_CLIENT_ID": "your-client-id",
    "DISCORD_REDIRECT_URI": "https://api.itai.gg/auth/callback",
    "AUTH_REDIRECT_URL": "https://yumes-tools.itai.gg/#cruddy-panel",
    "ALLOWED_USER_IDS": "user-id-1, user-id-2",
    
    // Environment
    "ENVIRONMENT": "production"
  },
  
  // Secrets (set via wrangler secret)
  // DISCORD_CLIENT_SECRET
  
  // Staging environment
  "env": {
    "staging": {
      "name": "yume-api-staging",
      "routes": [
        { "pattern": "api-staging.itai.gg", "custom_domain": true }
      ],
      "vars": {
        "ENVIRONMENT": "staging"
      }
    }
  }
}
```

## Environment Variables

### CDN SHAs

Control which version of widgets are served:

| Variable | Widget |
|----------|--------|
| `SHA_NAV_BAR` | Navigation Bar |
| `SHA_MENTION_WIDGET` | Mention Widget |
| `SHA_EVENT_PARSER` | Event Parser |
| `SHA_CRUDDY_PANEL` | CruDDy Panel |

### Discord OAuth

| Variable | Description |
|----------|-------------|
| `DISCORD_CLIENT_ID` | Discord application ID |
| `DISCORD_REDIRECT_URI` | OAuth callback URL |
| `AUTH_REDIRECT_URL` | Where to redirect after login |
| `ALLOWED_USER_IDS` | Comma-separated user IDs |

## Secrets

Secrets are stored securely and not in the config file:

```bash
# Set secret
npx wrangler secret put DISCORD_CLIENT_SECRET

# List secrets
npx wrangler secret list

# Delete secret
npx wrangler secret delete DISCORD_CLIENT_SECRET
```

## Updating Configuration

After changing `wrangler.jsonc`:

```bash
npx wrangler deploy
```

Or push to trigger CI/CD.

## Per-Environment Overrides

The `env.staging` block overrides values for staging:

```jsonc
{
  "env": {
    "staging": {
      "vars": {
        "ENVIRONMENT": "staging",
        "AUTH_REDIRECT_URL": "https://staging.yoursite.com"
      }
    }
  }
}
```

Deploy to staging:

```bash
npx wrangler deploy --env staging
```

