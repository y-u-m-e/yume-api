# CDN Proxy

Serves widget JavaScript files with instant cache invalidation.

## Endpoint

```http
GET /cdn/:filename.js
```

## Available Files

| File | Widget |
|------|--------|
| `nav-bar.js` | Navigation Bar |
| `mention-widget.js` | Mention Widget |
| `event-parser-widget.js` | Event Parser |
| `cruddy-panel.js` | CruDDy Panel |

## How It Works

```
Request to /cdn/widget.js
         ↓
Worker looks up SHA from env
         ↓
Fetches from jsDelivr with specific SHA
         ↓
Returns content (proxied, not redirect)
```

## Why Not Direct CDN?

**Problem:** jsDelivr caches files for up to 7 days at the edge, even when using branch tags like `@prod`.

**Solution:** The API proxies requests and pins to specific Git SHAs, which:
1. Provides cache-busting on every commit
2. Allows instant updates by changing the SHA in config
3. Maintains consistent versioning

## SHA Configuration

In `wrangler.jsonc`:

```json
{
  "vars": {
    "SHA_NAV_BAR": "abc1234",
    "SHA_MENTION_WIDGET": "def5678",
    "SHA_EVENT_PARSER": "ghi9012",
    "SHA_CRUDDY_PANEL": "jkl3456"
  }
}
```

## Updating Widget Versions

1. Push changes to `yume-tools` repo
2. Get the new commit SHA
3. Update the corresponding `SHA_*` variable
4. Deploy the worker

```bash
# Get latest SHA
git log --oneline -1

# Update wrangler.jsonc with new SHA
# Then deploy
npx wrangler deploy
```

## URL Format (Internal)

The proxy constructs URLs like:

```
https://cdn.jsdelivr.net/gh/y-u-m-e/yume-tools@{SHA}/dist/{path}
```

## Caching

- The proxy response includes standard cache headers
- Cloudflare caches at the edge
- SHA changes = new URL = fresh content

