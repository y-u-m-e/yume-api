# Authentication

The API uses Discord OAuth2 for authentication with a user ID whitelist.

## Flow

```
User clicks login
       ↓
Redirect to Discord OAuth
       ↓
User authorizes app
       ↓
Callback with auth code
       ↓
Exchange code for token
       ↓
Fetch user info from Discord
       ↓
Check if user ID in whitelist
       ↓
Set signed cookie (7 days)
       ↓
Redirect to app
```

## Endpoints

### Start Login

```http
GET /auth/login
```

Redirects user to Discord OAuth2 authorization page.

### OAuth Callback

```http
GET /auth/callback?code=...
```

Handles Discord callback, exchanges code for token, sets auth cookie.

**Success:** Redirects to app with `yume_auth` cookie set.

**Failure:** Returns 401 with error message.

### Get Current User

```http
GET /auth/me
```

Returns information about the currently authenticated user.

**Response (authenticated & authorized):**
```json
{
  "authenticated": true,
  "authorized": true,
  "user": {
    "id": "166201366228762624",
    "username": "yume",
    "avatar": "abc123def456"
  }
}
```

**Response (authenticated but not authorized):**
```json
{
  "authenticated": true,
  "authorized": false,
  "user": {
    "id": "123456789",
    "username": "someone",
    "avatar": null
  }
}
```

**Response (not authenticated):**
```json
{
  "authenticated": false
}
```

### Logout

```http
GET /auth/logout
```

Clears the auth cookie and redirects to the app homepage.

## Cookie

The `yume_auth` cookie contains a base64-encoded JSON payload:

```json
{
  "userId": "166201366228762624",
  "username": "yume",
  "avatar": "abc123",
  "exp": 1735689600000
}
```

- **Expiration:** 7 days
- **HttpOnly:** No (read by frontend)
- **Secure:** Yes (HTTPS only)
- **SameSite:** None (cross-site)

## Adding Authorized Users

Edit `wrangler.jsonc`:

```json
{
  "vars": {
    "ALLOWED_USER_IDS": "166201366228762624, 667951474856427520"
  }
}
```

Then redeploy:
```bash
npx wrangler deploy
```

## Finding Discord User IDs

1. Enable Developer Mode in Discord (Settings → Advanced)
2. Right-click user → Copy User ID

