/**
 * =============================================================================
 * YUME API - Cloudflare Worker
 * =============================================================================
 * 
 * Main API backend for Yume Tools ecosystem. Handles:
 * - Discord OAuth2 authentication
 * - User permission management (D1 database)
 * - Attendance tracking for clan events
 * - Tile Event system (snake-style progression games)
 * - Widget heartbeat monitoring
 * - CDN proxy for jsDelivr assets
 * 
 * Deployed via GitHub Actions to Cloudflare Workers.
 * Custom domains: api.emuy.gg, api.itai.gg
 * 
 * Database: Cloudflare D1 (SQLite)
 * Authentication: Discord OAuth2 + HMAC-signed JWT tokens
 * 
 * @author Yume Tools Team
 * @version 1.0.0
 */

// =============================================================================
// GOOGLE SHEETS HELPERS
// =============================================================================
// These functions handle reading from public Google Sheets for the Tile Events
// system. They support both authenticated (service account) and public access.

/**
 * Encode data to base64url format (used for JWT tokens)
 * Base64url is a URL-safe variant of base64 encoding
 * @param {string|ArrayBuffer} input - Data to encode
 * @returns {string} Base64url encoded string
 */
function base64urlEncode(input) {
  let base64;
  if (typeof input === "string") {
    base64 = btoa(input);
  } else {
    // Handle ArrayBuffer (for signatures)
    base64 = btoa(String.fromCharCode(...new Uint8Array(input)));
  }
  // Convert standard base64 to base64url (replace +/ with -_ and remove padding)
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Import a PEM-encoded private key for use with Web Crypto API
 * Used for signing Google service account JWTs
 * @param {string} pem - PEM-encoded private key
 * @returns {Promise<CryptoKey>} Imported key for signing
 */
async function importPrivateKey(pem) {
  // Strip PEM headers and whitespace to get raw base64
  const pemContents = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  // Decode base64 to binary
  const binaryKey = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
  // Import as PKCS8 key for RSA signing
  return crypto.subtle.importKey(
    "pkcs8",
    binaryKey,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

/**
 * Create a JWT for Google service account authentication
 * This is used when accessing private Google Sheets
 * @param {string} serviceAccountEmail - Google service account email
 * @param {string} privateKeyPem - PEM-encoded private key
 * @returns {Promise<string>} Signed JWT token
 */
async function createGoogleJWT(serviceAccountEmail, privateKeyPem) {
  const header = { alg: "RS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: serviceAccountEmail,           // Issuer (service account email)
    scope: "https://www.googleapis.com/auth/spreadsheets.readonly", // Read-only access
    aud: "https://oauth2.googleapis.com/token", // Token endpoint
    iat: now,                           // Issued at
    exp: now + 3600                     // Expires in 1 hour
  };
  
  // Create the unsigned token
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  
  // Sign with private key
  const privateKey = await importPrivateKey(privateKeyPem);
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    new TextEncoder().encode(signatureInput)
  );
  
  return `${signatureInput}.${base64urlEncode(signature)}`;
}

/**
 * Exchange a JWT for a Google access token
 * @param {string} jwt - Signed JWT token
 * @returns {Promise<string>} Google access token
 */
async function getGoogleAccessToken(jwt) {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
  });
  if (!response.ok) throw new Error(`Failed to get access token: ${await response.text()}`);
  const data = await response.json();
  return data.access_token;
}

/**
 * Read data from a PUBLIC Google Sheet (no authentication required)
 * Uses Google's CSV export endpoint which works for publicly shared sheets.
 * 
 * @param {string} spreadsheetId - The ID from the Google Sheet URL
 * @param {string} sheetName - The name of the tab/sheet to read
 * @returns {Promise<string[][]>} 2D array of cell values
 * @throws {Error} If sheet is not public or doesn't exist
 */
async function readGoogleSheetPublic(spreadsheetId, sheetName) {
  // Google Sheets public CSV export endpoint
  // This only works if the sheet is shared as "Anyone with the link can view"
  const csvUrl = `https://docs.google.com/spreadsheets/d/${spreadsheetId}/gviz/tq?tqx=out:csv&sheet=${encodeURIComponent(sheetName)}`;
  const response = await fetch(csvUrl);
  
  if (!response.ok) {
    throw new Error(`Failed to read sheet. Make sure it's shared as "Anyone with the link can view". Status: ${response.status}`);
  }
  
  const csvText = await response.text();
  
  // Parse CSV into rows
  const rows = [];
  const lines = csvText.split('\n');
  
  for (const line of lines) {
    if (!line.trim()) continue;
    
    // Simple CSV parsing (handles quoted fields)
    const row = [];
    let current = '';
    let inQuotes = false;
    
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      
      if (char === '"') {
        if (inQuotes && line[i + 1] === '"') {
          current += '"';
          i++; // Skip escaped quote
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char === ',' && !inQuotes) {
        row.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
    row.push(current.trim()); // Last field
    rows.push(row);
  }
  
  return rows;
}

export default {
  async fetch(request, env, ctx) {
    const { method } = request;
    const url = new URL(request.url);

    // ==========================================================================
    // ERROR LOGGING SYSTEM
    // ==========================================================================
    // Captures and stores errors in D1 for debugging and monitoring
    
    /**
     * Initialize the error_logs table if it doesn't exist
     */
    const initErrorLogTable = async () => {
      try {
        await env.EVENT_TRACK_DB.prepare(`
          CREATE TABLE IF NOT EXISTS error_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            endpoint TEXT,
            method TEXT,
            error_type TEXT,
            error_message TEXT,
            stack_trace TEXT,
            user_id TEXT,
            request_body TEXT,
            ip_address TEXT,
            user_agent TEXT,
            resolved INTEGER DEFAULT 0,
            notes TEXT
          )
        `).run();
      } catch (e) {
        console.error("Failed to init error_logs table:", e);
      }
    };

    /**
     * Log an error to the database
     * @param {Object} errorData - Error details to log
     * @param {string} errorData.endpoint - API endpoint that failed
     * @param {string} errorData.method - HTTP method
     * @param {string} errorData.errorType - Category of error (db, auth, validation, etc.)
     * @param {string} errorData.errorMessage - Error message
     * @param {string} errorData.stackTrace - Error stack trace (optional)
     * @param {string} errorData.userId - User ID if authenticated (optional)
     * @param {string} errorData.requestBody - Request body (optional, sanitized)
     */
    const logError = async (errorData) => {
      try {
        await initErrorLogTable();
        
        const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
        const userAgent = request.headers.get("User-Agent") || "unknown";
        
        await env.EVENT_TRACK_DB.prepare(`
          INSERT INTO error_logs (
            endpoint, method, error_type, error_message, stack_trace,
            user_id, request_body, ip_address, user_agent
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          errorData.endpoint || url.pathname,
          errorData.method || method,
          errorData.errorType || "unknown",
          errorData.errorMessage || "No message",
          errorData.stackTrace || null,
          errorData.userId || null,
          errorData.requestBody || null,
          clientIP,
          userAgent.substring(0, 255) // Truncate user agent
        ).run();
        
        console.log(`[ERROR LOGGED] ${errorData.errorType}: ${errorData.errorMessage}`);
      } catch (logErr) {
        // Don't let logging errors break the app
        console.error("Failed to log error:", logErr);
      }
    };

    // --- Allowed Origins (CORS Security) ---
    const ALLOWED_ORIGINS = [
      "https://itai.gg",
      "https://www.itai.gg",
      "https://yumes-tools.itai.gg",
      "https://emuy.gg",
      "https://www.emuy.gg",
      "https://api.itai.gg",
      "https://api.emuy.gg",
      // Development
      "http://localhost:5173",
      "http://localhost:3000",
      // Cloudflare Pages previews
    ];
    // Allow any *.pages.dev for Cloudflare Pages previews
    const requestOrigin = request.headers.get("Origin");
    const isAllowedOrigin = requestOrigin && (
      ALLOWED_ORIGINS.includes(requestOrigin) ||
      requestOrigin.endsWith(".pages.dev")
    );
    const corsOrigin = isAllowedOrigin ? requestOrigin : ALLOWED_ORIGINS[0];

    // --- CORS Headers Helper ---
    const corsHeaders = {
      "Access-Control-Allow-Origin": corsOrigin,
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Credentials": "true"
    };

    // --- Rate Limiting ---
    // Uses Cloudflare's edge cache for distributed rate limiting
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    const rateLimitKey = `rate:${clientIP}:${Math.floor(Date.now() / 60000)}`; // Per minute
    const RATE_LIMIT = 120; // requests per minute
    
    // Skip rate limiting for health checks and CDN
    const skipRateLimit = url.pathname === "/health" || url.pathname.startsWith("/cdn/");
    
    if (!skipRateLimit) {
      try {
        // Use D1 for simple rate limit tracking
        await env.EVENT_TRACK_DB.prepare(`
          CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT PRIMARY KEY,
            count INTEGER DEFAULT 1,
            expires_at INTEGER
          )
        `).run();
        
        const now = Date.now();
        const windowEnd = Math.floor(now / 60000) * 60000 + 60000;
        
        // Clean old entries and check/increment
        await env.EVENT_TRACK_DB.prepare(`DELETE FROM rate_limits WHERE expires_at < ?`).bind(now).run();
        
        const result = await env.EVENT_TRACK_DB.prepare(`
          INSERT INTO rate_limits (key, count, expires_at) VALUES (?, 1, ?)
          ON CONFLICT(key) DO UPDATE SET count = count + 1
          RETURNING count
        `).bind(rateLimitKey, windowEnd).first();
        
        if (result && result.count > RATE_LIMIT) {
          return new Response(JSON.stringify({ error: "Rate limit exceeded. Try again later." }), {
            status: 429,
            headers: { 
              ...corsHeaders, 
              "Content-Type": "application/json",
              "Retry-After": "60"
            }
          });
        }
      } catch (e) {
        // Don't block on rate limit errors, just log
        console.error("Rate limit check failed:", e);
      }
    }

    // --- Input Sanitization Helpers ---
    // Escape LIKE pattern special characters to prevent wildcard injection
    const escapeLike = (str) => str.replace(/[%_\\]/g, '\\$&');
    
    // Validate date format (YYYY-MM-DD)
    const isValidDate = (str) => /^\d{4}-\d{2}-\d{2}$/.test(str);
    
    // Sanitize string input - trim and limit length
    const sanitizeString = (str, maxLength = 255) => {
      if (typeof str !== 'string') return '';
      return str.trim().slice(0, maxLength);
    };
    
    // Validate positive integer
    const isPositiveInt = (val) => Number.isInteger(val) && val > 0;

    // --- CORS Preflight ---
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // --- Health Check Endpoint ---
    if (method === "GET" && url.pathname === "/health") {
      const startTime = Date.now();
      let dbStatus = "healthy";
      let dbLatency = 0;
      
      // Test database connectivity
      try {
        const dbStart = Date.now();
        await env.EVENT_TRACK_DB.prepare("SELECT 1").first();
        dbLatency = Date.now() - dbStart;
      } catch (err) {
        dbStatus = "unhealthy";
        dbLatency = -1;
      }

      const health = {
        status: dbStatus === "healthy" ? "healthy" : "degraded",
        timestamp: new Date().toISOString(),
        environment: env.ENVIRONMENT || "unknown",
        version: "1.0.0",
        uptime: "N/A", // Workers don't have persistent uptime
        checks: {
          database: {
            status: dbStatus,
            latency_ms: dbLatency
          }
        },
        response_time_ms: Date.now() - startTime
      };

      const statusCode = health.status === "healthy" ? 200 : 503;
      return new Response(JSON.stringify(health, null, 2), {
        status: statusCode,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // --- Discord OAuth2 Authentication ---
    const DISCORD_API = "https://discord.com/api/v10";
    
    // Super admin Discord IDs (hardcoded for security - can't be modified via D1)
    const ADMIN_USER_IDS = ["166201366228762624"];
    
    // Legacy env-based whitelists (fallback only - prefer D1 database)
    const allowedUsersDocs = (env.ALLOWED_USER_IDS_DOCS || "").split(",").map(id => id.trim()).filter(Boolean);
    const allowedUsersCruddy = (env.ALLOWED_USER_IDS_CRUDDY || "").split(",").map(id => id.trim()).filter(Boolean);
    const allowedUsersGeneral = (env.ALLOWED_USER_IDS || "").split(",").map(id => id.trim()).filter(Boolean);
    
    // Helper: Get user permissions from D1 database
    const getUserPermissions = async (userId) => {
      try {
        const result = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM admin_users WHERE discord_id = ?
        `).bind(userId).first();
        
        if (result) {
          return {
            found: true,
            isAdmin: result.is_admin === 1,
            isBanned: result.is_banned === 1,
            access: {
              cruddy: result.access_cruddy === 1,
              docs: result.access_docs === 1,
              devops: result.access_devops === 1,
              infographic: result.access_infographic === 1,
              events: result.access_events === 1
            }
          };
        }
        return { found: false };
      } catch (e) {
        console.error("Error fetching user permissions:", e);
        return { found: false };
      }
    };
    
    // Helper to check if user has access to a feature (checks D1 first, then env fallback)
    const hasAccess = async (userId, feature) => {
      // Super admins always have access
      if (ADMIN_USER_IDS.includes(userId)) return true;
      
      // Check D1 database first
      const perms = await getUserPermissions(userId);
      
      // If user is banned, deny all access
      if (perms.isBanned) return false;
      
      // If user is admin, grant all access
      if (perms.isAdmin) return true;
      
      // If user found in D1, use those permissions
      if (perms.found) {
        return perms.access[feature] === true;
      }
      
      // Fallback to legacy env-based whitelist
      switch (feature) {
        case 'docs': return allowedUsersDocs.includes(userId);
        case 'cruddy': return allowedUsersCruddy.includes(userId);
        case 'devops': return allowedUsersGeneral.includes(userId);
        case 'infographic': return allowedUsersCruddy.includes(userId);
        case 'events': return allowedUsersGeneral.includes(userId);
        default: return allowedUsersGeneral.includes(userId);
      }
    };

    // --- HMAC Token Signing ---
    // Creates cryptographically signed tokens that can't be forged
    const JWT_SECRET = env.JWT_SECRET || "default-dev-secret-change-in-production";
    
    // Helper: Create HMAC signature
    const createHmacSignature = async (data) => {
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(JWT_SECRET),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
      return btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    };
    
    // Helper: Verify HMAC signature
    const verifyHmacSignature = async (data, signature) => {
      const expectedSig = await createHmacSignature(data);
      return signature === expectedSig;
    };

    // Helper: Create a signed token (HMAC-SHA256)
    const createToken = async (userId, username, avatar, globalName) => {
      const payload = { 
        userId, 
        username, 
        avatar, 
        globalName,
        exp: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days
      };
      const data = btoa(JSON.stringify(payload));
      const signature = await createHmacSignature(data);
      return `${data}.${signature}`;
    };

    // Helper: Verify and decode signed token
    const verifyToken = async (token) => {
      try {
        const [data, signature] = token.split('.');
        if (!data || !signature) return null;
        
        // Verify signature
        const isValid = await verifyHmacSignature(data, signature);
        if (!isValid) {
          console.log("Token signature invalid");
          return null;
        }
        
        const payload = JSON.parse(atob(data));
        if (payload.exp < Date.now()) {
          console.log("Token expired");
          return null;
        }
        return payload;
      } catch (e) {
        console.error("Token verification error:", e);
        return null;
      }
    };

    // Helper: Get token from cookie
    const getTokenFromCookie = (request) => {
      const cookie = request.headers.get("Cookie") || "";
      const match = cookie.match(/yume_auth=([^;]+)/);
      return match ? match[1] : null;
    };
    
    // Helper: Get redirect URI based on request host (supports multiple domains)
    const getRedirectUri = (host) => {
      if (host.includes("emuy.gg")) {
        return "https://api.emuy.gg/auth/callback";
      }
      // Default to itai.gg
      return env.DISCORD_REDIRECT_URI || "https://api.itai.gg/auth/callback";
    };
    
    // Helper: Get default return URL based on request host
    const getDefaultReturnUrl = (host) => {
      if (host.includes("emuy.gg")) {
        return "https://emuy.gg/";
      }
      return "https://yumes-tools.itai.gg/";
    };

    // GET /auth/login - Redirect to Discord OAuth
    // Supports ?return_url= parameter to redirect back after login
    if (method === "GET" && url.pathname === "/auth/login") {
      const host = url.host;
      const redirectUri = getRedirectUri(host);
      const returnUrl = url.searchParams.get("return_url") || getDefaultReturnUrl(host);
      // Encode return URL in state (base64)
      const stateData = JSON.stringify({ returnUrl, nonce: crypto.randomUUID() });
      const state = btoa(stateData);
      const params = new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: "code",
        scope: "identify",
        state: state
      });
      return Response.redirect(`https://discord.com/api/oauth2/authorize?${params}`, 302);
    }

    // GET /auth/callback - Handle Discord OAuth callback
    if (method === "GET" && url.pathname === "/auth/callback") {
      const code = url.searchParams.get("code");
      if (!code) {
        return new Response("Missing authorization code", { status: 400 });
      }

      try {
        const host = url.host;
        const redirectUri = getRedirectUri(host);
        
        // Exchange code for access token
        const tokenResponse = await fetch(`${DISCORD_API}/oauth2/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: env.DISCORD_CLIENT_ID,
            client_secret: env.DISCORD_CLIENT_SECRET,
            grant_type: "authorization_code",
            code: code,
            redirect_uri: redirectUri
          })
        });

        if (!tokenResponse.ok) {
          const errorText = await tokenResponse.text();
          console.error("Token exchange failed:", errorText);
          console.error("Used redirect_uri:", redirectUri);
          return new Response(`Authentication failed: ${errorText}`, { status: 401 });
        }

        const tokens = await tokenResponse.json();

        // Get user info
        const userResponse = await fetch(`${DISCORD_API}/users/@me`, {
          headers: { Authorization: `Bearer ${tokens.access_token}` }
        });

        if (!userResponse.ok) {
          return new Response("Failed to get user info", { status: 401 });
        }

        const user = await userResponse.json();

        // Create session token
        const sessionToken = await createToken(user.id, user.username, user.avatar, user.global_name);

        // Decode return URL from state
        let returnUrl = "https://yumes-tools.itai.gg/";
        const state = url.searchParams.get("state");
        if (state) {
          try {
            const stateData = JSON.parse(atob(state));
            if (stateData.returnUrl) {
              // Only allow redirects to trusted domains
              const allowedDomains = ["itai.gg", "emuy.gg", "pages.dev"];
              const returnUrlObj = new URL(stateData.returnUrl);
              if (allowedDomains.some(d => returnUrlObj.hostname === d || returnUrlObj.hostname.endsWith("." + d))) {
                returnUrl = stateData.returnUrl;
              }
            }
          } catch (e) {
            console.error("Failed to decode state:", e);
          }
        }

        // Redirect back to the app with cookie set
        // Use SameSite=None for cross-site cookies
        const cookieOptions = `yume_auth=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${7 * 24 * 60 * 60}`;
        
        return new Response(null, {
          status: 302,
          headers: {
            "Location": returnUrl,
            "Set-Cookie": cookieOptions
          }
        });
      } catch (err) {
        console.error("OAuth callback error:", err);
        await logError({
          endpoint: "/auth/callback",
          errorType: "auth",
          errorMessage: err.message,
          stackTrace: err.stack
        });
        return new Response("Authentication error", { status: 500 });
      }
    }

    // GET /auth/me - Get current user (check if authenticated)
    if (method === "GET" && url.pathname === "/auth/me") {
      const cookieHeader = request.headers.get("Cookie") || "(no cookie header)";
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;

      // Debug logging
      console.log("=== AUTH DEBUG ===");
      console.log("Cookie header:", cookieHeader);
      console.log("Extracted token:", token ? token.substring(0, 30) + "..." : "(none)");
      console.log("Decoded user:", user);

      if (!user) {
        console.log("Result: NOT AUTHENTICATED (no valid token)");
        return new Response(JSON.stringify({ 
          authenticated: false,
          debug: { cookieReceived: cookieHeader !== "(no cookie header)", tokenFound: !!token }
        }), {
          status: 200,
          headers: { 
            ...corsHeaders, 
            "Content-Type": "application/json",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache"
          }
        });
      }

      // Get full permissions from D1
      const perms = await getUserPermissions(user.userId);
      
      // Check if user is banned
      if (perms.isBanned) {
        return new Response(JSON.stringify({
          authenticated: true,
          authorized: false,
          banned: true,
          access: { docs: false, cruddy: false, devops: false, infographic: false },
          user: { id: user.userId, username: user.username, avatar: user.avatar }
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      // Check access for each feature (async)
      const canAccessDocs = await hasAccess(user.userId, 'docs');
      const canAccessCruddy = await hasAccess(user.userId, 'cruddy');
      const canAccessDevops = await hasAccess(user.userId, 'devops');
      const canAccessInfographic = await hasAccess(user.userId, 'infographic');
      
      // Legacy: "authorized" = has access to cruddy panel (backward compatible)
      const isAuthorized = canAccessCruddy;
      const isAdmin = perms.isAdmin || ADMIN_USER_IDS.includes(user.userId);
      
      console.log("User ID:", user.userId);
      console.log("Access - Admin:", isAdmin, "Docs:", canAccessDocs, "Cruddy:", canAccessCruddy);
      
      // Update last login time in D1 (fire and forget)
      if (perms.found) {
        ctx.waitUntil(
          env.EVENT_TRACK_DB.prepare(`
            UPDATE admin_users SET last_login = datetime('now') WHERE discord_id = ?
          `).bind(user.userId).run()
        );
      }

      return new Response(JSON.stringify({
        authenticated: true,
        authorized: isAuthorized,
        isAdmin,
        access: {
          docs: canAccessDocs,
          cruddy: canAccessCruddy,
          devops: canAccessDevops,
          infographic: canAccessInfographic
        },
        user: {
          id: user.userId,
          username: user.username,
          avatar: user.avatar,
          globalName: user.globalName
        }
      }), {
        status: 200,
        headers: { 
          ...corsHeaders, 
          "Content-Type": "application/json",
          "Cache-Control": "no-store, no-cache, must-revalidate",
          "Pragma": "no-cache"
        }
      });
    }

    // GET /auth/logout - Clear session completely
    if (method === "GET" && url.pathname === "/auth/logout") {
      // Check for return_url or default to docs
      const returnUrl = url.searchParams.get("return_url") || "/docs/";
      // Clear cookie with ALL possible variations to ensure deletion
      const expiredDate = new Date(0).toUTCString();
      return new Response(null, {
        status: 302,
        headers: [
          ["Location", returnUrl],
          // Clear with .itai.gg domain
          ["Set-Cookie", "yume_auth=; Path=/; Domain=.itai.gg; HttpOnly; Secure; SameSite=Lax; Max-Age=0"],
          ["Set-Cookie", `yume_auth=; Path=/; Domain=.itai.gg; HttpOnly; Secure; SameSite=Lax; Expires=${expiredDate}`],
          // Clear with .emuy.gg domain
          ["Set-Cookie", "yume_auth=; Path=/; Domain=.emuy.gg; HttpOnly; Secure; SameSite=Lax; Max-Age=0"],
          ["Set-Cookie", `yume_auth=; Path=/; Domain=.emuy.gg; HttpOnly; Secure; SameSite=Lax; Expires=${expiredDate}`],
          // Clear without domain (matches current domain only)
          ["Set-Cookie", "yume_auth=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"],
          ["Set-Cookie", `yume_auth=; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${expiredDate}`],
          // Prevent caching
          ["Cache-Control", "no-store, no-cache, must-revalidate"],
          ["Pragma", "no-cache"]
        ]
      });
    }

    // --- Admin User Management ---
    // Helper to check if current user is admin (checks hardcoded list OR D1 is_admin flag)
    const isAdmin = async (user) => {
      if (!user) return false;
      // Hardcoded super admins always have access
      if (ADMIN_USER_IDS.includes(user.userId)) return true;
      // Check D1 for admin flag
      const perms = await getUserPermissions(user.userId);
      return perms.isAdmin === true;
    };
    
    // GET /admin/users - Get all allowed users
    if (method === "GET" && url.pathname === "/admin/users") {
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;
      
      if (!await isAdmin(user)) {
        return new Response(JSON.stringify({ error: "Not authorized" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        // Try to get users from D1, create table if doesn't exist
        // Enhanced with more granular permissions
        await env.EVENT_TRACK_DB.prepare(`
          CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT UNIQUE NOT NULL,
            username TEXT,
            global_name TEXT,
            avatar TEXT,
            is_admin INTEGER DEFAULT 0,
            access_cruddy INTEGER DEFAULT 0,
            access_docs INTEGER DEFAULT 0,
            access_devops INTEGER DEFAULT 0,
            access_infographic INTEGER DEFAULT 0,
            access_events INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            notes TEXT,
            last_login TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `).run();
        
        // Add new columns if they don't exist (for migration)
        const columns = ['is_admin', 'access_devops', 'access_infographic', 'access_events', 'is_banned', 'notes', 'last_login', 'updated_at', 'global_name', 'avatar'];
        for (const col of columns) {
          try {
            await env.EVENT_TRACK_DB.prepare(`ALTER TABLE admin_users ADD COLUMN ${col} ${col.startsWith('is_') || col.startsWith('access_') ? 'INTEGER DEFAULT 0' : 'TEXT'}`).run();
          } catch (e) { /* Column likely exists */ }
        }
        
        const result = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM admin_users ORDER BY is_admin DESC, created_at DESC
        `).all();
        
        // Also return env-based users for reference
        return new Response(JSON.stringify({
          users: result.results || [],
          env_users: {
            cruddy: allowedUsersCruddy,
            docs: allowedUsersDocs
          }
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    
    // POST /admin/users - Add a new allowed user
    if (method === "POST" && url.pathname === "/admin/users") {
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;
      
      if (!await isAdmin(user)) {
        return new Response(JSON.stringify({ error: "Not authorized" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        const body = await request.json();
        const { 
          discord_id, 
          username, 
          global_name,
          avatar,
          is_admin,
          access_cruddy, 
          access_docs,
          access_devops,
          access_infographic,
          access_events,
          is_banned,
          notes
        } = body;
        
        // Validate discord_id format (17-20 digit number)
        if (!discord_id || !/^\d{17,20}$/.test(discord_id)) {
          return new Response(JSON.stringify({ error: "Invalid discord_id. Must be 17-20 digits." }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Sanitize text inputs
        const sanitizedUsername = sanitizeString(username, 100);
        const sanitizedGlobalName = sanitizeString(global_name, 100);
        const sanitizedNotes = sanitizeString(notes, 500);
        
        // Insert or update user with all permissions
        await env.EVENT_TRACK_DB.prepare(`
          INSERT INTO admin_users (
            discord_id, username, global_name, avatar, is_admin,
            access_cruddy, access_docs, access_devops, access_infographic, access_events,
            is_banned, notes, updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
          ON CONFLICT(discord_id) DO UPDATE SET
            username = excluded.username,
            global_name = excluded.global_name,
            avatar = excluded.avatar,
            is_admin = excluded.is_admin,
            access_cruddy = excluded.access_cruddy,
            access_docs = excluded.access_docs,
            access_devops = excluded.access_devops,
            access_infographic = excluded.access_infographic,
            access_events = excluded.access_events,
            is_banned = excluded.is_banned,
            notes = excluded.notes,
            updated_at = datetime('now')
        `).bind(
          discord_id, 
          sanitizedUsername || null, 
          sanitizedGlobalName || null,
          avatar || null,
          is_admin ? 1 : 0,
          access_cruddy ? 1 : 0, 
          access_docs ? 1 : 0,
          access_devops ? 1 : 0,
          access_infographic ? 1 : 0,
          access_events ? 1 : 0,
          is_banned ? 1 : 0,
          sanitizedNotes || null
        ).run();
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    
    // DELETE /admin/users/:discord_id - Remove a user
    const deleteUserMatch = url.pathname.match(/^\/admin\/users\/(\d+)$/);
    if (method === "DELETE" && deleteUserMatch) {
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;
      
      if (!await isAdmin(user)) {
        return new Response(JSON.stringify({ error: "Not authorized" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const discordId = deleteUserMatch[1];
      
      try {
        await env.EVENT_TRACK_DB.prepare(`
          DELETE FROM admin_users WHERE discord_id = ?
        `).bind(discordId).run();
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin Secrets Endpoint ---
    // Returns sensitive config only for authenticated admins
    
    if (method === "GET" && url.pathname === "/admin/secrets") {
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;
      
      if (!user) {
        return new Response(JSON.stringify({ error: "Not authenticated" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      if (!ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Not authorized" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      // Return secrets for admin
      return new Response(JSON.stringify({
        github_pat: env.GITHUB_PAT || null,
        cloudflare_account_id: env.CLOUDFLARE_ACCOUNT_ID || null
      }), {
        status: 200,
        headers: { 
          ...corsHeaders, 
          "Content-Type": "application/json",
          "Cache-Control": "no-store, no-cache, must-revalidate"
        }
      });
    }

    // --- Admin: Cloudflare Pages Deployments ---
    // Fetches deployment history for a Pages project
    if (method === "GET" && url.pathname === "/admin/cf-deployments") {
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Not authorized" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const projectName = url.searchParams.get("project") || "yume-pages";
      
      if (!env.CLOUDFLARE_API_TOKEN || !env.CLOUDFLARE_ACCOUNT_ID) {
        return new Response(JSON.stringify({ error: "Cloudflare credentials not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        const cfResponse = await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/pages/projects/${projectName}/deployments?per_page=5`,
          {
            headers: {
              "Authorization": `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
              "Content-Type": "application/json"
            }
          }
        );
        
        const data = await cfResponse.json();
        
        if (!data.success) {
          return new Response(JSON.stringify({ error: data.errors?.[0]?.message || "Failed to fetch deployments" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Map to a simpler format
        const deployments = (data.result || []).map(d => ({
          id: d.id,
          url: d.url,
          environment: d.environment,
          status: d.latest_stage?.status || "unknown",
          created_at: d.created_on,
          source: {
            type: d.source?.type,
            branch: d.deployment_trigger?.metadata?.branch,
            commit_hash: d.deployment_trigger?.metadata?.commit_hash?.substring(0, 7),
            commit_message: d.deployment_trigger?.metadata?.commit_message?.split('\n')[0]
          }
        }));
        
        return new Response(JSON.stringify({ deployments }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Failed to fetch Cloudflare deployments" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Sesh Calendar Worker Management ---
    // Proxy endpoints to the sesh-calendar-worker
    
    // GET /admin/sesh-worker/status - Get worker status
    if (method === "GET" && url.pathname === "/admin/sesh-worker/status") {
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Not authorized" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const workerUrl = env.SESH_WORKER_URL;
      if (!workerUrl) {
        return new Response(JSON.stringify({ 
          error: "Sesh worker URL not configured",
          configured: false 
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        const response = await fetch(`${workerUrl}/status`);
        const data = await response.json();
        return new Response(JSON.stringify({ ...data, configured: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ 
          error: "Failed to reach sesh worker",
          configured: true,
          message: err.message 
        }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    
    // GET /admin/sesh-worker/config - Get worker configuration
    if (method === "GET" && url.pathname === "/admin/sesh-worker/config") {
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Not authorized" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const workerUrl = env.SESH_WORKER_URL;
      if (!workerUrl) {
        return new Response(JSON.stringify({ error: "Sesh worker URL not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        const response = await fetch(`${workerUrl}/config`);
        const data = await response.json();
        return new Response(JSON.stringify(data), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Failed to get sesh worker config" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    
    // POST /admin/sesh-worker/sync - Trigger manual sync
    if (method === "POST" && url.pathname === "/admin/sesh-worker/sync") {
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Not authorized" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const workerUrl = env.SESH_WORKER_URL;
      if (!workerUrl) {
        return new Response(JSON.stringify({ error: "Sesh worker URL not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        const response = await fetch(`${workerUrl}/sync`, { method: "POST" });
        const data = await response.json();
        return new Response(JSON.stringify(data), {
          status: response.status,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Failed to trigger sesh worker sync" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Documentation Site (Public + Protected) ---
    // Some pages are public, others require authentication
    if (method === "GET" && url.pathname.startsWith("/docs")) {
      // ============================================
      // PROTECTED SECTIONS CONFIGURATION
      // Add paths here to protect them from unauthorized access
      // These paths match the start of the file path (e.g., "api/" matches "api/overview.md")
      // ============================================
      const protectedPrefixes = [
        "api/",                    // API Reference section
        "database/",               // Database section  
        "devops/",                 // DevOps section
        "development/",            // Development section
        "widgets/cruddy-panel"     // CruDDy Panel widget (single page)
      ];
      
      let filePath = url.pathname.replace(/^\/docs\/?/, "") || "index.html";
      if (filePath === "" || filePath.endsWith("/")) {
        filePath = filePath + "index.html";
      }
      // If no extension and not a known file, serve index.html (SPA routing)
      if (!filePath.includes(".")) {
        filePath = "index.html";
      }
      
      // Check if page is protected
      const isProtectedPage = protectedPrefixes.some(prefix => filePath.startsWith(prefix));
      
      // Check authentication
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;
      const canAccessDocs = user ? await hasAccess(user.userId, 'docs') : false;
      
      const sha = env.SHA_DOCS || "main";
      
      // SERVER-SIDE PROTECTION: Never send protected content to unauthorized users
      // If requesting a protected markdown file without access, return placeholder
      if (isProtectedPage && !canAccessDocs && filePath.endsWith(".md")) {
        const placeholder = `# 🔒 Protected Content

This page requires authorized access to view.

${user ? `**Signed in as:** ${user.username}

You don't have permission to view this content. Contact an administrator if you believe this is an error.` : `Please log in with Discord using the button above.`}

---

[← Back to public documentation](/)
`;
        // Return 200 so Docsify renders the placeholder (security is still enforced - real content never sent)
        return new Response(placeholder, {
          status: 200,
          headers: { "Content-Type": "text/markdown", "Cache-Control": "no-store" }
        });
      }
      
      const cdnUrl = `https://cdn.jsdelivr.net/gh/y-u-m-e/yume-api@${sha}/docs/${filePath}`;
      
      try {
        const cdnResponse = await fetch(cdnUrl);
        if (!cdnResponse.ok) {
          // File not found - serve index.html for SPA
          if (cdnResponse.status === 404) {
            const indexUrl = `https://cdn.jsdelivr.net/gh/y-u-m-e/yume-api@${sha}/docs/index.html`;
            const indexResponse = await fetch(indexUrl);
            if (indexResponse.ok) {
              const html = await indexResponse.text();
              return new Response(html, {
                status: 200,
                headers: { "Content-Type": "text/html", "Cache-Control": "no-store" }
              });
            }
          }
          return new Response("Documentation not found", { status: 404 });
        }
        
        const content = await cdnResponse.text();
        const contentType = filePath.endsWith(".html") ? "text/html" :
                           filePath.endsWith(".md") ? "text/markdown" :
                           filePath.endsWith(".css") ? "text/css" :
                           filePath.endsWith(".js") ? "application/javascript" :
                           "text/plain";
        
        // IMPORTANT: Protected pages must NOT be cached by the browser
        // Otherwise users can still see content after logging out
        const cacheControl = isProtectedPage 
          ? "no-store, no-cache, must-revalidate" 
          : "public, max-age=300";
        
        return new Response(content, {
          status: 200,
          headers: { 
            "Content-Type": contentType, 
            "Cache-Control": cacheControl,
            "Pragma": isProtectedPage ? "no-cache" : ""
          }
        });
      } catch (err) {
        console.error("Docs proxy error:", err);
        return new Response("Failed to load documentation", { status: 502 });
      }
    }

    // --- Widget Heartbeat System ---
    // Widgets ping this when they load on Carrd to report they're visible
    
    // POST /widget/heartbeat - Widget pings when it loads
    if (method === "POST" && url.pathname === "/widget/heartbeat") {
      try {
        const body = await request.json();
        const widgetName = sanitizeString(body.widget || "", 50);
        const source = sanitizeString(body.source || "unknown", 100);
        
        if (!widgetName) {
          return new Response(JSON.stringify({ error: "widget name required" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Create heartbeat table if doesn't exist
        await env.EVENT_TRACK_DB.prepare(`
          CREATE TABLE IF NOT EXISTS widget_heartbeats (
            widget TEXT PRIMARY KEY,
            last_ping TEXT NOT NULL,
            source TEXT,
            ping_count INTEGER DEFAULT 1
          )
        `).run();
        
        // Upsert heartbeat
        await env.EVENT_TRACK_DB.prepare(`
          INSERT INTO widget_heartbeats (widget, last_ping, source, ping_count)
          VALUES (?, datetime('now'), ?, 1)
          ON CONFLICT(widget) DO UPDATE SET
            last_ping = datetime('now'),
            source = excluded.source,
            ping_count = ping_count + 1
        `).bind(widgetName, source).run();
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Heartbeat error:", err);
        await logError({
          endpoint: "/widget/heartbeat",
          errorType: "db",
          errorMessage: err.message,
          stackTrace: err.stack
        });
        return new Response(JSON.stringify({ error: "Failed to record heartbeat" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    
    // POST /admin/widget/ping - Admin endpoint to manually trigger heartbeats (for testing)
    if (method === "POST" && url.pathname === "/admin/widget/ping") {
      const token = getTokenFromCookie(request);
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Not authorized" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        // Create table if doesn't exist
        await env.EVENT_TRACK_DB.prepare(`
          CREATE TABLE IF NOT EXISTS widget_heartbeats (
            widget TEXT PRIMARY KEY,
            last_ping TEXT NOT NULL,
            source TEXT,
            ping_count INTEGER DEFAULT 1
          )
        `).run();
        
        // Ping all three widgets as "admin-test"
        const widgets = ['mention-maker', 'event-parser', 'infographic-maker'];
        for (const widget of widgets) {
          await env.EVENT_TRACK_DB.prepare(`
            INSERT INTO widget_heartbeats (widget, last_ping, source, ping_count)
            VALUES (?, datetime('now'), 'admin-devops', 1)
            ON CONFLICT(widget) DO UPDATE SET
              last_ping = datetime('now'),
              source = 'admin-devops',
              ping_count = ping_count + 1
          `).bind(widget).run();
        }
        
        return new Response(JSON.stringify({ 
          success: true, 
          message: "Heartbeats updated for all widgets",
          widgets 
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Admin heartbeat error:", err);
        return new Response(JSON.stringify({ error: "Failed to update heartbeats" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // GET /widget/status - Get status of all widgets (public endpoint)
    if (method === "GET" && url.pathname === "/widget/status") {
      try {
        // Create table if doesn't exist (for first-time queries)
        await env.EVENT_TRACK_DB.prepare(`
          CREATE TABLE IF NOT EXISTS widget_heartbeats (
            widget TEXT PRIMARY KEY,
            last_ping TEXT NOT NULL,
            source TEXT,
            ping_count INTEGER DEFAULT 1
          )
        `).run();
        
        const result = await env.EVENT_TRACK_DB.prepare(`
          SELECT 
            widget,
            last_ping,
            source,
            ping_count,
            CASE 
              WHEN datetime(last_ping) > datetime('now', '-5 minutes') THEN 'online'
              WHEN datetime(last_ping) > datetime('now', '-30 minutes') THEN 'recent'
              WHEN datetime(last_ping) > datetime('now', '-24 hours') THEN 'stale'
              ELSE 'offline'
            END as status
          FROM widget_heartbeats
          ORDER BY last_ping DESC
        `).all();
        
        // Map to object for easy lookup
        const widgets = {};
        for (const row of result.results || []) {
          widgets[row.widget] = {
            status: row.status,
            lastPing: row.last_ping,
            source: row.source,
            pingCount: row.ping_count
          };
        }
        
        return new Response(JSON.stringify({ widgets }), {
          status: 200,
          headers: { 
            ...corsHeaders, 
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=30" // Cache for 30 seconds
          }
        });
      } catch (err) {
        console.error("Widget status error:", err);
        return new Response(JSON.stringify({ error: "Failed to get widget status" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Widget CDN Proxy ---
    // Proxies jsDelivr with the configured SHA for instant cache-busting
    // Each widget has its own SHA env variable for independent versioning
    // Usage: https://api.itai.gg/cdn/event-parser-widget.js
    //        https://api.itai.gg/cdn/cruddy-panel.js
    //        https://api.itai.gg/cdn/mention-widget.js
    const cdnMatch = url.pathname.match(/^\/cdn\/(.+\.js)$/);
    if (cdnMatch && (method === "GET" || method === "HEAD")) {
      const file = cdnMatch[1];
      
      // Map filenames to their paths and SHA env variables
      const fileMap = {
        "event-parser-widget.js": {
          path: "dist/log-parser/event-parser-widget.js",
          sha: env.SHA_EVENT_PARSER || "main"
        },
        "cruddy-panel.js": {
          path: "dist/cruddy-panel/cruddy-panel.js",
          sha: env.SHA_CRUDDY_PANEL || "main"
        },
        "mention-widget.js": {
          path: "dist/msg-maker/mention-widget.js",
          sha: env.SHA_MENTION_WIDGET || "main"
        },
        "nav-bar.js": {
          path: "dist/nav-bar/nav-bar.js",
          sha: env.SHA_NAV_BAR || "main"
        },
        "infographic-maker.js": {
          path: "dist/infographic-maker/infographic-maker.js",
          sha: env.SHA_INFOGRAPHIC_MAKER || "main"
        },
        "how-to.js": {
          path: "dist/how-to/how-to.js",
          sha: env.SHA_HOW_TO || "main"
        }
      };
      
      const config = fileMap[file];
      if (!config) {
        return new Response("Widget not found", { status: 404, headers: corsHeaders });
      }
      
      // Proxy the file instead of redirecting (fixes CORS issues with script tags)
      const cdnUrl = `https://cdn.jsdelivr.net/gh/y-u-m-e/yume-tools@${config.sha}/${config.path}`;
      try {
        const cdnResponse = await fetch(cdnUrl, { method: method === "HEAD" ? "HEAD" : "GET" });
        if (!cdnResponse.ok) {
          return new Response(method === "HEAD" ? null : "Failed to fetch widget", { status: 502, headers: corsHeaders });
        }
        // For HEAD requests, just return headers
        if (method === "HEAD") {
          return new Response(null, {
            status: 200,
            headers: {
              ...corsHeaders,
              "Content-Type": "application/javascript",
              "Cache-Control": "public, max-age=300"
            }
          });
        }
        const script = await cdnResponse.text();
        return new Response(script, {
          status: 200,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/javascript",
            "Cache-Control": "public, max-age=300"  // Cache for 5 min
          }
        });
      } catch (err) {
        console.error("CDN proxy error:", err);
        return new Response("Failed to fetch widget", { status: 502, headers: corsHeaders });
      }
    }

    // --- CRUD: /attendance/records ---
    const recordsMatch = url.pathname.match(/^\/attendance\/records(?:\/(\d+))?$/);
    if (recordsMatch) {
      const recordId = recordsMatch[1] ? parseInt(recordsMatch[1]) : null;

      // GET /attendance/records - List all with filtering & pagination
      if (method === "GET" && !recordId) {
        try {
          const name = sanitizeString(url.searchParams.get("name") || "", 100);
          const event = sanitizeString(url.searchParams.get("event") || "", 200);
          const start = url.searchParams.get("start") || "";
          const end = url.searchParams.get("end") || "";
          const page = Math.max(1, parseInt(url.searchParams.get("page")) || 1);
          const limit = Math.min(Math.max(1, parseInt(url.searchParams.get("limit")) || 20), 5000);
          const offset = (page - 1) * limit;

          // Validate date formats if provided
          if ((start && !isValidDate(start)) || (end && !isValidDate(end))) {
            return new Response(JSON.stringify({ error: "Invalid date format. Use YYYY-MM-DD" }), {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          let whereConditions = [];
          let bindings = [];

          if (name) {
            whereConditions.push("name LIKE ? ESCAPE '\\'");
            bindings.push(`%${escapeLike(name)}%`);
          }
          if (event) {
            whereConditions.push("event LIKE ? ESCAPE '\\'");
            bindings.push(`%${escapeLike(event)}%`);
          }
          if (start && end) {
            whereConditions.push("date BETWEEN ? AND ?");
            bindings.push(start, end);
          }

          const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(" AND ")}` : "";

          // Get total count
          const countQuery = `SELECT COUNT(*) as total FROM attendance ${whereClause}`;
          const countResult = await env.EVENT_TRACK_DB.prepare(countQuery).bind(...bindings).first();
          const total = countResult?.total || 0;

          // Get paginated results
          const dataQuery = `SELECT id, name, event, date FROM attendance ${whereClause} ORDER BY date DESC, id DESC LIMIT ? OFFSET ?`;
          const results = await env.EVENT_TRACK_DB.prepare(dataQuery).bind(...bindings, limit, offset).all();

          return new Response(JSON.stringify({ results: results.results, total, page, limit }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (err) {
          console.error("List records error:", err);
          await logError({
            endpoint: "/attendance/records",
            errorType: "db",
            errorMessage: err.message,
            stackTrace: err.stack,
            userId: user?.userId
          });
          return new Response(JSON.stringify({ error: "Failed to list records" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // POST /attendance/records - Add a single record
      if (method === "POST" && !recordId) {
        try {
          const body = await request.json();
          const name = sanitizeString(body.name, 100);
          const event = sanitizeString(body.event, 200);
          const date = body.date;

          if (!name || !event || !date) {
            return new Response(JSON.stringify({ error: "name, event, and date are required" }), {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          if (!isValidDate(date)) {
            return new Response(JSON.stringify({ error: "Invalid date format. Use YYYY-MM-DD" }), {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          const result = await env.EVENT_TRACK_DB
            .prepare("INSERT INTO attendance (name, event, date) VALUES (?, ?, ?)")
            .bind(name, event, date)
            .run();

          return new Response(JSON.stringify({ success: true, id: result.meta.last_row_id }), {
            status: 201,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (err) {
          console.error("Add record error:", err);
          return new Response(JSON.stringify({ error: "Failed to add record" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // PUT /attendance/records/:id - Update a record
      if (method === "PUT" && recordId) {
        try {
          const body = await request.json();
          const name = sanitizeString(body.name, 100);
          const event = sanitizeString(body.event, 200);
          const date = body.date;

          if (!name || !event || !date) {
            return new Response(JSON.stringify({ error: "name, event, and date are required" }), {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          if (!isValidDate(date)) {
            return new Response(JSON.stringify({ error: "Invalid date format. Use YYYY-MM-DD" }), {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          const result = await env.EVENT_TRACK_DB
            .prepare("UPDATE attendance SET name = ?, event = ?, date = ? WHERE id = ?")
            .bind(name, event, date, recordId)
            .run();

          if (result.meta.changes === 0) {
            return new Response(JSON.stringify({ error: "Record not found" }), {
              status: 404,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (err) {
          console.error("Update record error:", err);
          return new Response(JSON.stringify({ error: "Failed to update record" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // DELETE /attendance/records/:id - Delete a record
      if (method === "DELETE" && recordId) {
        try {
          const result = await env.EVENT_TRACK_DB
            .prepare("DELETE FROM attendance WHERE id = ?")
            .bind(recordId)
            .run();

          if (result.meta.changes === 0) {
            return new Response(JSON.stringify({ error: "Record not found" }), {
              status: 404,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (err) {
          console.error("Delete record error:", err);
          return new Response(JSON.stringify({ error: "Failed to delete record" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }
    }

    // --- GET: Analytics Queries ---
    if (method === "GET" && url.pathname === "/attendance") {
      const name = sanitizeString(url.searchParams.get("name") || "", 100);
      const top = parseInt(url.searchParams.get("top")) || null;
      const start = url.searchParams.get("start") || "";
      const end = url.searchParams.get("end") || "";

      // Validate date formats if provided
      if ((start && !isValidDate(start)) || (end && !isValidDate(end))) {
        return new Response(JSON.stringify({ error: "Invalid date format. Use YYYY-MM-DD" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // Validate top is reasonable
      if (top !== null && (top < 1 || top > 1000)) {
        return new Response(JSON.stringify({ error: "top must be between 1 and 1000" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      try {
        let results;

        if (top !== null) {
          // Query for Top X users (with optional date range)
          const query = start && end
            ? `SELECT name, COUNT(*) as count FROM attendance WHERE date BETWEEN ? AND ? GROUP BY name ORDER BY count DESC LIMIT ?;`
            : `SELECT name, COUNT(*) as count FROM attendance GROUP BY name ORDER BY count DESC LIMIT ?;`;

          const stmt = env.EVENT_TRACK_DB.prepare(query);
          const bindings = start && end ? [start, end, top] : [top];

          results = await stmt.bind(...bindings).all();
        } else if (name) {
          // Query for individual user history (with optional date range)
          const query = start && end
            ? `SELECT event, date FROM attendance WHERE name = ? AND date BETWEEN ? AND ? ORDER BY date DESC;`
            : `SELECT event, date FROM attendance WHERE name = ? ORDER BY date DESC;`;

          const stmt = env.EVENT_TRACK_DB.prepare(query);
          const bindings = start && end ? [name, start, end] : [name];

          results = await stmt.bind(...bindings).all();
        } else {
          return new Response("Missing required parameters.", {
            status: 400,
            headers: corsHeaders
          });
        }

        return new Response(JSON.stringify(results), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Query error:", err);
        return new Response("Failed to query attendance data", {
          status: 500,
          headers: corsHeaders
        });
      }
    }

    // --- POST: Discord + DB Logging (root path only) ---
    if (method === "POST" && url.pathname === "/") {
      try {
        const data = await request.json();

        // Parse event + names with sanitization
        const eventName = sanitizeString(data.embeds?.[0]?.fields?.[0]?.value || "Unknown Event", 200);
        const content = data.content || "";
        const attendanceBlock = content.split("```")[1] || "";
        const names = attendanceBlock
          .split(",")
          .map(n => sanitizeString(n, 100))
          .filter(n => n.length > 0);
        const today = new Date().toISOString().split("T")[0];

        for (const name of names) {
          await env.EVENT_TRACK_DB
            .prepare("INSERT INTO attendance (name, event, date) VALUES (?, ?, ?)")
            .bind(name, eventName, today)
            .run();
        }

        // Forward to Discord webhook
        const discordResponse = await fetch(env.DISCORD_WEBHOOK_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data)
        });

        if (!discordResponse.ok) {
          return new Response("Failed to send to Discord", {
            status: 500,
            headers: corsHeaders
          });
        }

        return new Response("OK", {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error parsing request:", err);
        return new Response("Invalid request", {
          status: 400,
          headers: corsHeaders
        });
      }
    }

    // ========================================
    // TILE EVENT SYSTEM
    // Snake-style tile progression game
    // ========================================
    
    // Initialize tile event tables
    const initTileEventTables = async () => {
      // Main event configuration table
      await env.EVENT_TRACK_DB.prepare(`
        CREATE TABLE IF NOT EXISTS tile_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          description TEXT,
          is_active INTEGER DEFAULT 1,
          google_sheet_id TEXT,
          google_sheet_tab TEXT,
          created_by TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
      `).run();
      
      // Tiles within an event (the snake path)
      await env.EVENT_TRACK_DB.prepare(`
        CREATE TABLE IF NOT EXISTS tile_event_tiles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id INTEGER NOT NULL,
          position INTEGER NOT NULL,
          title TEXT NOT NULL,
          description TEXT,
          image_url TEXT,
          reward TEXT,
          is_start INTEGER DEFAULT 0,
          is_end INTEGER DEFAULT 0,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (event_id) REFERENCES tile_events(id) ON DELETE CASCADE
        )
      `).run();
      
      // User progress on tiles
      await env.EVENT_TRACK_DB.prepare(`
        CREATE TABLE IF NOT EXISTS tile_event_progress (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id INTEGER NOT NULL,
          discord_id TEXT NOT NULL,
          discord_username TEXT,
          current_tile INTEGER DEFAULT 0,
          tiles_unlocked TEXT DEFAULT '[]',
          completed_at TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (event_id) REFERENCES tile_events(id) ON DELETE CASCADE,
          UNIQUE(event_id, discord_id)
        )
      `).run();
      
      // Tile completion submissions (screenshot proof)
      // Status: pending, approved, rejected
      await env.EVENT_TRACK_DB.prepare(`
        CREATE TABLE IF NOT EXISTS tile_submissions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id INTEGER NOT NULL,
          tile_id INTEGER NOT NULL,
          discord_id TEXT NOT NULL,
          discord_username TEXT,
          image_key TEXT NOT NULL,
          image_url TEXT,
          status TEXT DEFAULT 'pending',
          ocr_text TEXT,
          ai_confidence REAL,
          ai_result TEXT,
          admin_notes TEXT,
          reviewed_by TEXT,
          reviewed_at TEXT,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (event_id) REFERENCES tile_events(id) ON DELETE CASCADE,
          FOREIGN KEY (tile_id) REFERENCES tile_event_tiles(id) ON DELETE CASCADE
        )
      `).run();
      
      // Add unlock_keywords column to tiles if it doesn't exist
      // This stores keywords for OCR matching (comma-separated)
      try {
        await env.EVENT_TRACK_DB.prepare(`
          ALTER TABLE tile_event_tiles ADD COLUMN unlock_keywords TEXT
        `).run();
      } catch (e) {
        // Column already exists, ignore
      }
    };

    // --- GET /tile-events - List all tile events ---
    if (method === "GET" && url.pathname === "/tile-events") {
      try {
        await initTileEventTables();
        
        const result = await env.EVENT_TRACK_DB.prepare(`
          SELECT te.*, 
                 (SELECT COUNT(*) FROM tile_event_tiles WHERE event_id = te.id) as tile_count,
                 (SELECT COUNT(*) FROM tile_event_progress WHERE event_id = te.id) as participant_count
          FROM tile_events te
          ORDER BY te.is_active DESC, te.created_at DESC
        `).all();
        
        return new Response(JSON.stringify({ events: result.results || [] }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error fetching tile events:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- GET /tile-events/:id - Get a specific tile event with all tiles ---
    if (method === "GET" && url.pathname.match(/^\/tile-events\/\d+$/)) {
      const eventId = parseInt(url.pathname.split('/')[2]);
      
      try {
        await initTileEventTables();
        
        // Get event details
        const event = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM tile_events WHERE id = ?
        `).bind(eventId).first();
        
        if (!event) {
          return new Response(JSON.stringify({ error: "Event not found" }), {
            status: 404,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Get all tiles for this event
        const tiles = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM tile_event_tiles WHERE event_id = ? ORDER BY position ASC
        `).bind(eventId).all();
        
        return new Response(JSON.stringify({ 
          event, 
          tiles: tiles.results || [] 
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error fetching tile event:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- GET /tile-events/:id/progress - Get user's progress on an event ---
    if (method === "GET" && url.pathname.match(/^\/tile-events\/\d+\/progress$/)) {
      const eventId = parseInt(url.pathname.split('/')[2]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      
      if (!token) {
        return new Response(JSON.stringify({ error: "Authentication required" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const user = await verifyToken(token);
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid token" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        // Get progress for this user (don't auto-create)
        let progress = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM tile_event_progress WHERE event_id = ? AND discord_id = ?
        `).bind(eventId, user.userId).first();
        
        if (!progress) {
          // User hasn't joined this event
          return new Response(JSON.stringify({ 
            progress: null, 
            joined: false,
            message: "You haven't joined this event yet"
          }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Parse tiles_unlocked JSON
        progress.tiles_unlocked = JSON.parse(progress.tiles_unlocked || '[]');
        
        return new Response(JSON.stringify({ progress, joined: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error fetching progress:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- POST /tile-events/:id/join - Join an event ---
    if (method === "POST" && url.pathname.match(/^\/tile-events\/\d+\/join$/)) {
      const eventId = parseInt(url.pathname.split('/')[2]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      
      if (!token) {
        return new Response(JSON.stringify({ error: "Authentication required" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const user = await verifyToken(token);
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid token" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        // Check if event exists and is active
        const event = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM tile_events WHERE id = ?
        `).bind(eventId).first();
        
        if (!event) {
          return new Response(JSON.stringify({ error: "Event not found" }), {
            status: 404,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        if (!event.is_active) {
          return new Response(JSON.stringify({ error: "This event has ended" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Check if already joined
        const existing = await env.EVENT_TRACK_DB.prepare(`
          SELECT id FROM tile_event_progress WHERE event_id = ? AND discord_id = ?
        `).bind(eventId, user.userId).first();
        
        if (existing) {
          return new Response(JSON.stringify({ error: "You've already joined this event" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Create progress entry
        await env.EVENT_TRACK_DB.prepare(`
          INSERT INTO tile_event_progress (event_id, discord_id, discord_username, current_tile, tiles_unlocked)
          VALUES (?, ?, ?, 0, '[]')
        `).bind(eventId, user.userId, user.username).run();
        
        return new Response(JSON.stringify({ 
          success: true, 
          message: "Successfully joined the event!"
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error joining event:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- POST /tile-events/:id/leave - Leave an event ---
    if (method === "POST" && url.pathname.match(/^\/tile-events\/\d+\/leave$/)) {
      const eventId = parseInt(url.pathname.split('/')[2]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      
      if (!token) {
        return new Response(JSON.stringify({ error: "Authentication required" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const user = await verifyToken(token);
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid token" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        await env.EVENT_TRACK_DB.prepare(`
          DELETE FROM tile_event_progress WHERE event_id = ? AND discord_id = ?
        `).bind(eventId, user.userId).run();
        
        return new Response(JSON.stringify({ 
          success: true, 
          message: "Left the event"
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error leaving event:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // ========================================
    // TILE SUBMISSION SYSTEM (Screenshot Verification)
    // ========================================
    
    // --- POST /tile-events/:eventId/tiles/:tileId/submit - Submit proof screenshot ---
    if (method === "POST" && url.pathname.match(/^\/tile-events\/\d+\/tiles\/\d+\/submit$/)) {
      const parts = url.pathname.split('/');
      const eventId = parseInt(parts[2]);
      const tileId = parseInt(parts[4]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      
      if (!token) {
        return new Response(JSON.stringify({ error: "Authentication required" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const user = await verifyToken(token);
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid token" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        // Check if user has joined this event
        const progress = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM tile_event_progress WHERE event_id = ? AND discord_id = ?
        `).bind(eventId, user.userId).first();
        
        if (!progress) {
          return new Response(JSON.stringify({ error: "You must join the event first" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Get tile info
        const tile = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM tile_event_tiles WHERE id = ? AND event_id = ?
        `).bind(tileId, eventId).first();
        
        if (!tile) {
          return new Response(JSON.stringify({ error: "Tile not found" }), {
            status: 404,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Check if user already has this tile unlocked
        const unlockedTiles = JSON.parse(progress.tiles_unlocked || '[]');
        if (unlockedTiles.includes(tile.position)) {
          return new Response(JSON.stringify({ error: "You've already completed this tile" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Check if this is the next tile to unlock
        const canUnlock = tile.position === 0 || unlockedTiles.includes(tile.position - 1);
        if (!canUnlock) {
          return new Response(JSON.stringify({ error: "You must complete the previous tile first" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Check for pending submission
        const pendingSubmission = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM tile_submissions 
          WHERE event_id = ? AND tile_id = ? AND discord_id = ? AND status = 'pending'
        `).bind(eventId, tileId, user.userId).first();
        
        if (pendingSubmission) {
          return new Response(JSON.stringify({ error: "You already have a pending submission for this tile" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Parse multipart form data for image upload
        const contentType = request.headers.get("Content-Type") || "";
        if (!contentType.includes("multipart/form-data")) {
          return new Response(JSON.stringify({ error: "Must upload as multipart/form-data" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        const formData = await request.formData();
        const imageFile = formData.get("image");
        
        if (!imageFile || !(imageFile instanceof File)) {
          return new Response(JSON.stringify({ error: "No image file uploaded" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Validate file type
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        if (!allowedTypes.includes(imageFile.type)) {
          return new Response(JSON.stringify({ error: "Invalid file type. Allowed: JPEG, PNG, WebP, GIF" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Limit file size (5MB for storage)
        if (imageFile.size > 5 * 1024 * 1024) {
          return new Response(JSON.stringify({ error: "File too large. Max 5MB" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Check if image is small enough for AI processing (1MB limit for Workers AI)
        const MAX_AI_IMAGE_SIZE = 1024 * 1024; // 1MB
        const canRunAI = imageFile.size <= MAX_AI_IMAGE_SIZE;
        
        // Generate unique key for R2 storage
        const ext = imageFile.name.split('.').pop() || 'png';
        const imageKey = `submissions/${eventId}/${user.userId}/${tileId}_${Date.now()}.${ext}`;
        
        // Upload to R2
        const imageBuffer = await imageFile.arrayBuffer();
        await env.SUBMISSIONS_BUCKET.put(imageKey, imageBuffer, {
          httpMetadata: { contentType: imageFile.type }
        });
        
        // Generate secure API URL for the image (served through authenticated endpoint)
        // Note: imageKey already includes 'submissions/' prefix, so we just use /r2/ as the endpoint
        const apiOrigin = url.origin;
        const imageUrl = `${apiOrigin}/r2/${imageKey}`;
        
        // Run OCR to extract text from the image
        let ocrText = null;
        let aiConfidence = null;
        let aiResult = null;
        let autoApproved = false;
        
        // Try OCR.space first (dedicated OCR service, more accurate)
        // Fall back to LLaVA if OCR.space not configured
        if (env.OCR_SPACE_API_KEY && canRunAI) {
          try {
            console.log("Running OCR.space text extraction...");
            
            // Convert image to base64 for OCR.space API
            const base64Image = btoa(String.fromCharCode(...new Uint8Array(imageBuffer)));
            
            const ocrFormData = new FormData();
            ocrFormData.append('base64Image', `data:${imageFile.type};base64,${base64Image}`);
            ocrFormData.append('language', 'eng');
            ocrFormData.append('isOverlayRequired', 'false');
            ocrFormData.append('detectOrientation', 'true');
            ocrFormData.append('scale', 'true');
            ocrFormData.append('OCREngine', '2'); // Engine 2 is better for screenshots
            
            const ocrResponse = await fetch('https://api.ocr.space/parse/image', {
              method: 'POST',
              headers: {
                'apikey': env.OCR_SPACE_API_KEY
              },
              body: ocrFormData
            });
            
            const ocrData = await ocrResponse.json();
            console.log("OCR.space response:", JSON.stringify(ocrData));
            
            if (ocrData.ParsedResults && ocrData.ParsedResults.length > 0) {
              ocrText = ocrData.ParsedResults.map(r => r.ParsedText).join('\n');
              aiResult = 'ocrspace_extracted';
            } else if (ocrData.ErrorMessage) {
              console.error("OCR.space error:", ocrData.ErrorMessage);
              aiResult = `ocrspace_error: ${ocrData.ErrorMessage}`;
            }
          } catch (ocrErr) {
            console.error("OCR.space failed:", ocrErr);
            aiResult = `ocrspace_error: ${ocrErr.message}`;
          }
        }
        // Fallback to LLaVA if OCR.space didn't work or not configured
        else if (env.AI && canRunAI) {
          try {
            console.log("Running LLaVA OCR text extraction (fallback)...");
            
            const ocrPrompt = `Read all the text visible in this image. Output only the exact text you can see, one line at a time. Do not describe the image.`;
            
            const visionResponse = await env.AI.run("@cf/llava-hf/llava-1.5-7b-hf", {
              prompt: ocrPrompt,
              image: [...new Uint8Array(imageBuffer)]
            });
            
            console.log("LLaVA response:", JSON.stringify(visionResponse));
            
            if (visionResponse && (visionResponse.response || visionResponse.description)) {
              ocrText = visionResponse.response || visionResponse.description;
              aiResult = 'llava_extracted';
            }
          } catch (aiErr) {
            console.error("LLaVA failed:", aiErr);
            aiResult = `llava_error: ${aiErr.message}`;
          }
        }
        
        // Process extracted text for keyword matching
        if (ocrText && tile.unlock_keywords) {
          const ocrLower = ocrText.toLowerCase();
          const rawKeywords = tile.unlock_keywords.split(',').map(k => k.trim()).filter(k => k);
          
          // Parse keyword modifiers
          let requireAll = false;
          const keywords = [];
          const exactPhrases = [];
          
          for (const kw of rawKeywords) {
            const kwLower = kw.toLowerCase();
            if (kwLower.startsWith('all:')) {
              requireAll = true;
            } else if (kwLower.startsWith('exact:')) {
              exactPhrases.push(kwLower.replace('exact:', '').trim());
            } else {
              keywords.push(kwLower);
            }
          }
          
          // Check exact phrase matches
          const exactMatches = exactPhrases.filter(phrase => ocrLower.includes(phrase));
          
          // Check keyword matches (must be whole words, not partial)
          const keywordMatches = keywords.filter(keyword => {
            const regex = new RegExp(`\\b${keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
            return regex.test(ocrText);
          });
          
          const allMatches = [...exactMatches, ...keywordMatches];
          const totalKeywords = exactPhrases.length + keywords.length;
          
          // Calculate confidence
          aiConfidence = totalKeywords > 0 ? allMatches.length / totalKeywords : 0;
          aiResult = allMatches.length > 0 
            ? `match: ${allMatches.join(', ')}` 
            : 'no_match';
          
          console.log(`OCR keyword matching: ${allMatches.length}/${totalKeywords} (requireAll: ${requireAll})`);
          console.log(`Matched: [${allMatches.join(', ')}]`);
          
          // Auto-approve logic:
          // - If "all:" prefix used, ALL keywords must match
          // - Otherwise, at least one match required
          if (requireAll) {
            autoApproved = allMatches.length === totalKeywords;
          } else {
            autoApproved = allMatches.length > 0;
          }
          
          if (autoApproved) {
            console.log("Auto-approving based on OCR text match");
          }
        } else if (!canRunAI) {
          console.log(`Image too large for OCR (${Math.round(imageFile.size / 1024)}KB), skipping auto-scan`);
          aiResult = 'image_too_large';
        } else if (!env.OCR_SPACE_API_KEY && !env.AI) {
          console.log("No OCR service available, skipping auto-scan");
          aiResult = 'ocr_unavailable';
        }
        
        // Create submission record
        const status = autoApproved ? 'approved' : 'pending';
        await env.EVENT_TRACK_DB.prepare(`
          INSERT INTO tile_submissions (
            event_id, tile_id, discord_id, discord_username, 
            image_key, image_url, status, ocr_text, ai_confidence, ai_result
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          eventId, tileId, user.userId, user.username,
          imageKey, imageUrl, status, ocrText, aiConfidence, aiResult
        ).run();
        
        // If auto-approved, unlock the tile for the user
        if (autoApproved) {
          unlockedTiles.push(tile.position);
          const newCurrentTile = Math.max(...unlockedTiles, 0);
          
          // Check if completed
          const totalTiles = await env.EVENT_TRACK_DB.prepare(`
            SELECT COUNT(*) as count FROM tile_event_tiles WHERE event_id = ?
          `).bind(eventId).first();
          
          const completedAt = unlockedTiles.length >= (totalTiles?.count || 0) 
            ? new Date().toISOString() 
            : null;
          
          await env.EVENT_TRACK_DB.prepare(`
            UPDATE tile_event_progress 
            SET tiles_unlocked = ?, current_tile = ?, completed_at = ?, updated_at = CURRENT_TIMESTAMP
            WHERE event_id = ? AND discord_id = ?
          `).bind(JSON.stringify(unlockedTiles), newCurrentTile, completedAt, eventId, user.userId).run();
        }
        
        return new Response(JSON.stringify({ 
          success: true,
          submission_id: (await env.EVENT_TRACK_DB.prepare(`SELECT last_insert_rowid() as id`).first())?.id,
          status: status,
          auto_approved: autoApproved,
          ai_confidence: aiConfidence,
          message: autoApproved 
            ? "Submission approved! Tile unlocked." 
            : "Submission received. Awaiting admin review."
        }), {
          status: 201,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
        
      } catch (err) {
        console.error("Error submitting proof:", err);
        await logError({
          endpoint: url.pathname,
          method,
          errorType: 'submission',
          errorMessage: err.message,
          stackTrace: err.stack,
          userId: user?.userId,
          ipAddress: request.headers.get('CF-Connecting-IP')
        });
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    
    // --- GET /tile-events/:eventId/submissions - Get user's submissions for an event ---
    if (method === "GET" && url.pathname.match(/^\/tile-events\/\d+\/submissions$/)) {
      const eventId = parseInt(url.pathname.split('/')[2]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      
      if (!token) {
        return new Response(JSON.stringify({ error: "Authentication required" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const user = await verifyToken(token);
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid token" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        const submissions = await env.EVENT_TRACK_DB.prepare(`
          SELECT ts.*, t.title as tile_title, t.position as tile_position
          FROM tile_submissions ts
          JOIN tile_event_tiles t ON ts.tile_id = t.id
          WHERE ts.event_id = ? AND ts.discord_id = ?
          ORDER BY ts.created_at DESC
        `).bind(eventId, user.userId).all();
        
        return new Response(JSON.stringify({ submissions: submissions.results || [] }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error fetching submissions:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    
    // --- Admin: GET /admin/tile-events/:eventId/submissions - Get all submissions for review ---
    if (method === "GET" && url.pathname.match(/^\/admin\/tile-events\/\d+\/submissions$/)) {
      const eventId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !(await hasAccess(user.userId, 'events'))) {
        return new Response(JSON.stringify({ error: "Events admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        // Get query params for filtering
        const status = url.searchParams.get('status') || '';
        const limit = parseInt(url.searchParams.get('limit') || '50');
        const offset = parseInt(url.searchParams.get('offset') || '0');
        
        let query = `
          SELECT ts.*, t.title as tile_title, t.position as tile_position,
                 au.global_name, au.avatar
          FROM tile_submissions ts
          JOIN tile_event_tiles t ON ts.tile_id = t.id
          LEFT JOIN admin_users au ON ts.discord_id = au.discord_id
          WHERE ts.event_id = ?
        `;
        const bindings = [eventId];
        
        if (status) {
          query += ` AND ts.status = ?`;
          bindings.push(status);
        }
        
        query += ` ORDER BY ts.created_at DESC LIMIT ? OFFSET ?`;
        bindings.push(limit, offset);
        
        const submissions = await env.EVENT_TRACK_DB.prepare(query).bind(...bindings).all();
        
        // Get counts
        const counts = await env.EVENT_TRACK_DB.prepare(`
          SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
            SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
          FROM tile_submissions WHERE event_id = ?
        `).bind(eventId).first();
        
        return new Response(JSON.stringify({ 
          submissions: submissions.results || [],
          counts
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error fetching admin submissions:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    
    // --- Admin: PUT /admin/tile-events/submissions/:submissionId - Review a submission ---
    if (method === "PUT" && url.pathname.match(/^\/admin\/tile-events\/submissions\/\d+$/)) {
      const submissionId = parseInt(url.pathname.split('/')[4]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const adminUser = token ? await verifyToken(token) : null;
      
      if (!adminUser || !(await hasAccess(adminUser.userId, 'events'))) {
        return new Response(JSON.stringify({ error: "Events admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        const body = await request.json();
        const { status, notes } = body; // status: 'approved' | 'rejected'
        
        if (!['approved', 'rejected'].includes(status)) {
          return new Response(JSON.stringify({ error: "Status must be 'approved' or 'rejected'" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Get submission details
        const submission = await env.EVENT_TRACK_DB.prepare(`
          SELECT ts.*, t.position as tile_position
          FROM tile_submissions ts
          JOIN tile_event_tiles t ON ts.tile_id = t.id
          WHERE ts.id = ?
        `).bind(submissionId).first();
        
        if (!submission) {
          return new Response(JSON.stringify({ error: "Submission not found" }), {
            status: 404,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Update submission status
        await env.EVENT_TRACK_DB.prepare(`
          UPDATE tile_submissions 
          SET status = ?, admin_notes = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(status, notes || null, adminUser.userId, submissionId).run();
        
        // If approved, unlock the tile for the user
        if (status === 'approved') {
          const progress = await env.EVENT_TRACK_DB.prepare(`
            SELECT * FROM tile_event_progress WHERE event_id = ? AND discord_id = ?
          `).bind(submission.event_id, submission.discord_id).first();
          
          if (progress) {
            const unlockedTiles = JSON.parse(progress.tiles_unlocked || '[]');
            
            if (!unlockedTiles.includes(submission.tile_position)) {
              unlockedTiles.push(submission.tile_position);
              const newCurrentTile = Math.max(...unlockedTiles, 0);
              
              // Check if completed
              const totalTiles = await env.EVENT_TRACK_DB.prepare(`
                SELECT COUNT(*) as count FROM tile_event_tiles WHERE event_id = ?
              `).bind(submission.event_id).first();
              
              const completedAt = unlockedTiles.length >= (totalTiles?.count || 0) 
                ? new Date().toISOString() 
                : null;
              
              await env.EVENT_TRACK_DB.prepare(`
                UPDATE tile_event_progress 
                SET tiles_unlocked = ?, current_tile = ?, completed_at = ?, updated_at = CURRENT_TIMESTAMP
                WHERE event_id = ? AND discord_id = ?
              `).bind(JSON.stringify(unlockedTiles), newCurrentTile, completedAt, submission.event_id, submission.discord_id).run();
            }
          }
        }
        
        return new Response(JSON.stringify({ 
          success: true,
          message: `Submission ${status}`
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error reviewing submission:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }
    
    // --- Admin: DELETE /admin/tile-events/submissions/:submissionId - Delete a submission ---
    if (method === "DELETE" && url.pathname.match(/^\/admin\/tile-events\/submissions\/\d+$/)) {
      const submissionId = parseInt(url.pathname.split('/')[4]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const adminUser = token ? await verifyToken(token) : null;
      
      if (!adminUser || !(await hasAccess(adminUser.userId, 'events'))) {
        return new Response(JSON.stringify({ error: "Events admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        // Get submission to delete image from R2
        const submission = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM tile_submissions WHERE id = ?
        `).bind(submissionId).first();
        
        if (!submission) {
          return new Response(JSON.stringify({ error: "Submission not found" }), {
            status: 404,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Delete from R2
        if (submission.image_key) {
          try {
            await env.SUBMISSIONS_BUCKET.delete(submission.image_key);
          } catch (r2Err) {
            console.log("Failed to delete R2 object:", r2Err.message);
          }
        }
        
        // Delete submission record
        await env.EVENT_TRACK_DB.prepare(`DELETE FROM tile_submissions WHERE id = ?`).bind(submissionId).run();
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error deleting submission:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin: DELETE /admin/tile-events/:id/participants/:discordId - Remove a participant ---
    if (method === "DELETE" && url.pathname.match(/^\/admin\/tile-events\/\d+\/participants\/\d+$/)) {
      const parts = url.pathname.split('/');
      const eventId = parseInt(parts[3]);
      const discordId = parts[5];
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !await hasAccess(user.userId, 'events')) {
        return new Response(JSON.stringify({ error: "Events access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        const result = await env.EVENT_TRACK_DB.prepare(`
          DELETE FROM tile_event_progress WHERE event_id = ? AND discord_id = ?
        `).bind(eventId, discordId).run();
        
        return new Response(JSON.stringify({ 
          success: true,
          removed: result.meta.changes > 0
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error removing participant:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin: POST /admin/tile-events - Create a new tile event ---
    if (method === "POST" && url.pathname === "/admin/tile-events") {
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      // Debug logging
      console.log("Create tile event - token exists:", !!token);
      console.log("Create tile event - user:", user ? { userId: user.userId } : null);
      console.log("Create tile event - ADMIN_USER_IDS:", ADMIN_USER_IDS);
      console.log("Create tile event - is in admin list:", user ? ADMIN_USER_IDS.includes(user.userId) : false);
      
      if (!user || !await hasAccess(user.userId, 'events')) {
        return new Response(JSON.stringify({ 
          error: "Admin access required",
          debug: { hasToken: !!token, hasUser: !!user, userId: user?.userId }
        }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        const body = await request.json();
        
        const name = sanitizeString(body.name || '', 200);
        const description = sanitizeString(body.description || '', 1000);
        const googleSheetId = sanitizeString(body.google_sheet_id || '', 100);
        const googleSheetTab = sanitizeString(body.google_sheet_tab || '', 100);
        
        if (!name) {
          return new Response(JSON.stringify({ error: "Name is required" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        const result = await env.EVENT_TRACK_DB.prepare(`
          INSERT INTO tile_events (name, description, google_sheet_id, google_sheet_tab, created_by)
          VALUES (?, ?, ?, ?, ?)
        `).bind(name, description, googleSheetId, googleSheetTab, user.userId).run();
        
        return new Response(JSON.stringify({ 
          success: true, 
          eventId: result.meta.last_row_id 
        }), {
          status: 201,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error creating tile event:", err);
        await logError({
          endpoint: "/admin/tile-events",
          errorType: "db",
          errorMessage: err.message,
          stackTrace: err.stack,
          userId: user?.userId
        });
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin: PUT /admin/tile-events/:id - Update a tile event ---
    if (method === "PUT" && url.pathname.match(/^\/admin\/tile-events\/\d+$/)) {
      const eventId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !await hasAccess(user.userId, 'events')) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        const body = await request.json();
        
        const name = sanitizeString(body.name || '', 200);
        const description = sanitizeString(body.description || '', 1000);
        const isActive = body.is_active ? 1 : 0;
        const googleSheetId = sanitizeString(body.google_sheet_id || '', 100);
        const googleSheetTab = sanitizeString(body.google_sheet_tab || '', 100);
        
        await env.EVENT_TRACK_DB.prepare(`
          UPDATE tile_events 
          SET name = ?, description = ?, is_active = ?, google_sheet_id = ?, google_sheet_tab = ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).bind(name, description, isActive, googleSheetId, googleSheetTab, eventId).run();
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error updating tile event:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin: DELETE /admin/tile-events/:id - Delete a tile event ---
    if (method === "DELETE" && url.pathname.match(/^\/admin\/tile-events\/\d+$/)) {
      const eventId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !await hasAccess(user.userId, 'events')) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        // Delete progress first
        await env.EVENT_TRACK_DB.prepare(`DELETE FROM tile_event_progress WHERE event_id = ?`).bind(eventId).run();
        // Delete tiles
        await env.EVENT_TRACK_DB.prepare(`DELETE FROM tile_event_tiles WHERE event_id = ?`).bind(eventId).run();
        // Delete event
        await env.EVENT_TRACK_DB.prepare(`DELETE FROM tile_events WHERE id = ?`).bind(eventId).run();
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error deleting tile event:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin: POST /admin/tile-events/:id/tiles - Add tiles to an event ---
    if (method === "POST" && url.pathname.match(/^\/admin\/tile-events\/\d+\/tiles$/)) {
      const eventId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !await hasAccess(user.userId, 'events')) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        const body = await request.json();
        
        // Body can be a single tile or array of tiles
        const tiles = Array.isArray(body) ? body : [body];
        
        for (const tile of tiles) {
          const position = parseInt(tile.position) || 0;
          const title = sanitizeString(tile.title || '', 200);
          const description = sanitizeString(tile.description || '', 500);
          const imageUrl = sanitizeString(tile.image_url || '', 500);
          const reward = sanitizeString(tile.reward || '', 200);
          const unlockKeywords = sanitizeString(tile.unlock_keywords || '', 500);
          const isStart = tile.is_start ? 1 : 0;
          const isEnd = tile.is_end ? 1 : 0;
          
          await env.EVENT_TRACK_DB.prepare(`
            INSERT INTO tile_event_tiles (event_id, position, title, description, image_url, reward, is_start, is_end, unlock_keywords)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(eventId, position, title, description, imageUrl, reward, isStart, isEnd, unlockKeywords).run();
        }
        
        return new Response(JSON.stringify({ success: true, count: tiles.length }), {
          status: 201,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error adding tiles:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin: PUT /admin/tile-events/:id/tiles/bulk - Replace all tiles ---
    if (method === "PUT" && url.pathname.match(/^\/admin\/tile-events\/\d+\/tiles\/bulk$/)) {
      const eventId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !await hasAccess(user.userId, 'events')) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        const body = await request.json();
        const tiles = Array.isArray(body.tiles) ? body.tiles : [];
        
        // Delete existing tiles
        await env.EVENT_TRACK_DB.prepare(`DELETE FROM tile_event_tiles WHERE event_id = ?`).bind(eventId).run();
        
        // Insert new tiles
        for (let i = 0; i < tiles.length; i++) {
          const tile = tiles[i];
          const position = i;
          const title = sanitizeString(tile.title || '', 200);
          const description = sanitizeString(tile.description || '', 500);
          const imageUrl = sanitizeString(tile.image_url || '', 500);
          const reward = sanitizeString(tile.reward || '', 200);
          const unlockKeywords = sanitizeString(tile.unlock_keywords || '', 500);
          const isStart = i === 0 ? 1 : 0;
          const isEnd = i === tiles.length - 1 ? 1 : 0;
          
          await env.EVENT_TRACK_DB.prepare(`
            INSERT INTO tile_event_tiles (event_id, position, title, description, image_url, reward, is_start, is_end, unlock_keywords)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(eventId, position, title, description, imageUrl, reward, isStart, isEnd, unlockKeywords).run();
        }
        
        return new Response(JSON.stringify({ success: true, count: tiles.length }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error bulk updating tiles:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin: GET /admin/tile-events/:id/participants - Get all participants ---
    if (method === "GET" && url.pathname.match(/^\/admin\/tile-events\/\d+\/participants$/)) {
      const eventId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !await hasAccess(user.userId, 'events')) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        const participants = await env.EVENT_TRACK_DB.prepare(`
          SELECT tep.*, au.username, au.global_name, au.avatar
          FROM tile_event_progress tep
          LEFT JOIN admin_users au ON tep.discord_id = au.discord_id
          WHERE tep.event_id = ?
          ORDER BY tep.current_tile DESC, tep.updated_at DESC
        `).bind(eventId).all();
        
        // Parse tiles_unlocked for each participant
        const parsed = (participants.results || []).map(p => ({
          ...p,
          tiles_unlocked: JSON.parse(p.tiles_unlocked || '[]')
        }));
        
        return new Response(JSON.stringify({ participants: parsed }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error fetching participants:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin: POST /admin/tile-events/:id/unlock - Unlock tile(s) for a user ---
    if (method === "POST" && url.pathname.match(/^\/admin\/tile-events\/\d+\/unlock$/)) {
      const eventId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !await hasAccess(user.userId, 'events')) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        const body = await request.json();
        
        const targetUserId = sanitizeString(body.discord_id || '', 30);
        const tilePosition = parseInt(body.tile_position);
        
        if (!targetUserId || isNaN(tilePosition)) {
          return new Response(JSON.stringify({ error: "discord_id and tile_position required" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Get current progress
        let progress = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM tile_event_progress WHERE event_id = ? AND discord_id = ?
        `).bind(eventId, targetUserId).first();
        
        if (!progress) {
          // Create initial progress
          await env.EVENT_TRACK_DB.prepare(`
            INSERT INTO tile_event_progress (event_id, discord_id, discord_username, current_tile, tiles_unlocked)
            VALUES (?, ?, ?, 0, '[]')
          `).bind(eventId, targetUserId, body.username || 'Unknown').run();
          
          progress = { tiles_unlocked: '[]', current_tile: 0 };
        }
        
        // Parse and update unlocked tiles
        let unlockedTiles = JSON.parse(progress.tiles_unlocked || '[]');
        if (!unlockedTiles.includes(tilePosition)) {
          unlockedTiles.push(tilePosition);
          unlockedTiles.sort((a, b) => a - b);
        }
        
        // Update current_tile to the highest unlocked
        const newCurrentTile = Math.max(...unlockedTiles, 0);
        
        // Check if event is completed (all tiles unlocked)
        const totalTiles = await env.EVENT_TRACK_DB.prepare(`
          SELECT COUNT(*) as count FROM tile_event_tiles WHERE event_id = ?
        `).bind(eventId).first();
        
        const completedAt = unlockedTiles.length >= (totalTiles?.count || 0) 
          ? new Date().toISOString() 
          : null;
        
        await env.EVENT_TRACK_DB.prepare(`
          UPDATE tile_event_progress 
          SET tiles_unlocked = ?, current_tile = ?, completed_at = ?, updated_at = CURRENT_TIMESTAMP
          WHERE event_id = ? AND discord_id = ?
        `).bind(JSON.stringify(unlockedTiles), newCurrentTile, completedAt, eventId, targetUserId).run();
        
        return new Response(JSON.stringify({ 
          success: true, 
          tiles_unlocked: unlockedTiles,
          current_tile: newCurrentTile,
          completed: !!completedAt
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error unlocking tile:", err);
        await logError({
          endpoint: url.pathname,
          errorType: "db",
          errorMessage: err.message,
          stackTrace: err.stack,
          userId: user?.userId
        });
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin: POST /admin/tile-events/:id/reset-user - Reset a user's progress ---
    if (method === "POST" && url.pathname.match(/^\/admin\/tile-events\/\d+\/reset-user$/)) {
      const eventId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !await hasAccess(user.userId, 'events')) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        const body = await request.json();
        
        const targetUserId = sanitizeString(body.discord_id || '', 30);
        
        if (!targetUserId) {
          return new Response(JSON.stringify({ error: "discord_id required" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        await env.EVENT_TRACK_DB.prepare(`
          UPDATE tile_event_progress 
          SET tiles_unlocked = '[]', current_tile = 0, completed_at = NULL, updated_at = CURRENT_TIMESTAMP
          WHERE event_id = ? AND discord_id = ?
        `).bind(eventId, targetUserId).run();
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error resetting user progress:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Admin: POST /admin/tile-events/:id/sync-sheet - Sync tiles from Google Sheet ---
    if (method === "POST" && url.pathname.match(/^\/admin\/tile-events\/\d+\/sync-sheet$/)) {
      const eventId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !await hasAccess(user.userId, 'events')) {
        return new Response(JSON.stringify({ error: "Events access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initTileEventTables();
        
        // Get event details including sheet info
        const event = await env.EVENT_TRACK_DB.prepare(`
          SELECT * FROM tile_events WHERE id = ?
        `).bind(eventId).first();
        
        if (!event) {
          return new Response(JSON.stringify({ error: "Event not found" }), {
            status: 404,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Check if sheet is configured
        if (!event.google_sheet_id || !event.google_sheet_tab) {
          return new Response(JSON.stringify({ 
            error: "Google Sheet not configured. Set sheet ID and tab name first." 
          }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Read from public Google Sheet (no credentials needed)
        const rows = await readGoogleSheetPublic(event.google_sheet_id, event.google_sheet_tab);
        
        if (rows.length === 0) {
          return new Response(JSON.stringify({ 
            error: "Sheet is empty or not found",
            sheetId: event.google_sheet_id,
            tab: event.google_sheet_tab
          }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Skip header row if it looks like headers
        const firstRow = rows[0];
        const hasHeaders = firstRow[0]?.toLowerCase().includes('title') || 
                          firstRow[0]?.toLowerCase().includes('name') ||
                          firstRow[0]?.toLowerCase() === 'tile';
        const dataRows = hasHeaders ? rows.slice(1) : rows;
        
        // Delete existing tiles
        await env.EVENT_TRACK_DB.prepare(`DELETE FROM tile_event_tiles WHERE event_id = ?`).bind(eventId).run();
        
        // Insert tiles from sheet
        // Expected columns: A=Title, B=Description, C=ImageURL, D=Reward, E=Keywords (for AI auto-approval)
        let insertedCount = 0;
        for (let i = 0; i < dataRows.length; i++) {
          const row = dataRows[i];
          const title = sanitizeString(row[0] || '', 200);
          
          // Skip empty rows
          if (!title) continue;
          
          const description = sanitizeString(row[1] || '', 500);
          const imageUrl = sanitizeString(row[2] || '', 500);
          const reward = sanitizeString(row[3] || '', 200);
          const unlockKeywords = sanitizeString(row[4] || '', 500);
          const isStart = i === 0 ? 1 : 0;
          const isEnd = i === dataRows.length - 1 ? 1 : 0;
          
          await env.EVENT_TRACK_DB.prepare(`
            INSERT INTO tile_event_tiles (event_id, position, title, description, image_url, reward, is_start, is_end, unlock_keywords)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(eventId, i, title, description, imageUrl, reward, isStart, isEnd, unlockKeywords).run();
          
          insertedCount++;
        }
        
        return new Response(JSON.stringify({ 
          success: true, 
          message: `Synced ${insertedCount} tiles from Google Sheet`,
          tilesImported: insertedCount
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error syncing from sheet:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // ==========================================================================
    // ERROR LOG ADMIN ENDPOINTS
    // ==========================================================================

    // --- GET /admin/error-logs - View error logs ---
    if (method === "GET" && url.pathname === "/admin/error-logs") {
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await initErrorLogTable();
        
        // Parse query params
        const limit = parseInt(url.searchParams.get("limit")) || 50;
        const offset = parseInt(url.searchParams.get("offset")) || 0;
        const errorType = url.searchParams.get("type") || null;
        const resolved = url.searchParams.get("resolved");
        const startDate = url.searchParams.get("start") || null;
        const endDate = url.searchParams.get("end") || null;
        
        // Build query with filters
        let query = `SELECT * FROM error_logs WHERE 1=1`;
        const params = [];
        
        if (errorType) {
          query += ` AND error_type = ?`;
          params.push(errorType);
        }
        
        if (resolved !== null && resolved !== "") {
          query += ` AND resolved = ?`;
          params.push(resolved === "true" ? 1 : 0);
        }
        
        if (startDate) {
          query += ` AND timestamp >= ?`;
          params.push(startDate);
        }
        
        if (endDate) {
          query += ` AND timestamp <= ?`;
          params.push(endDate);
        }
        
        query += ` ORDER BY timestamp DESC LIMIT ? OFFSET ?`;
        params.push(limit, offset);
        
        const result = await env.EVENT_TRACK_DB.prepare(query).bind(...params).all();
        
        // Get total count for pagination
        let countQuery = `SELECT COUNT(*) as total FROM error_logs WHERE 1=1`;
        const countParams = [];
        if (errorType) {
          countQuery += ` AND error_type = ?`;
          countParams.push(errorType);
        }
        if (resolved !== null && resolved !== "") {
          countQuery += ` AND resolved = ?`;
          countParams.push(resolved === "true" ? 1 : 0);
        }
        
        const countResult = await env.EVENT_TRACK_DB.prepare(countQuery)
          .bind(...countParams).first();
        
        // Get error type summary
        const typeSummary = await env.EVENT_TRACK_DB.prepare(`
          SELECT error_type, COUNT(*) as count, 
                 SUM(CASE WHEN resolved = 0 THEN 1 ELSE 0 END) as unresolved
          FROM error_logs 
          GROUP BY error_type 
          ORDER BY count DESC
        `).all();
        
        return new Response(JSON.stringify({
          logs: result.results || [],
          total: countResult?.total || 0,
          limit,
          offset,
          summary: typeSummary.results || []
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error fetching error logs:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- PUT /admin/error-logs/:id - Update error log (mark resolved, add notes) ---
    if (method === "PUT" && url.pathname.match(/^\/admin\/error-logs\/\d+$/)) {
      const logId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        const body = await request.json();
        const { resolved, notes } = body;
        
        await env.EVENT_TRACK_DB.prepare(`
          UPDATE error_logs SET resolved = ?, notes = ? WHERE id = ?
        `).bind(resolved ? 1 : 0, notes || null, logId).run();
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error updating error log:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- DELETE /admin/error-logs/:id - Delete a single error log ---
    if (method === "DELETE" && url.pathname.match(/^\/admin\/error-logs\/\d+$/)) {
      const logId = parseInt(url.pathname.split('/')[3]);
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        await env.EVENT_TRACK_DB.prepare(`DELETE FROM error_logs WHERE id = ?`).bind(logId).run();
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error deleting error log:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- DELETE /admin/error-logs - Clear resolved logs or all logs ---
    if (method === "DELETE" && url.pathname === "/admin/error-logs") {
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user || !ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        const clearAll = url.searchParams.get("all") === "true";
        
        if (clearAll) {
          await env.EVENT_TRACK_DB.prepare(`DELETE FROM error_logs`).run();
        } else {
          // Only clear resolved logs
          await env.EVENT_TRACK_DB.prepare(`DELETE FROM error_logs WHERE resolved = 1`).run();
        }
        
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err) {
        console.error("Error clearing error logs:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // ========================================
    // AI DEBUG ENDPOINT
    // ========================================
    
    /**
     * POST /admin/ai-debug/scan - Test AI image scanning without saving
     * 
     * Allows admins to test AI scanning on images to:
     * - See what text the AI extracts
     * - Test keyword matching
     * - Tune keywords before setting them on tiles
     * 
     * @body FormData with 'image' file and optional 'keywords' string
     * @returns OCR text, matched keywords, confidence score
     */
    if (method === "POST" && url.pathname === "/admin/ai-debug/scan") {
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      // Only allow admins
      if (!user || !ADMIN_USER_IDS.includes(user.userId)) {
        return new Response(JSON.stringify({ error: "Admin access required" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        // Parse multipart form data
        const contentType = request.headers.get("Content-Type") || "";
        if (!contentType.includes("multipart/form-data")) {
          return new Response(JSON.stringify({ error: "Must upload as multipart/form-data" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        const formData = await request.formData();
        const imageFile = formData.get("image");
        const keywords = formData.get("keywords")?.toString() || "";
        const promptStyle = formData.get("promptStyle")?.toString() || "ocr";
        
        if (!imageFile || !(imageFile instanceof File)) {
          return new Response(JSON.stringify({ error: "No image file provided" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Check file size - Workers AI limit is ~1MB for vision models
        const MAX_AI_IMAGE_SIZE = 1024 * 1024; // 1MB
        if (imageFile.size > MAX_AI_IMAGE_SIZE) {
          return new Response(JSON.stringify({ 
            error: `Image too large for AI (${(imageFile.size / 1024 / 1024).toFixed(2)}MB). Max: 1MB. Please resize or compress your image.`,
            suggestion: "Try using a tool like https://squoosh.app to compress your image to under 1MB"
          }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Read image data
        const imageBuffer = await imageFile.arrayBuffer();
        
        let ocrText = null;
        let aiConfidence = null;
        let aiResult = null;
        let matchedKeywords = [];
        let allKeywords = [];
        let rawResponse = null;
        let promptUsed = '';
        
        // Parse keywords with special prefixes
        // "exact:" for exact phrase match
        // "all:" to require ALL keywords
        let requireAll = false;
        const exactPhrases = [];
        const regularKeywords = [];
        
        if (keywords.trim()) {
          const rawKeywords = keywords.split(',').map(k => k.trim()).filter(k => k);
          for (const kw of rawKeywords) {
            const kwLower = kw.toLowerCase();
            if (kwLower.startsWith('all:')) {
              requireAll = true;
            } else if (kwLower.startsWith('exact:')) {
              exactPhrases.push(kwLower.replace('exact:', '').trim());
            } else {
              regularKeywords.push(kwLower);
            }
          }
          allKeywords = [...exactPhrases.map(p => `exact:${p}`), ...regularKeywords];
        }
        
        const imageSizeKB = Math.round(imageFile.size / 1024);
        let serviceUsed = promptStyle;
        
        // OCR.space - Dedicated OCR service (recommended)
        if (promptStyle === 'ocrspace') {
          if (!env.OCR_SPACE_API_KEY) {
            return new Response(JSON.stringify({ 
              error: "OCR.space API key not configured",
              suggestion: "Set OCR_SPACE_API_KEY secret: npx wrangler secret put OCR_SPACE_API_KEY"
            }), {
              status: 500,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
          
          console.log(`Running OCR.space scan on ${imageSizeKB}KB image...`);
          
          try {
            // Convert image to base64 for OCR.space API
            const base64Image = btoa(String.fromCharCode(...new Uint8Array(imageBuffer)));
            
            const ocrFormData = new FormData();
            ocrFormData.append('base64Image', `data:${imageFile.type};base64,${base64Image}`);
            ocrFormData.append('language', 'eng');
            ocrFormData.append('isOverlayRequired', 'false');
            ocrFormData.append('detectOrientation', 'true');
            ocrFormData.append('scale', 'true');
            ocrFormData.append('OCREngine', '2'); // Engine 2 is better for screenshots
            
            const ocrResponse = await fetch('https://api.ocr.space/parse/image', {
              method: 'POST',
              headers: {
                'apikey': env.OCR_SPACE_API_KEY
              },
              body: ocrFormData
            });
            
            const ocrData = await ocrResponse.json();
            rawResponse = ocrData;
            console.log("OCR.space response:", JSON.stringify(ocrData));
            
            if (ocrData.ParsedResults && ocrData.ParsedResults.length > 0) {
              ocrText = ocrData.ParsedResults.map(r => r.ParsedText).join('\n');
              aiResult = 'ocr_extracted';
              promptUsed = 'OCR.space Engine 2 (dedicated OCR service)';
            } else if (ocrData.ErrorMessage) {
              aiResult = `error: ${ocrData.ErrorMessage}`;
            } else {
              aiResult = 'no_text_found';
            }
          } catch (ocrErr) {
            console.error("OCR.space failed:", ocrErr);
            aiResult = `error: ${ocrErr.message}`;
            rawResponse = { error: ocrErr.message };
          }
        }
        // LLaVA vision model (Cloudflare AI) - various prompt styles
        else if (env.AI) {
          // Define different prompt styles for LLaVA
          const prompts = {
            ocr: `You are an OCR text extractor. Read and output ALL text visible in this image. Output only the exact text, one line at a time.`,
            simple: `Read all the text in this image. Output only the exact words and text you can see. Do not describe the image. Just list the text.`,
            game: `This is a screenshot from Old School RuneScape. Read and list ALL text visible in the image including chat messages, drop notifications, player names, item names, and interface text. Output ONLY the text you can read.`,
            describe: `Describe everything you see in this image in detail. Include any text, objects, colors, and activities visible.`,
            minimal: `What text is in this image?`
          };
          
          promptUsed = prompts[promptStyle] || prompts.game;
          console.log(`Running LLaVA scan (style: ${promptStyle}) on ${imageSizeKB}KB image...`);
          
          try {
            const visionResponse = await env.AI.run("@cf/llava-hf/llava-1.5-7b-hf", {
              prompt: promptUsed,
              image: [...new Uint8Array(imageBuffer)]
            });
            
            rawResponse = visionResponse;
            console.log("LLaVA response:", JSON.stringify(visionResponse));
            
            if (visionResponse && (visionResponse.response || visionResponse.description)) {
              ocrText = visionResponse.response || visionResponse.description;
              aiResult = 'llava_extracted';
            } else {
              aiResult = 'no_response';
            }
          } catch (aiErr) {
            console.error("LLaVA failed:", aiErr);
            aiResult = `error: ${aiErr.message}`;
            rawResponse = { error: aiErr.message, stack: aiErr.stack };
          }
        } else {
          aiResult = 'ai_unavailable';
        }
        
        // Keyword matching (same for all services)
        if ((exactPhrases.length > 0 || regularKeywords.length > 0) && ocrText) {
          const ocrLower = ocrText.toLowerCase();
          
          // Check exact phrase matches
          const exactMatches = exactPhrases.filter(phrase => ocrLower.includes(phrase));
          
          // Check keyword matches with word boundaries
          const keywordMatches = regularKeywords.filter(keyword => {
            const regex = new RegExp(`\\b${keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
            return regex.test(ocrText);
          });
          
          matchedKeywords = [...exactMatches.map(p => `exact:${p}`), ...keywordMatches];
          const totalKeywords = exactPhrases.length + regularKeywords.length;
          aiConfidence = totalKeywords > 0 ? matchedKeywords.length / totalKeywords : 0;
          if (matchedKeywords.length > 0) {
            aiResult = `match: ${matchedKeywords.join(', ')}`;
          }
        }
        
        return new Response(JSON.stringify({
          success: true,
          ocrText,
          aiResult,
          aiConfidence,
          matchedKeywords,
          allKeywords,
          imageSizeKB,
          requireAll,
          wouldAutoApprove: requireAll 
            ? matchedKeywords.length === allKeywords.length 
            : matchedKeywords.length > 0,
          // Debug info
          debug: {
            service: promptStyle === 'ocrspace' ? 'OCR.space' : 'Cloudflare LLaVA',
            promptStyle: serviceUsed,
            promptUsed: promptUsed.length > 200 ? promptUsed.substring(0, 200) + '...' : promptUsed,
            rawResponse,
            model: promptStyle === 'ocrspace' ? 'OCR.space Engine 2' : '@cf/llava-hf/llava-1.5-7b-hf'
          }
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
        
      } catch (err) {
        console.error("AI debug scan error:", err);
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // ========================================
    // SECURE IMAGE SERVING (R2 Proxy)
    // ========================================
    
    /**
     * GET /r2/submissions/:eventId/:userId/:filename - Serve submission images securely from R2
     * 
     * Security Features:
     * - Requires authentication (logged-in user)
     * - Users can only view their own submissions OR admins can view all
     * - Adds cache headers for performance
     * 
     * URL Pattern: /r2/submissions/{eventId}/{userId}/{tileId}_{timestamp}.{ext}
     * Example: /r2/submissions/1/166201366228762624/5_1718457600000.png
     */
    if (method === "GET" && url.pathname.startsWith("/r2/submissions/")) {
      // Extract the image key from the URL path (everything after /r2/)
      const imageKey = url.pathname.replace("/r2/", "");
      
      // Validate image key format: submissions/{eventId}/{userId}/{tileId}_{timestamp}.{ext}
      const keyMatch = imageKey.match(/^submissions\/(\d+)\/(\d+)\/(\d+)_\d+\.(png|jpg|jpeg|gif|webp)$/i);
      if (!keyMatch) {
        return new Response(JSON.stringify({ error: "Invalid image path", path: imageKey }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      const [, eventId, imageOwnerId] = keyMatch;
      
      // Check authentication
      const token = request.headers.get("Cookie")?.match(/yume_auth=([^;]+)/)?.[1];
      const user = token ? await verifyToken(token) : null;
      
      if (!user) {
        return new Response(JSON.stringify({ error: "Authentication required" }), {
          status: 401,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      // Authorization check: user can view their own images OR admins/events managers can view all
      const isOwner = user.userId === imageOwnerId;
      const isAdminOrEvents = ADMIN_USER_IDS.includes(user.userId) || 
                              await hasAccess(user.userId, 'admin') || 
                              await hasAccess(user.userId, 'events');
      
      if (!isOwner && !isAdminOrEvents) {
        return new Response(JSON.stringify({ error: "Access denied" }), {
          status: 403,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      
      try {
        // Fetch the image from R2
        const object = await env.SUBMISSIONS_BUCKET.get(imageKey);
        
        if (!object) {
          return new Response(JSON.stringify({ error: "Image not found" }), {
            status: 404,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        // Build response headers from R2 object metadata
        const headers = new Headers(corsHeaders);
        headers.set("Content-Type", object.httpMetadata?.contentType || "image/png");
        headers.set("Content-Length", object.size.toString());
        headers.set("ETag", object.httpEtag);
        
        // Cache for 1 hour for authenticated users (private cache only)
        headers.set("Cache-Control", "private, max-age=3600");
        
        // Security headers to prevent embedding in other sites
        headers.set("X-Content-Type-Options", "nosniff");
        
        return new Response(object.body, {
          status: 200,
          headers
        });
      } catch (err) {
        console.error("Error serving R2 image:", err);
        await logError({
          endpoint: url.pathname,
          method: method,
          errorType: 'r2',
          errorMessage: `Failed to serve R2 image: ${err.message}`,
          userId: user.userId
        });
        return new Response(JSON.stringify({ error: "Failed to load image" }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // --- Default Fallback ---
    return new Response("Not Found", {
      status: 404,
      headers: corsHeaders
    });
  }
};
