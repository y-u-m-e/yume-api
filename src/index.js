export default {
  async fetch(request, env, ctx) {
    const { method } = request;
    const url = new URL(request.url);

    // --- CORS Headers Helper ---
    const origin = request.headers.get("Origin") || "*";
    const corsHeaders = {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Credentials": "true"
    };

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
    // Separate whitelists for different features
    const allowedUsersDocs = (env.ALLOWED_USER_IDS_DOCS || "").split(",").map(id => id.trim()).filter(Boolean);
    const allowedUsersCruddy = (env.ALLOWED_USER_IDS_CRUDDY || "").split(",").map(id => id.trim()).filter(Boolean);
    // Legacy fallback - if specific lists are empty, fall back to general list
    const allowedUsersGeneral = (env.ALLOWED_USER_IDS || "").split(",").map(id => id.trim()).filter(Boolean);
    
    // Helper to check if user has access to a feature
    const hasAccess = (userId, featureList) => {
      if (featureList.length > 0) return featureList.includes(userId);
      return allowedUsersGeneral.includes(userId); // Fallback to general list
    };

    // Helper: Create a simple signed token (base64 encoded JSON with timestamp)
    const createToken = (userId, username, avatar) => {
      const payload = { userId, username, avatar, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }; // 7 days
      return btoa(JSON.stringify(payload));
    };

    // Helper: Verify and decode token
    const verifyToken = (token) => {
      try {
        const payload = JSON.parse(atob(token));
        if (payload.exp < Date.now()) return null;
        return payload;
      } catch {
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
        const sessionToken = createToken(user.id, user.username, user.avatar);

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
        return new Response("Authentication error", { status: 500 });
      }
    }

    // GET /auth/me - Get current user (check if authenticated)
    if (method === "GET" && url.pathname === "/auth/me") {
      const cookieHeader = request.headers.get("Cookie") || "(no cookie header)";
      const token = getTokenFromCookie(request);
      const user = token ? verifyToken(token) : null;

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

      // Check access for each feature
      const canAccessDocs = hasAccess(user.userId, allowedUsersDocs);
      const canAccessCruddy = hasAccess(user.userId, allowedUsersCruddy);
      // Legacy: "authorized" = has access to cruddy panel (backward compatible)
      const isAuthorized = canAccessCruddy;
      
      console.log("User ID:", user.userId);
      console.log("Access - Docs:", canAccessDocs, "Cruddy:", canAccessCruddy);

      return new Response(JSON.stringify({
        authenticated: true,
        authorized: isAuthorized,
        access: {
          docs: canAccessDocs,
          cruddy: canAccessCruddy
        },
        user: {
          id: user.userId,
          username: user.username,
          avatar: user.avatar
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

    // --- Admin Secrets Endpoint ---
    // Returns sensitive config only for authenticated admins
    const ADMIN_USER_IDS = ["166201366228762624"]; // Admin Discord IDs
    
    if (method === "GET" && url.pathname === "/admin/secrets") {
      const token = getTokenFromCookie(request);
      const user = token ? verifyToken(token) : null;
      
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
      const user = token ? verifyToken(token) : null;
      
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
      const user = token ? verifyToken(token) : null;
      const canAccessDocs = user ? hasAccess(user.userId, allowedUsersDocs) : false;
      
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

    // --- Widget CDN Proxy ---
    // Proxies jsDelivr with the configured SHA for instant cache-busting
    // Each widget has its own SHA env variable for independent versioning
    // Usage: https://api.itai.gg/cdn/event-parser-widget.js
    //        https://api.itai.gg/cdn/cruddy-panel.js
    //        https://api.itai.gg/cdn/mention-widget.js
    const cdnMatch = url.pathname.match(/^\/cdn\/(.+\.js)$/);
    if (cdnMatch && method === "GET") {
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
        const cdnResponse = await fetch(cdnUrl);
        if (!cdnResponse.ok) {
          return new Response("Failed to fetch widget", { status: 502, headers: corsHeaders });
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

    // --- Default Fallback ---
    return new Response("Not Found", {
      status: 404,
      headers: corsHeaders
    });
  }
};
