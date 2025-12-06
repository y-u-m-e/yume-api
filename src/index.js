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
    const allowedUsers = (env.ALLOWED_USER_IDS || "").split(",").map(id => id.trim());

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

    // GET /auth/login - Redirect to Discord OAuth
    if (method === "GET" && url.pathname === "/auth/login") {
      const state = crypto.randomUUID();
      const params = new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        redirect_uri: env.DISCORD_REDIRECT_URI,
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
        // Exchange code for access token
        const tokenResponse = await fetch(`${DISCORD_API}/oauth2/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: env.DISCORD_CLIENT_ID,
            client_secret: env.DISCORD_CLIENT_SECRET,
            grant_type: "authorization_code",
            code: code,
            redirect_uri: env.DISCORD_REDIRECT_URI
          })
        });

        if (!tokenResponse.ok) {
          console.error("Token exchange failed:", await tokenResponse.text());
          return new Response("Authentication failed", { status: 401 });
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

        // Redirect back to the app with cookie set
        return new Response(null, {
          status: 302,
          headers: {
            "Location": "https://yumes-tools.itai.gg/#history-interface",
            "Set-Cookie": `yume_auth=${sessionToken}; Path=/; Domain=.itai.gg; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`
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
      console.log("Allowed users:", allowedUsers);
      console.log("ALLOWED_USER_IDS env:", env.ALLOWED_USER_IDS);

      if (!user) {
        console.log("Result: NOT AUTHENTICATED (no valid token)");
        return new Response(JSON.stringify({ 
          authenticated: false,
          debug: { cookieReceived: cookieHeader !== "(no cookie header)", tokenFound: !!token }
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      const isAuthorized = allowedUsers.includes(user.userId);
      console.log("User ID:", user.userId, "Authorized:", isAuthorized);

      return new Response(JSON.stringify({
        authenticated: true,
        authorized: isAuthorized,
        user: {
          id: user.userId,
          username: user.username,
          avatar: user.avatar
        },
        debug: { allowedUsers, userIdType: typeof user.userId }
      }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // GET /auth/logout - Clear session
    if (method === "GET" && url.pathname === "/auth/logout") {
      return new Response(null, {
        status: 302,
        headers: {
          "Location": "https://yumes-tools.itai.gg/#sandbox",
          "Set-Cookie": "yume_auth=; Path=/; Domain=.itai.gg; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
        }
      });
    }

    // --- Protected Documentation Site ---
    // Serves Docsify docs with Discord OAuth protection
    if (method === "GET" && url.pathname.startsWith("/docs")) {
      // Check authentication
      const token = getTokenFromCookie(request);
      const user = token ? verifyToken(token) : null;
      
      if (!user) {
        // Not logged in - redirect to login
        return Response.redirect(`${url.origin}/auth/login`, 302);
      }
      
      const isAuthorized = allowedUsers.includes(user.userId);
      if (!isAuthorized) {
        // Logged in but not authorized
        return new Response(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>Unauthorized</title>
            <style>
              body { font-family: system-ui; background: #0f172a; color: #fff; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
              .box { text-align: center; padding: 40px; background: rgba(255,255,255,0.05); border-radius: 12px; }
              h1 { color: #f87171; }
              a { color: #5eead4; }
            </style>
          </head>
          <body>
            <div class="box">
              <h1>⛔ Unauthorized</h1>
              <p>You don't have access to the documentation.</p>
              <p>Logged in as: ${user.username}</p>
              <p><a href="/auth/logout">Logout</a></p>
            </div>
          </body>
          </html>
        `, {
          status: 403,
          headers: { "Content-Type": "text/html" }
        });
      }
      
      // User is authorized - serve docs from jsDelivr (yume-api repo)
      let filePath = url.pathname.replace(/^\/docs\/?/, "") || "index.html";
      if (filePath === "" || filePath.endsWith("/")) {
        filePath = filePath + "index.html";
      }
      // If no extension and not a known file, serve index.html (SPA routing)
      if (!filePath.includes(".")) {
        filePath = "index.html";
      }
      
      const sha = env.SHA_DOCS || "main";
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
                headers: { "Content-Type": "text/html", "Cache-Control": "public, max-age=300" }
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
        
        return new Response(content, {
          status: 200,
          headers: { "Content-Type": contentType, "Cache-Control": "public, max-age=300" }
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
