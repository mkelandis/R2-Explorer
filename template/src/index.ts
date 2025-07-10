import { R2Explorer } from 'r2-explorer';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const explorer = R2Explorer({
      readonly: false,
      cfAccessTeamName: env.CF_ACCESS_TEAM_NAME
    });

    const log = (...args: any[]) => {
      if (env.DEBUG_LOGS === "true") console.log(...args);
    };

    const url = new URL(request.url);
    const path = url.pathname;

    // ✅ Authenticate with CF Access
    const jwt = request.headers.get("Cf-Access-Jwt-Assertion");
    if (!jwt) return new Response("Unauthorized", { status: 401 });

    let claims: any;
    try {
      claims = JSON.parse(atob(jwt.split('.')[1]));
    } catch (e) {
      log("JWT parse error:", e);
      return new Response("Invalid token", { status: 401 });
    }

    const email = claims.email;
    if (!email) return new Response("Missing email", { status: 403 });
    log("🔐 Authenticated user:", email);

    // ✅ Load access config from BUCKET
    let allowedPaths: string[] = [];
    try {
      const configFile = await env.BUCKET.get("access-control/config.json");
      const config = configFile ? JSON.parse(await configFile.text()) : {};
      allowedPaths = config[email] || [];
    } catch (err) {
      console.error("❌ Failed to load config.json:", err);
      return new Response("Access config error", { status: 500 });
    }
    log("🔒 Folder permissions:", allowedPaths);

    const isAllowed = (path: string) =>
      allowedPaths.some(allowedPath => path.startsWith(allowedPath));

    //
    // ✅ Allow /api/server/config
    //
    const isProtectedApi =
      path.startsWith('/api/') &&
      path !== '/api/server/config' &&
      !path.startsWith('/api/list') &&
      !path.startsWith('/api/buckets/');

    //
    // ✅ Protect upload/view/delete routes
    //
    if (isProtectedApi) {
      const key = url.searchParams.get("key") || "";
      const allowed = allowedPaths.includes("*") || isAllowed(key);

      log(`🔐 Key access check: ${key} → ${allowed ? "✔️ allowed" : "❌ denied"}`);
      if (!allowed) {
        return new Response("Forbidden", { status: 403 });
      }
    }


    // ✅ Pass request to R2Explorer
    const explorerResponse = await explorer.fetch(request, env, ctx);

    // ✅ Intercept list endpoints to filter based on folder access
    if (path.startsWith('/api/list') || path.startsWith('/api/buckets/')) {
      const contentType = explorerResponse.headers.get("Content-Type") || "";
      if (!contentType.includes("application/json")) return explorerResponse;

      let data: any;
      try {
        data = await explorerResponse.clone().json();
      } catch (e) {
        log("❌ Failed to parse explorer response JSON:", e);
        return explorerResponse;
      }

      log("📦 Raw response from explorer:", data);

      if (allowedPaths.includes("*")) {
        log("✅ Wildcard access — returning unfiltered data");
        return explorerResponse;
      }

      const filtered = {
        ...data,
        objects: data.objects?.filter((obj: any) => {
          const allowed = isAllowed(obj.key);
          log(`${allowed ? "✅" : "❌"} object "${obj.key}"`);
          return allowed;
        }),
        delimitedPrefixes: data.delimitedPrefixes?.filter((prefix: string) => {
          const allowed = isAllowed(prefix);
          log(`${allowed ? "✅" : "❌"} prefix "${prefix}"`);
          return allowed;
        })
      };

      return new Response(JSON.stringify(filtered), {
        status: explorerResponse.status,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store'
        }
      });
    }

    // ✅ Otherwise, allow R2Explorer to handle the request
    return explorerResponse;
  }
};
