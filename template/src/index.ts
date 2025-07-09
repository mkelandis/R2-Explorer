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

    const jwt = request.headers.get("Cf-Access-Jwt-Assertion");
    if (!jwt) return new Response("Unauthorized", { status: 401 });

    let claims;
    try {
      claims = JSON.parse(atob(jwt.split('.')[1]));
    } catch (e) {
      log("JWT parse error:", e);
      return new Response("Invalid token", { status: 401 });
    }

    const email = claims.email;
    if (!email) return new Response("Missing email", { status: 403 });

    log("🔐 User:", email);

    // Load access-control config
    let folders: string[] = [];
    try {
      const configFile = await env.BUCKET.get("access-control/config.json");
      const config = configFile ? JSON.parse(await configFile.text()) : {};
      folders = config[email] || [];
    } catch (err) {
      console.error("❌ Failed to load config.json:", err);
      return new Response("Access config error", { status: 500 });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    //
    // ✅ /api/list: allow + filter
    //
    if (path.startsWith('/api/list')) {
      const prefix = url.searchParams.get("prefix") || "";
      const list = await env.BUCKET.list({ prefix });

      if (folders.includes("*")) {
        log(`📂 Full listing for ${email}`);
        return new Response(JSON.stringify(list), {
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const isAllowed = (key: string) => folders.some(folder => key.startsWith(folder));
      const filtered = {
        ...list,
        objects: list.objects.filter(obj => isAllowed(obj.key)),
        prefixes: list.prefixes?.filter(p => isAllowed(p))
      };

      log(`📂 Filtered listing for ${email}:`, filtered.objects.map(f => f.key));
      return new Response(JSON.stringify(filtered), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    //
    // ✅ /api/buckets/:bucket: allow if prefix is permitted
    //
    if (path.startsWith('/api/buckets/')) {
      const prefix = url.searchParams.get("prefix") || "";
      const allowed = folders.includes("*") || folders.some(folder => prefix.startsWith(folder));

      log(`📦 Metadata prefix check: ${prefix} → ${allowed ? "✔️ allowed" : "❌ denied"}`);

      if (!allowed) {
        return new Response("Forbidden", { status: 403 });
      }
    }

    //
    // ✅ Allow /api/server/config
    //
    const isProtectedApi =
      path.startsWith('/api/') &&
      path !== '/api/server/config' &&
      !path.startsWith('/api/list') &&
      !path.startsWith('/api/buckets/');

    if (isProtectedApi) {
      const key = url.searchParams.get("key") || "";
      const allowed = folders.includes("*") || folders.some(prefix => key.startsWith(prefix));

      log(`🔍 Key access: ${key} → ${allowed ? "✔️ allowed" : "❌ denied"}`);

      if (!allowed) {
        return new Response("Forbidden", { status: 403 });
      }
    }

    //
    // ✅ Fallback to R2Explorer for everything else
    //
    return explorer.fetch(request, env, ctx);
  }
};
