// 🔐 R2 Explorer with Cloudflare Access + Per-User Folder Control
// File: template/src/index.ts

import { getAssetFromKV } from '@cloudflare/kv-asset-handler';

const CONFIG_FILE_KEY = 'access-control/config.json';

function parseJwt(token: string): Record<string, any> {
  const [, payload] = token.split('.');
  return JSON.parse(atob(payload));
}

async function getAccessConfig(env: any): Promise<Record<string, string[]>> {
  const obj = await env.BUCKET.get(CONFIG_FILE_KEY);
  if (!obj) return {};
  const text = await obj.text();
  return JSON.parse(text);
}

function getUserFolders(email: string, config: Record<string, string[]>) {
  if (config[email]?.includes("*")) return '*';
  return config[email] || [];
}

function isAllowedPath(userFolders: string[] | '*', path: string) {
  if (userFolders === '*') return true;
  return userFolders.some(prefix => path.startsWith(prefix));
}

addEventListener('fetch', (event) => {
  event.respondWith(handleRequest(event));
});

async function handleRequest(event: FetchEvent): Promise<Response> {
  const { request } = event;
  const url = new URL(request.url);
  const pathname = url.pathname.replace(/^\//, '');
  const method = request.method;

  const jwt = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!jwt) return new Response("Unauthorized", { status: 401 });

  let claims: any;
  try {
    claims = parseJwt(jwt);
  } catch (e) {
    return new Response("Invalid token", { status: 401 });
  }

  const email = claims.email;
  const config = await getAccessConfig((event as any).env);
  const folders = getUserFolders(email, config);

  if (!folders || (Array.isArray(folders) && folders.length === 0)) {
    return new Response("Access denied", { status: 403 });
  }

  // Handle file operations
  if (method === 'GET' && url.pathname.startsWith('/api/list')) {
    const prefixParam = url.searchParams.get('prefix') || '';
    if (!isAllowedPath(folders, prefixParam)) {
      return new Response("Forbidden", { status: 403 });
    }
    const list = await (event as any).env.BUCKET.list({ prefix: prefixParam });
    return new Response(JSON.stringify(list), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (method === 'PUT' && url.pathname.startsWith('/api/upload')) {
    const key = url.searchParams.get('key');
    if (!key || !isAllowedPath(folders, key)) {
      return new Response("Forbidden", { status: 403 });
    }
    const data = await request.arrayBuffer();
    await (event as any).env.BUCKET.put(key, data);
    return new Response("Uploaded", { status: 200 });
  }

  // Serve static assets (UI)
  try {
    return await getAssetFromKV(event);
  } catch (e) {
    return new Response("Not found", { status: 404 });
  }
}
