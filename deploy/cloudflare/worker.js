const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith("/api/")) {
        if (!env.API_BASE_URL) {
          if (url.pathname === "/api/health" && request.method === "GET") {
            return json({ status: "degraded" }, 503);
          }
          return json({ detail: "ForkSure API backend is not configured." }, 503);
        }
        return await proxyApi(request, env, url);
      }

      const response = await env.ASSETS.fetch(request);
      return withSecurityHeaders(response);
    } catch (error) {
      const status = Number(error?.status || 500);
      const detail = status === 500 ? "ForkSure could not complete the request." : String(error.message || error);
      return json({ detail }, status);
    }
  },
};

async function proxyApi(request, env, requestUrl) {
  const baseUrl = new URL(env.API_BASE_URL);
  if (baseUrl.protocol !== "https:") throw httpError(500, "ForkSure API proxy is not configured safely.");

  const target = new URL(`${requestUrl.pathname}${requestUrl.search}`, baseUrl);
  const headers = new Headers(request.headers);
  headers.delete("host");
  if (env.FORKSURE_PROXY_TOKEN) headers.set("x-forksure-proxy-token", env.FORKSURE_PROXY_TOKEN);

  const response = await fetch(target, {
    method: request.method,
    headers,
    body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
    redirect: "manual",
  });
  const secured = withSecurityHeaders(response);
  secured.headers.set("Cache-Control", "no-store");
  return secured;
}

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function json(body, status = 200) {
  return withSecurityHeaders(new Response(JSON.stringify(body), { status, headers: JSON_HEADERS }));
}

function withSecurityHeaders(response) {
  const next = new Response(response.body, response);
  next.headers.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
  next.headers.set("Referrer-Policy", "no-referrer");
  next.headers.set("X-Content-Type-Options", "nosniff");
  return next;
}
