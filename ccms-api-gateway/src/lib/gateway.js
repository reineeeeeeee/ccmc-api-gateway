import { randomUUID } from 'node:crypto';
import { bearerToken } from './auth.js';
import { isPublicApi, resolveRoute, serviceTargets } from './routes.js';

const CORRELATION = 'x-correlation-id';
const SAFE_ID = /^[A-Za-z0-9._-]{8,128}$/;

// Headers that belong to one connection, not to the message. They are never copied across.
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host']);
// fetch() decodes the body for us, so the encoding and length of the original no longer apply.
const DROP_ON_RESPONSE = new Set([...HOP_BY_HOP, 'content-encoding', 'content-length']);

export function errorResponse(status, code, message, correlationId, extraHeaders = {}) {
  const body = { error: { code, message, details: null, correlation_id: correlationId, timestamp: new Date().toISOString() } };
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', [CORRELATION]: correlationId, ...extraHeaders },
  });
}

/**
 * Builds the gateway as a function (Request) => Response, so it runs inside a Next.js Route Handler.
 *   targets      { name: 'https://service-origin' }
 *   requireTls   refuse or redirect anything that did not arrive over HTTPS (all deployed environments)
 *   trustProxy   believe X-Forwarded-Proto from the platform in front of us (Vercel sets it)
 *   tokenCheck   async (token) -> { ok } | { ok: false, status, code, message }; when set, every /api route that
 *                is not public needs a valid token (the gateway never checks roles or offices)
 *   fetchImpl    the fetch used to reach services (tests replace it)
 *   timeoutMs    how long to wait for a service before answering 504
 */
export function createGateway({ targets = serviceTargets(), requireTls = false, trustProxy = false, tokenCheck, fetchImpl = fetch, timeoutMs = 25_000 } = {}) {
  return async function gateway(request) {
    const incoming = request.headers.get(CORRELATION);
    // Keep a caller's correlation id when it is safe, otherwise start a new one; forward it unchanged.
    const correlationId = incoming && SAFE_ID.test(incoming) ? incoming : randomUUID();
    const url = new URL(request.url);

    const secure = url.protocol === 'https:' || (trustProxy && (request.headers.get('x-forwarded-proto') ?? '').split(',')[0].trim() === 'https');
    if (requireTls && !secure) {
      if (request.method === 'GET' || request.method === 'HEAD') {
        const host = request.headers.get('host') ?? url.host;
        return new Response(null, { status: 308, headers: { location: `https://${host}${url.pathname}${url.search}`, [CORRELATION]: correlationId } });
      }
      return errorResponse(403, 'HTTPS_REQUIRED', 'This address only accepts HTTPS.', correlationId);
    }

    // Use the path exactly as the client sent it (not as the framework decoded it).
    const rawTarget = request.url.slice(request.url.indexOf(url.pathname));
    const route = resolveRoute(rawTarget, targets, request.method);
    if (!route || route.blocked) return errorResponse(404, 'ROUTE_NOT_FOUND', 'Not found', correlationId);

    if (tokenCheck && !isPublicApi(route.name, route.path)) {
      const token = bearerToken({ authorization: request.headers.get('authorization') ?? undefined });
      if (!token) return errorResponse(401, 'UNAUTHORIZED', 'Authentication required', correlationId);
      let result;
      try {
        result = await tokenCheck(token);
      } catch {
        result = { ok: false, status: 503, code: 'AUTH_UNAVAILABLE', message: 'Cannot verify your session right now, try again' };
      }
      if (!result.ok) return errorResponse(result.status, result.code, result.message, correlationId);
    }

    // ---- forward ----
    const headers = new Headers();
    for (const [name, value] of request.headers) {
      if (HOP_BY_HOP.has(name) || name === 'x-service-key' || name === 'content-length') continue; // a browser can never present the service key
      headers.set(name, value);
    }
    headers.set(CORRELATION, correlationId);
    headers.set('x-forwarded-host', request.headers.get('x-forwarded-host') ?? request.headers.get('host') ?? url.host);
    headers.set('x-forwarded-proto', secure ? 'https' : 'http');

    const init = { method: request.method, headers, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) };
    if (!['GET', 'HEAD'].includes(request.method)) init.body = await request.arrayBuffer();

    let upstream;
    try {
      upstream = await fetchImpl(`${targets[route.name]}${route.path}`, init);
    } catch (err) {
      const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
      return errorResponse(
        timedOut ? 504 : 502,
        timedOut ? 'SERVICE_TIMEOUT' : 'SERVICE_UNAVAILABLE',
        timedOut ? 'The service took too long to answer. Please try again.' : 'The service is not available right now. Please try again.',
        correlationId,
      );
    }

    const out = new Headers();
    for (const [name, value] of upstream.headers) {
      if (DROP_ON_RESPONSE.has(name) || name === 'set-cookie') continue;
      out.set(name, value);
    }
    // Several Set-Cookie headers must stay separate (a comma-joined cookie is broken).
    for (const cookie of upstream.headers.getSetCookie?.() ?? []) out.append('set-cookie', cookie);
    out.set(CORRELATION, correlationId);
    if (requireTls) out.set('strict-transport-security', 'max-age=31536000; includeSubDomains');
    return new Response([204, 205, 304].includes(upstream.status) ? null : upstream.body, { status: upstream.status, statusText: upstream.statusText, headers: out });
  };
}
