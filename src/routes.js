// Routing table. The browser only ever talks to the gateway:
//   /api/{service}/*        -> that service's /api/*         (JSON APIs)
//   /_ccms/{service}/*      -> that service's /*             (its Next.js static assets)
//   page paths below        -> the service that owns the page
// Add a service here when its sprint creates it.

export const SERVICES = {
  identity: { env: 'IDENTITY_URL', fallback: 'http://127.0.0.1:3001' },
  logs: { env: 'LOGS_URL', fallback: 'http://127.0.0.1:3002' },
  catalogue: { env: 'CATALOGUE_URL', fallback: 'http://127.0.0.1:3003' },
  // Calendar lives in the same service as the Catalogue (one "Core" repo and database), so /api/calendar/* goes there too.
  calendar: { env: 'CALENDAR_URL', fallback: 'http://127.0.0.1:3003' },
};

// Pages (exact path or a sub-path) and the service that serves them.
export const PAGE_ROUTES = [
  { service: 'identity', paths: ['/login', '/accounts', '/reset-password', '/office', '/campus'] },
  // Each repo ships its own pages. The Core repo (Catalogue + Calendar) owns the public home page,
  // Offices, Services and Calendar.
  { service: 'catalogue', paths: ['/', '/offices', '/services', '/public', '/calendar'] },
  { service: 'logs', paths: ['/logs'] },
];

// Backend-only writes (service-to-service, protected by the shared key). Browsers never need them,
// so the gateway refuses every method except GET/HEAD on these paths. GET /api/logs/audit-events is
// the read-only audit viewer and passes through to the Logs service (which checks the token and role).
export const BLOCKED_API_PATHS = ['/api/logs/audit-events'];
const READ_METHODS = new Set(['GET', 'HEAD']);

// Browser-facing API routes that need no token (RBAC doc 4.4): sign-in, refresh, sign-out and the
// published keys; the public service browse; and every service's health check. Everything else under
// /api needs a valid token. Paths are the service's own paths (after /api/{service} is mapped to /api).
export const PUBLIC_API = {
  identity: ['/api/auth/', '/api/health'],
  catalogue: ['/api/public/', '/api/health'],
  calendar: ['/api/health'],
  logs: ['/api/health'],
};

export function isPublicApi(service, path) {
  const pathname = path.split('?')[0].replace(/\/+$/, '');
  return (PUBLIC_API[service] ?? []).some((p) => (p.endsWith('/') ? pathname.startsWith(p) : pathname === p));
}

export function serviceTargets(env = process.env) {
  return Object.fromEntries(Object.entries(SERVICES).map(([name, s]) => [name, (env[s.env] || s.fallback).replace(/\/$/, '')]));
}

/** Decides where a request goes. Returns { service, path } (path keeps the query) or { blocked } / null. */
export function resolveRoute(url, targets = serviceTargets(), method = 'GET') {
  const queryStart = url.indexOf('?');
  const pathname = queryStart === -1 ? url : url.slice(0, queryStart);
  const query = queryStart === -1 ? '' : url.slice(queryStart);

  // Refuse ambiguous paths outright (dot segments, doubled or encoded slashes, backslashes) so a
  // crafted URL cannot slip past the routing and blocking rules below.
  if (/(\/\.{1,2}(\/|$))|%2e|%2f|%5c|\/\/|\\/i.test(pathname)) return { blocked: true };
  const trimmed = pathname.replace(/\/+$/, '');
  const readOnly = READ_METHODS.has(String(method).toUpperCase());
  if (!readOnly && BLOCKED_API_PATHS.some((blocked) => trimmed === blocked || trimmed.startsWith(`${blocked}/`))) return { blocked: true };

  let match = /^\/api\/([a-z0-9-]+)(\/.*)?$/.exec(pathname);
  if (match && targets[match[1]]) return { service: match[1], path: `/api${match[2] ?? ''}${query}` };

  match = /^\/_ccms\/([a-z0-9-]+)(\/.*)$/.exec(pathname);
  if (match && targets[match[1]]) return { service: match[1], path: match[2] + query };

  for (const route of PAGE_ROUTES) {
    if (!targets[route.service]) continue;
    const owns = route.paths.some((p) => pathname === p || (p !== '/' && pathname.startsWith(`${p}/`)));
    if (owns) return { service: route.service, path: pathname + query };
  }
  return null;
}
