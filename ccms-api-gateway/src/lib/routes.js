// Routing table. The browser only ever talks to the gateway:
//   /api/{name}/*   ->   that service's /api/*
// Several names can point at one service: Catalogue and Calendar both live in Core.
// Add a service here when its sprint creates it.

export const SERVICES = {
  identity: { env: 'IDENTITY_URL', fallback: 'http://127.0.0.1:3001' },
  catalogue: { env: 'CORE_URL', fallback: 'http://127.0.0.1:3003' },
  calendar: { env: 'CORE_URL', fallback: 'http://127.0.0.1:3003' },
  logs: { env: 'LOGS_URL', fallback: 'http://127.0.0.1:3002' },
  operations: { env: 'OPERATIONS_URL', fallback: 'http://127.0.0.1:3004' },
};

// Backend-only writes (service-to-service, protected by the shared key). Browsers never need them,
// so the gateway refuses every method except GET/HEAD on these paths. GET /api/logs/audit-events is
// the read-only audit viewer and passes through to the Logs service (which checks the token and role).
export const BLOCKED_API_PATHS = ['/api/logs/audit-events'];
const READ_METHODS = new Set(['GET', 'HEAD']);

// Scheduled jobs belong to each service and are called by Vercel Cron with a secret. They are never
// reachable through the gateway, whatever the method.
export const BLOCKED_PREFIXES = ['/api/jobs'];

// Browser-facing API routes that need no token (RBAC doc 4.4): sign-in, refresh, sign-out and the
// published keys; the public service browse; and every service's health check. Everything else under
// /api needs a valid token. Paths are the service's own paths (after /api/{name} is mapped to /api).
export const PUBLIC_API = {
  identity: ['/api/auth/', '/api/health'],
  catalogue: ['/api/public/', '/api/health'],
  calendar: ['/api/health'],
  logs: ['/api/health'],
  operations: ['/api/health'],
};

// EB6 / EB7: the one machine-to-machine route. FMS pulls the calendar snapshot with a machine key
// (Authorization: Bearer ccms_mk_<ref>.<secret>), which is not a user token, so the user-token check
// is skipped for exactly this path, only for GET/HEAD, and only when the key has the machine-key
// prefix. The gateway does NOT validate the key: Core does, and answers the same 401 for every failure.
// Every other route, method or kind of credential still needs a valid user token.
export const MACHINE_KEY_API = { calendar: ['/api/declarations'] };
export const MACHINE_KEY_PREFIX = 'ccms_mk_';

export function isMachineKeyRequest(name, path, method, token) {
  if (!READ_METHODS.has(String(method).toUpperCase())) return false;
  if (typeof token !== 'string' || !token.startsWith(MACHINE_KEY_PREFIX)) return false;
  const pathname = path.split('?')[0].replace(/\/+$/, '');
  return (MACHINE_KEY_API[name] ?? []).includes(pathname);
}

export function isPublicApi(name, path) {
  const pathname = path.split('?')[0].replace(/\/+$/, '');
  return (PUBLIC_API[name] ?? []).some((p) => (p.endsWith('/') ? pathname.startsWith(p) : pathname === p));
}

export function serviceTargets(env = process.env) {
  return Object.fromEntries(Object.entries(SERVICES).map(([name, s]) => [name, (env[s.env] || s.fallback).replace(/\/$/, '')]));
}

/** Decides where a request goes. Returns { name, path } (path keeps the query), { blocked: true } or null. */
export function resolveRoute(url, targets = serviceTargets(), method = 'GET') {
  const queryStart = url.indexOf('?');
  const pathname = queryStart === -1 ? url : url.slice(0, queryStart);
  const query = queryStart === -1 ? '' : url.slice(queryStart);

  // Refuse ambiguous paths outright (dot segments, doubled or encoded slashes, backslashes) so a
  // crafted URL cannot slip past the routing and blocking rules below.
  if (/(\/\.{1,2}(\/|$))|%2e|%2f|%5c|\/\/|\\/i.test(pathname)) return { blocked: true };

  const match = /^\/api\/([a-z0-9-]+)(\/.*)?$/.exec(pathname);
  if (!match || !targets[match[1]]) return null;
  const path = `/api${match[2] ?? ''}`;
  const trimmed = path.replace(/\/+$/, '');

  if (BLOCKED_PREFIXES.some((prefix) => trimmed === prefix || trimmed.startsWith(`${prefix}/`))) return { blocked: true };
  const readOnly = READ_METHODS.has(String(method).toUpperCase());
  const fullTrimmed = pathname.replace(/\/+$/, '');
  if (!readOnly && BLOCKED_API_PATHS.some((blocked) => fullTrimmed === blocked || fullTrimmed.startsWith(`${blocked}/`))) {
    return { blocked: true };
  }
  return { name: match[1], path: path + query };
}
