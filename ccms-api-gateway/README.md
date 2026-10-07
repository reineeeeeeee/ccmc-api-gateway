# ccms-api-gateway

The one public entry point for the browser. It is a small Next.js app made only of Route Handlers: no pages, no database.
Deployed as its own Vercel project; `ccms-frontend` forwards every `/api/*` request to it.

```
ccms-api-gateway/
├── src/
│   ├── app/api/
│   │   ├── identity/[...path]/route.js    # one folder per service name; each re-exports lib/handlers.js
│   │   ├── catalogue/[...path]/route.js
│   │   ├── calendar/[...path]/route.js
│   │   ├── logs/[...path]/route.js
│   │   └── health/route.js
│   └── lib/
│       ├── routes.js        # which name goes to which service; public routes; blocked routes
│       ├── auth.js          # token check (RS256, Identity's public keys, offline)
│       ├── handlers.js      # the one handler every service folder re-exports
│       ├── gateway.js       # the proxy: (Request) => Response, built on fetch
│       └── instance.js      # builds the gateway from environment variables
└── test/
```

## What it does for every request

1. Starts or keeps the correlation id (`x-correlation-id`) and returns it.
2. Refuses plain HTTP when HTTPS is required (on Vercel it is; locally it is off).
3. Maps `/api/{name}/…` to a service: `identity` → Identity, `catalogue` and `calendar` → Core, `logs` → Logs. Anything else is a 404.
4. Refuses ambiguous paths (`..`, `//`, `%2e`, `%2f`, `\`) and **never forwards `/api/jobs/*`**: scheduled jobs are called by Vercel
   Cron directly on each service, not through the gateway.
5. On every route that is not public, requires a valid token (signature, expiry, issuer, audience). **It does no role or office
   checks**: each service does its own (RBAC doc 3.6). Public routes: sign-in, refresh, sign-out, password-reset confirm, the public
   keys, the public service browse, and every health check.
6. Removes `x-service-key` (a browser can never present the service-to-service key) and forwards the rest, including `Authorization`
   and cookies; returns the answer with every `Set-Cookie` kept separate.
7. Answers in the standard error format: 404 `ROUTE_NOT_FOUND`, 401 `UNAUTHORIZED` / `INVALID_TOKEN`, 502 `SERVICE_UNAVAILABLE`,
   503 `AUTH_UNAVAILABLE` (keys unreachable), 504 `SERVICE_TIMEOUT`.

`GET /api/logs/audit-events` (the read-only audit viewer) passes through; every other method on that path is blocked.

## Run it

```bash
cp .env.example .env.local
npm install
npm run dev          # http://localhost:8080/api/health
npm test
```

## Environment

| Variable | Meaning |
| --- | --- |
| `IDENTITY_URL`, `CORE_URL`, `LOGS_URL` | where each service runs (origin only, no `/api`) |
| `IDENTITY_JWKS_URL`, `JWT_ISSUER`, `JWT_AUDIENCE`, `VERIFY_TOKENS` | token check (defaults: `IDENTITY_URL/api/auth/jwks`, `ccms-identity`, `ccms`, on) |
| `REQUIRE_TLS`, `TRUST_PROXY` | HTTPS only; on by default on Vercel |
| `PROXY_TIMEOUT_SECONDS` | wait for a service before answering 504 (default 25) |
