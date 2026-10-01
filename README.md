# ccms-gateway

Single entry point (port 8080). The browser only talks to the gateway; it forwards to the services.

- Pages: each repo serves its own. `/login`, `/accounts`, `/office`, `/campus`, `/reset-password` go to Identity. `/` (public home), `/offices`, `/services`, `/calendar`, `/public` go to the Core repo (Catalogue + Calendar). `/logs` goes to Logs. Sign-in is only in Identity: the pages in the other repos use the same refresh cookie and the same access token, which works because the browser sees one address (the gateway).
- API: `/api/...` is routed per service. Backend-only writes are blocked here: on `/api/logs/audit-events` only GET/HEAD (the read-only audit viewer, authorised by the Logs service) pass through; POST, PUT, PATCH and DELETE get 404.
- Each service's assets are served under `/_ccms/{service}` so several Next apps can share one origin.
- Adds a correlation id to every request and enforces HTTPS in production (`ENFORCE_HTTPS`).

Setup: copy `.env.example` to `.env.local`, then `npm install && npm start`. Tests: `npm test`.

## Token check (RBAC doc 3.6, 4.4)

Every `/api` route that is not public needs a valid token: the gateway checks the signature (RS256, Identity's published keys, fetched when first needed and then cached), expiry, issuer and audience, and answers `401` in the standard error format otherwise (`503 AUTH_UNAVAILABLE` if the keys cannot be reached and are not cached yet). It does **no** role or office checks; each service does those. The token is forwarded unchanged. Public (no token): `/api/identity/auth/*` (sign-in, refresh, sign-out, password-reset confirm, keys), `/api/catalogue/public/*` (public service browse) and every service's `/api/health`. Pages and static assets need no token: the page script fetches it.

| Variable | Default | Meaning |
|---|---|---|
| `IDENTITY_JWKS_URL` | `{IDENTITY_URL}/api/auth/jwks` | where the public keys are read |
| `JWT_ISSUER`, `JWT_AUDIENCE` | `ccms-identity`, `ccms` | must match Identity |
| `VERIFY_TOKENS` | `true` | `false` turns the check off |
