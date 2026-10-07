import { createTokenCheck } from './auth.js';
import { createGateway } from './gateway.js';
import { serviceTargets } from './routes.js';

const KEY = '__ccmsGateway';
const flag = (value, fallback) => (value === undefined || value === '' ? fallback : !['false', '0', 'no', 'off'].includes(String(value).toLowerCase()));

/** The gateway for this process, built from the environment on first use. */
export function getGateway(env = process.env) {
  if (!globalThis[KEY]) {
    const targets = serviceTargets(env);
    // HTTPS is enforced on Vercel (it always terminates TLS and tells us with X-Forwarded-Proto). A local
    // `npm start` is plain HTTP, so it is not enforced unless REQUIRE_TLS=true.
    const onVercel = Boolean(env.VERCEL);
    const tokenCheck = flag(env.VERIFY_TOKENS, true)
      ? createTokenCheck({
          jwksUrl: env.IDENTITY_JWKS_URL || `${targets.identity}/api/auth/jwks`,
          issuer: env.JWT_ISSUER || 'ccms-identity',
          audience: env.JWT_AUDIENCE || 'ccms',
        })
      : undefined;
    globalThis[KEY] = createGateway({
      targets,
      tokenCheck,
      requireTls: flag(env.REQUIRE_TLS, onVercel),
      trustProxy: flag(env.TRUST_PROXY, onVercel),
      timeoutMs: (Number(env.PROXY_TIMEOUT_SECONDS) > 0 ? Number(env.PROXY_TIMEOUT_SECONDS) : 25) * 1000,
    });
  }
  return globalThis[KEY];
}
