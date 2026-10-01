import { createLocalJWKSet, createRemoteJWKSet, jwtVerify } from 'jose';

// The gateway only checks that a token is present and valid (signature, expiry, issuer, audience).
// It does no role or office checks: each service does those itself (RBAC doc 3.6).

const TOKEN_PROBLEM_CODES = new Set([
  'ERR_JWT_EXPIRED',
  'ERR_JWT_INVALID',
  'ERR_JWT_CLAIM_VALIDATION_FAILED',
  'ERR_JWS_INVALID',
  'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
  'ERR_JWKS_NO_MATCHING_KEY',
  'ERR_JWKS_MULTIPLE_MATCHING_KEYS',
  'ERR_JOSE_ALG_NOT_ALLOWED',
  'ERR_JOSE_NOT_SUPPORTED',
  'ERR_JWK_INVALID',
  'ERR_JWKS_INVALID',
]);

/**
 * Offline RS256 verifier. Provide jwksUrl (Identity's published keys, fetched lazily and cached) or
 * jwks (a JWKS object, for tests). Returns async verify(token) -> { ok: true } | { ok: false, status, code, message }.
 */
export function createTokenCheck({ jwksUrl, jwks, issuer = 'ccms-identity', audience = 'ccms' }) {
  let keySet;
  const getKeySet = () => {
    if (!keySet) {
      keySet = jwks
        ? createLocalJWKSet(jwks)
        : createRemoteJWKSet(new URL(jwksUrl), { timeoutDuration: 3000, cooldownDuration: 10_000 });
    }
    return keySet;
  };

  return async function check(token) {
    try {
      await jwtVerify(token, getKeySet(), { issuer, audience, algorithms: ['RS256'] });
      return { ok: true };
    } catch (err) {
      if (err?.code && TOKEN_PROBLEM_CODES.has(err.code)) {
        return { ok: false, status: 401, code: 'INVALID_TOKEN', message: 'Invalid or expired token' };
      }
      if (err?.code === 'ERR_JWKS_TIMEOUT' || err?.name === 'TypeError' || err?.code === 'ERR_JOSE_GENERIC') {
        // The public keys are unreachable and not cached: that is not the caller's fault, so not a 401.
        return { ok: false, status: 503, code: 'AUTH_UNAVAILABLE', message: 'Cannot verify your session right now, try again' };
      }
      return { ok: false, status: 401, code: 'INVALID_TOKEN', message: 'Invalid or expired token' };
    }
  };
}

export function bearerToken(headers) {
  const match = /^Bearer\s+(\S+)$/i.exec(headers.authorization ?? '');
  return match ? match[1] : null;
}
