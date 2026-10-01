import { readFileSync } from 'node:fs';
import { createTokenCheck } from './auth.js';
import { serviceTargets } from './routes.js';
import { createGateway } from './server.js';

const flag = (name, fallback) => {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : ['true', '1', 'yes'].includes(value.toLowerCase());
};

// TLS is required in every deployed environment. Locally (NODE_ENV unset) plain HTTP is allowed.
const requireTls = flag('REQUIRE_TLS', process.env.NODE_ENV === 'production');
const tls = process.env.TLS_CERT_FILE && process.env.TLS_KEY_FILE
  ? { cert: readFileSync(process.env.TLS_CERT_FILE), key: readFileSync(process.env.TLS_KEY_FILE) }
  : undefined;

// Token check on /api routes that are not public. Keys come from Identity (fetched when first needed,
// then cached). Set VERIFY_TOKENS=false to turn it off.
const tokenCheck = flag('VERIFY_TOKENS', true)
  ? createTokenCheck({
      jwksUrl: process.env.IDENTITY_JWKS_URL || `${serviceTargets().identity}/api/auth/jwks`,
      issuer: process.env.JWT_ISSUER || 'ccms-identity',
      audience: process.env.JWT_AUDIENCE || 'ccms',
    })
  : undefined;

const server = createGateway({ requireTls, trustProxy: flag('TRUST_PROXY', false), tls, tokenCheck });
const port = Number(process.env.PORT || 8080);
const host = process.env.HOST || '0.0.0.0';

server.listen(port, host, () => {
  console.log(`[gateway] listening on ${tls ? 'https' : 'http'}://${host}:${port} (TLS required: ${requireTls})`);
});

for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)));
