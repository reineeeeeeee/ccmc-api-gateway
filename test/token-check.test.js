import { strict as assert } from 'node:assert';
import http from 'node:http';
import { after, before, describe, it } from 'node:test';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createTokenCheck } from '../src/auth.js';
import { createGateway } from '../src/server.js';

// The gateway checks that a token is present and valid on /api routes that are not public (RBAC doc 3.6, 4.4).
const hits = { identity: [], catalogue: [] };
const servers = [];
let targets;
let privateKey;
let jwks;

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));

before(async () => {
  targets = {};
  for (const name of Object.keys(hits)) {
    const server = http.createServer((req, res) => {
      hits[name].push({ url: req.url, headers: req.headers });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    });
    servers.push(server);
    targets[name] = `http://127.0.0.1:${await listen(server)}`;
  }
  const pair = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' }] };
});
after(() => servers.forEach((s) => s.close()));

const sign = ({ exp = '10m', aud = 'ccms', iss = 'ccms-identity', key = privateKey } = {}) =>
  new SignJWT({ role: 'SUPER_ADMIN', office_id: null })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setSubject('user-1')
    .setIssuer(iss)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(key);

async function withGateway(tokenCheck, fn) {
  const gateway = createGateway({ targets, tokenCheck });
  const port = await listen(gateway);
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    gateway.closeAllConnections?.();
    gateway.close();
  }
}

const check = () => createTokenCheck({ jwks });
const total = () => hits.identity.length + hits.catalogue.length;

describe('gateway token check', () => {
  it('refuses a protected /api route with no token (401, standard error) and never reaches the service', async () => {
    await withGateway(check(), async (base) => {
      const before = total();
      const response = await fetch(`${base}/api/catalogue/offices`);
      assert.equal(response.status, 401);
      const body = await response.json();
      assert.equal(body.error.code, 'UNAUTHORIZED');
      assert.ok(body.error.correlation_id && body.error.timestamp);
      assert.equal(total(), before);
    });
  });

  it('refuses tampered, expired, wrong-audience, wrong-issuer and wrongly signed tokens with 401', async () => {
    const other = await generateKeyPair('RS256');
    const bad = {
      tampered: `${await sign()}x`,
      expired: await sign({ exp: Math.floor(Date.now() / 1000) - 60 }),
      audience: await sign({ aud: 'someone-else' }),
      issuer: await sign({ iss: 'not-identity' }),
      signedByOther: await sign({ key: other.privateKey }),
      junk: 'not-a-jwt',
    };
    await withGateway(check(), async (base) => {
      const before = total();
      for (const [label, token] of Object.entries(bad)) {
        const response = await fetch(`${base}/api/catalogue/services`, { headers: { authorization: `Bearer ${token}` } });
        assert.equal(response.status, 401, label);
        assert.equal((await response.json()).error.code, 'INVALID_TOKEN', label);
      }
      assert.equal(total(), before);
    });
  });

  it('forwards a valid token to the service unchanged, for every method', async () => {
    const token = await sign();
    await withGateway(check(), async (base) => {
      for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
        const response = await fetch(`${base}/api/catalogue/services/abc`, { method, headers: { authorization: `Bearer ${token}` }, body: method === 'GET' ? undefined : '{}' });
        assert.equal(response.status, 200, method);
        const seen = hits.catalogue.at(-1);
        assert.equal(seen.url, '/api/services/abc');
        assert.equal(seen.headers.authorization, `Bearer ${token}`);
      }
    });
  });

  it('lets the public routes through with no token: sign-in, refresh, keys, public service browse, health', async () => {
    await withGateway(check(), async (base) => {
      const open = [
        ['POST', '/api/identity/auth/login'],
        ['POST', '/api/identity/auth/refresh'],
        ['POST', '/api/identity/auth/logout'],
        ['POST', '/api/identity/auth/password-reset/confirm'],
        ['GET', '/api/identity/auth/jwks'],
        ['GET', '/api/catalogue/public/services?search=x'],
        ['GET', '/api/catalogue/public/services/abc'],
        ['GET', '/api/identity/health'],
        ['GET', '/api/catalogue/health'],
      ];
      for (const [method, path] of open) {
        const response = await fetch(`${base}${path}`, { method, body: method === 'POST' ? '{}' : undefined, headers: { 'content-type': 'application/json' } });
        assert.equal(response.status, 200, `${method} ${path}`);
      }
    });
  });

  it('does not treat look-alike paths as public', async () => {
    await withGateway(check(), async (base) => {
      for (const path of ['/api/catalogue/publicity', '/api/catalogue/public', '/api/identity/auth', '/api/identity/accounts', '/api/catalogue/offices/public/x']) {
        const response = await fetch(`${base}${path}`);
        assert.equal(response.status, 401, path);
      }
    });
  });

  it('serves pages and static assets without a token (the token is fetched by the page script)', async () => {
    await withGateway(check(), async (base) => {
      for (const path of ['/login', '/accounts', '/_ccms/identity/_next/static/a.js']) {
        assert.equal((await fetch(`${base}${path}`)).status, 200, path);
      }
    });
  });

  it('answers 503, not 401, when the public keys cannot be reached and are not cached', async () => {
    const unreachable = createTokenCheck({ jwksUrl: 'http://127.0.0.1:9/api/auth/jwks' });
    await withGateway(unreachable, async (base) => {
      const response = await fetch(`${base}/api/catalogue/offices`, { headers: { authorization: `Bearer ${await sign()}` } });
      assert.equal(response.status, 503);
      assert.equal((await response.json()).error.code, 'AUTH_UNAVAILABLE');
    });
  });

  it('is off when no checker is given (existing behaviour)', async () => {
    await withGateway(undefined, async (base) => {
      assert.equal((await fetch(`${base}/api/catalogue/offices`)).status, 200);
    });
  });
});
