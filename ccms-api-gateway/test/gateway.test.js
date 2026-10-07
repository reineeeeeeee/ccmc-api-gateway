import { strict as assert } from 'node:assert';
import http from 'node:http';
import { after, before, describe, it } from 'node:test';
import { listen, makeWithGateway, startUpstreams } from './helpers.js';

let stack;
let targets;
let seen;
before(async () => {
  stack = await startUpstreams(['identity', 'logs', 'catalogue'], { identity: { cookies: ['refresh=abc; Path=/api/identity/auth; HttpOnly; SameSite=Lax', 'ccms_signed_in=1; Path=/; SameSite=Lax'] } });
  ({ seen, targets } = stack);
});
after(() => stack.close());

const withGateway = makeWithGateway(() => targets);
const last = (name) => seen[name][seen[name].length - 1];

describe('gateway routing (TT2 AC1)', () => {
  it('routes /api/{service}/* to that service, forwarding Authorization and X-Correlation-Id unchanged', async () => {
    await withGateway({}, async (base) => {
      const response = await fetch(`${base}/api/identity/auth/login?next=1`, {
        method: 'POST',
        headers: { authorization: 'Bearer abc.def.ghi', 'x-correlation-id': 'corr-id-12345678', 'content-type': 'application/json' },
        body: JSON.stringify({ hello: 'world' }),
      });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('x-from'), 'identity');
      assert.equal(response.headers.get('x-correlation-id'), 'corr-id-12345678');
      const request = last('identity');
      assert.equal(request.url, '/api/auth/login?next=1');
      assert.equal(request.method, 'POST');
      assert.equal(request.headers.authorization, 'Bearer abc.def.ghi');
      assert.equal(request.headers['x-correlation-id'], 'corr-id-12345678');
      assert.deepEqual(JSON.parse(request.body), { hello: 'world' });
    });
  });

  it('routes each service by name', async () => {
    await withGateway({}, async (base) => {
      await fetch(`${base}/api/catalogue/offices/123`);
      assert.equal(last('catalogue').url, '/api/offices/123');
      await fetch(`${base}/api/logs/health`);
      assert.equal(last('logs').url, '/api/health');
    });
  });

  it('starts a correlation id when the caller has none (or an unsafe one) and echoes it', async () => {
    await withGateway({}, async (base) => {
      for (const headers of [{}, { 'x-correlation-id': 'bad id' }]) {
        const response = await fetch(`${base}/api/identity/health`, { headers });
        const id = response.headers.get('x-correlation-id');
        assert.match(id, /^[0-9a-f-]{36}$/);
        assert.equal(last('identity').headers['x-correlation-id'], id);
      }
    });
  });

  it('never lets a browser send the service key', async () => {
    await withGateway({}, async (base) => {
      await fetch(`${base}/api/catalogue/offices`, { headers: { 'x-service-key': 'guess' } });
      assert.equal(last('catalogue').headers['x-service-key'], undefined);
    });
  });

  it('returns the standard error format for unknown routes, backend-only endpoints and tricky paths', async () => {
    await withGateway({}, async (base) => {
      const logsBefore = seen.logs.length;
      for (const path of ['/api/nope/x', '/nothing-here', '/api/identity-ish', '/api/catalogue/jobs/outbox', '/api/calendar/jobs/calendar-sync', '/api/identity/jobs/outbox', '/api/logs/audit-events', '/api/logs/audit-events/', '/api/logs//audit-events', '/api/logs/%2e%2e/audit-events', '/api/identity/../logs/audit-events']) {
        const response = await fetch(`${base}${path}`, { method: 'POST' });
        assert.equal(response.status, 404, path);
        const body = await response.json();
        assert.equal(body.error.code, 'ROUTE_NOT_FOUND');
        assert.ok(body.error.correlation_id && body.error.timestamp);
      }
      assert.equal(seen.logs.length, logsBefore, 'nothing may reach the Logs service');
    });
  });

  it('lets GET through to the Logs audit viewer but blocks every other method (Sprint 2)', async () => {
    await withGateway({}, async (base) => {
      const get = await fetch(`${base}/api/logs/audit-events?action=SERVICE_CREATED&page=2`, { headers: { authorization: 'Bearer abc.def.ghi' } });
      assert.equal(get.status, 200);
      assert.equal(last('logs').method, 'GET');
      assert.equal(last('logs').url, '/api/audit-events?action=SERVICE_CREATED&page=2');
      assert.equal(last('logs').headers.authorization, 'Bearer abc.def.ghi');

      const logsBefore = seen.logs.length;
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        for (const path of ['/api/logs/audit-events', '/api/logs/audit-events/', '/api/logs/audit-events/123']) {
          const response = await fetch(`${base}${path}`, { method, body: method === 'DELETE' ? undefined : '{}' });
          assert.equal(response.status, 404, `${method} ${path}`);
          assert.equal((await response.json()).error.code, 'ROUTE_NOT_FOUND');
        }
      }
      assert.equal(seen.logs.length, logsBefore, 'no write method may reach the Logs service');

      // Tricky paths stay blocked even for GET.
      for (const path of ['/api/logs//audit-events', '/api/logs/%2e%2e/audit-events']) {
        assert.equal((await fetch(`${base}${path}`)).status, 404, path);
      }
      assert.equal(seen.logs.length, logsBefore);
    });
  });

  it('returns 502 in the standard format when a service is down', async () => {
    await withGateway({ targets: { ...targets, identity: 'http://127.0.0.1:1' } }, async (base) => {
      const response = await fetch(`${base}/api/identity/health`);
      assert.equal(response.status, 502);
      const body = await response.json();
      assert.equal(body.error.code, 'SERVICE_UNAVAILABLE');
      assert.ok(!JSON.stringify(body).includes('ECONNREFUSED'));
    });
  });

});

describe('HTTPS only (TT2 AC2)', () => {
  it('redirects plain-HTTP GET and refuses other methods when TLS is required', async () => {
    await withGateway({ requireTls: true }, async (base) => {
      const before = seen.identity.length;
      const get = await fetch(`${base}/api/identity/accounts?x=1`, { redirect: 'manual' });
      assert.equal(get.status, 308);
      assert.equal(get.headers.get('location'), `https://${new URL(base).host}/api/identity/accounts?x=1`);
      const post = await fetch(`${base}/api/identity/auth/login`, { method: 'POST', body: '{}' });
      assert.equal(post.status, 403);
      assert.equal((await post.json()).error.code, 'HTTPS_REQUIRED');
      assert.equal(seen.identity.length, before, 'plain-HTTP requests never reach a service');
    });
  });

  it('accepts requests that a trusted load balancer says arrived over HTTPS, and adds HSTS', async () => {
    await withGateway({ requireTls: true, trustProxy: true }, async (base) => {
      const response = await fetch(`${base}/api/identity/health`, { headers: { 'x-forwarded-proto': 'https' } });
      assert.equal(response.status, 200);
      assert.match(response.headers.get('strict-transport-security'), /max-age=/);
      const spoof = await fetch(`${base}/api/identity/health`, { headers: { 'x-forwarded-proto': 'http' }, redirect: 'manual' });
      assert.equal(spoof.status, 308);
    });
  });

  it('ignores X-Forwarded-Proto unless the proxy is trusted', async () => {
    await withGateway({ requireTls: true, trustProxy: false }, async (base) => {
      const response = await fetch(`${base}/api/identity/health`, { headers: { 'x-forwarded-proto': 'https' }, redirect: 'manual' });
      assert.equal(response.status, 308);
    });
  });

  it('allows plain HTTP when TLS is not required (local development)', async () => {
    await withGateway({ requireTls: false }, async (base) => {
      assert.equal((await fetch(`${base}/api/identity/health`)).status, 200);
    });
  });
});

describe('proxy behaviour', () => {
  it('keeps every Set-Cookie header separate (the refresh cookie and the signed-in marker)', async () => {
    await withGateway({}, async (base) => {
      const response = await fetch(`${base}/api/identity/auth/login`, { method: 'POST', body: '{}' });
      const cookies = response.headers.getSetCookie();
      assert.equal(cookies.length, 2);
      assert.ok(cookies[0].startsWith('refresh=abc') && cookies[0].includes('Path=/api/identity/auth') && cookies[0].includes('HttpOnly'));
      assert.ok(cookies[1].startsWith('ccms_signed_in=1'));
    });
  });

  it('forwards the browser cookie to the service', async () => {
    await withGateway({}, async (base) => {
      await fetch(`${base}/api/identity/auth/refresh`, { method: 'POST', headers: { cookie: 'refresh=abc' } });
      assert.equal(last('identity').headers.cookie, 'refresh=abc');
    });
  });

  it('never exposes the scheduled jobs of any service, with or without a cron secret', async () => {
    await withGateway({}, async (base) => {
      const before = seen.identity.length + seen.catalogue.length;
      for (const path of ['/api/identity/jobs/outbox', '/api/catalogue/jobs/outbox', '/api/calendar/jobs/calendar-sync', '/api/catalogue/jobs']) {
        for (const method of ['GET', 'POST']) {
          const response = await fetch(`${base}${path}`, { method, headers: { authorization: 'Bearer anything' }, body: method === 'POST' ? '{}' : undefined });
          assert.equal(response.status, 404, `${method} ${path}`);
        }
      }
      assert.equal(seen.identity.length + seen.catalogue.length, before);
    });
  });

  it('maps Catalogue and Calendar to the same Core service', async () => {
    await withGateway({ targets: { ...targets, calendar: targets.catalogue } }, async (base) => {
      await fetch(`${base}/api/calendar/holidays?year=2026`);
      assert.equal(last('catalogue').url, '/api/holidays?year=2026');
    });
  });

  it('passes redirects and empty answers through untouched', async () => {
    const odd = http.createServer((req, res) => {
      if (req.url.includes('redirect')) {
        res.writeHead(302, { location: '/somewhere' });
        return res.end();
      }
      res.writeHead(204);
      res.end();
    });
    const oddPort = await listen(odd);
    try {
      await withGateway({ targets: { ...targets, identity: `http://127.0.0.1:${oddPort}` } }, async (base) => {
        const redirect = await fetch(`${base}/api/identity/redirect`, { redirect: 'manual' });
        assert.equal(redirect.status, 302);
        assert.equal(redirect.headers.get('location'), '/somewhere');
        const empty = await fetch(`${base}/api/identity/nothing`);
        assert.equal(empty.status, 204);
      });
    } finally {
      odd.closeAllConnections?.();
      odd.close();
    }
  });

  it('answers 504 in the standard format when a service is too slow', async () => {
    const slow = http.createServer(() => {});
    const slowPort = await listen(slow);
    try {
      await withGateway({ targets: { ...targets, identity: `http://127.0.0.1:${slowPort}` }, timeoutMs: 150 }, async (base) => {
        const response = await fetch(`${base}/api/identity/health`);
        assert.equal(response.status, 504);
        assert.equal((await response.json()).error.code, 'SERVICE_TIMEOUT');
      });
    } finally {
      slow.closeAllConnections?.();
      slow.close();
    }
  });

  it('forwards the client address chain and the original protocol', async () => {
    await withGateway({ trustProxy: true }, async (base) => {
      await fetch(`${base}/api/catalogue/public/services`, { headers: { 'x-forwarded-for': '203.0.113.7', 'x-forwarded-proto': 'https' } });
      assert.equal(last('catalogue').headers['x-forwarded-for'], '203.0.113.7');
      assert.equal(last('catalogue').headers['x-forwarded-proto'], 'https');
    });
  });
});

describe('route handlers', () => {
  it('/api/health answers for the gateway itself', async () => {
    const { GET } = await import('../src/app/api/health/route.js');
    const response = GET();
    assert.deepEqual(await response.json(), { status: 'ok', service: 'api-gateway' });
  });

  it('the identity route hands every method to the gateway built from the environment', async () => {
    process.env.IDENTITY_URL = targets.identity;
    process.env.VERIFY_TOKENS = 'false';
    process.env.REQUIRE_TLS = 'false';
    globalThis.__ccmsGateway = undefined;
    const route = await import('../src/app/api/identity/[...path]/route.js');
    for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) assert.equal(typeof route[method], 'function', method);
    const response = await route.POST(new Request('http://localhost/api/identity/auth/login', { method: 'POST', body: '{"a":1}' }));
    assert.equal(response.status, 200);
    assert.equal(last('identity').url, '/api/auth/login');
    assert.equal(last('identity').body, '{"a":1}');
    globalThis.__ccmsGateway = undefined;
    delete process.env.IDENTITY_URL;
    delete process.env.VERIFY_TOKENS;
    delete process.env.REQUIRE_TLS;
  });
});
