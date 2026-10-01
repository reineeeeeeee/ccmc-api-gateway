import { strict as assert } from 'node:assert';
import http from 'node:http';
import { after, before, describe, it } from 'node:test';
import { createGateway } from '../src/server.js';

const seen = { identity: [], logs: [], catalogue: [] };

function upstream(name) {
  return http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen[name].push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
      res.writeHead(200, { 'content-type': 'application/json', 'x-from': name });
      res.end(JSON.stringify({ service: name, url: req.url }));
    });
  });
}

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
const servers = [];
let targets;

before(async () => {
  targets = {};
  for (const name of Object.keys(seen)) {
    const server = upstream(name);
    servers.push(server);
    targets[name] = `http://127.0.0.1:${await listen(server)}`;
  }
});
after(() => servers.forEach((s) => s.close()));

async function withGateway(options, fn) {
  const gateway = createGateway({ targets, ...options });
  const port = await listen(gateway);
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    gateway.closeAllConnections?.();
    gateway.close();
  }
}

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

  it('serves pages and static assets from the owning service', async () => {
    await withGateway({}, async (base) => {
      // Each repo owns its own pages: Identity has sign-in and accounts, the Core repo has the public
      // home page, Offices, Services and Calendar.
      for (const path of ['/accounts', '/login', '/office', '/campus', '/reset-password']) {
        await fetch(`${base}${path}`);
        assert.equal(last('identity').url, path, `${path} is hosted by Identity`);
      }
      for (const path of ['/', '/offices', '/services', '/services/abc-123', '/public/abc-123', '/calendar']) {
        await fetch(`${base}${path}`);
        assert.equal(last('catalogue').url, path, `${path} is hosted by the Core repo`);
      }
      await fetch(`${base}/logs`);
      assert.equal(last('logs').url, '/logs');
      await fetch(`${base}/_ccms/identity/_next/static/chunk.js`);
      assert.equal(last('identity').url, '/_next/static/chunk.js');
      await fetch(`${base}/_ccms/catalogue/_next/static/chunk.js`);
      assert.equal(last('catalogue').url, '/_next/static/chunk.js');
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
      for (const path of ['/api/nope/x', '/nothing-here', '/api/logs/audit-events', '/api/logs/audit-events/', '/api/logs//audit-events', '/api/logs/%2e%2e/audit-events', '/api/identity/../logs/audit-events']) {
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

  it('answers /healthz itself', async () => {
    await withGateway({ requireTls: true }, async (base) => {
      const response = await fetch(`${base}/healthz`);
      assert.equal(response.status, 200);
    });
  });
});

describe('HTTPS only (TT2 AC2)', () => {
  it('redirects plain-HTTP GET and refuses other methods when TLS is required', async () => {
    await withGateway({ requireTls: true }, async (base) => {
      const before = seen.identity.length;
      const get = await fetch(`${base}/accounts?x=1`, { redirect: 'manual' });
      assert.equal(get.status, 308);
      assert.equal(get.headers.get('location'), `https://${new URL(base).host}/accounts?x=1`);
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

describe('gateway websocket (dev hot reload)', () => {
  it('keeps the prefixed path when upgrading, as the Next dev server expects', async () => {
    const paths = [];
    const upstreamServer = http.createServer();
    upstreamServer.on('upgrade', (req, socket) => {
      paths.push(req.url);
      socket.end('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
    });
    const upstreamPort = await listen(upstreamServer);
    const gateway = createGateway({ targets: { ...targets, identity: `http://127.0.0.1:${upstreamPort}` } });
    const port = await listen(gateway);
    try {
      await new Promise((resolve, reject) => {
        const req = http.request({ port, host: '127.0.0.1', path: '/_ccms/identity/_next/hmr?id=1', headers: { Connection: 'Upgrade', Upgrade: 'websocket' } });
        req.on('upgrade', (res, socket) => { socket.destroy(); resolve(); });
        req.on('error', reject);
        req.end();
      });
      assert.deepEqual(paths, ['/_ccms/identity/_next/hmr?id=1']);
    } finally {
      gateway.closeAllConnections?.();
      gateway.close();
      upstreamServer.close();
    }
  });
});
