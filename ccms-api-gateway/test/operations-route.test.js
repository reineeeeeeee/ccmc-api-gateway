import { strict as assert } from 'node:assert';
import { after, before, describe, it } from 'node:test';
import { makeWithGateway, startUpstreams } from './helpers.js';
import { serviceTargets } from '../src/lib/routes.js';

let stack;
let targets;
let seen;

before(async () => {
  stack = await startUpstreams(['operations']);
  ({ targets, seen } = stack);
});

after(() => stack.close());

const withGateway = makeWithGateway(() => targets);
const lastRequest = () => seen.operations.at(-1);

describe('TT1 Operations routing', () => {
  it('uses OPERATIONS_URL and removes a trailing slash', () => {
    const configured = serviceTargets({ OPERATIONS_URL: 'https://operations.example.test/' });
    assert.equal(configured.operations, 'https://operations.example.test');
  });

  it('routes GET /api/operations/health without a token', async () => {
    const shouldNotCheckPublicRoute = async () => {
      throw new Error('the public health route must not verify a token');
    };

    await withGateway({ tokenCheck: shouldNotCheckPublicRoute }, async (base) => {
      const response = await fetch(`${base}/api/operations/health`);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('x-from'), 'operations');
      assert.equal(lastRequest().method, 'GET');
      assert.equal(lastRequest().url, '/api/health');
    });
  });

  it('returns 401 for every non-health Operations path without a token', async () => {
    const tokenCheck = async () => ({ ok: true });

    await withGateway({ tokenCheck }, async (base) => {
      const before = seen.operations.length;
      const requests = [
        ['GET', '/api/operations/transactions'],
        ['GET', '/api/operations/settings'],
        ['POST', '/api/operations/transactions'],
        ['GET', '/api/operations/health/details'],
        ['GET', '/api/operations/healthcheck'],
      ];

      for (const [method, path] of requests) {
        const response = await fetch(`${base}${path}`, {
          method,
          body: method === 'GET' ? undefined : '{}',
          headers: method === 'GET' ? undefined : { 'content-type': 'application/json' },
        });
        assert.equal(response.status, 401, `${method} ${path}`);
        assert.equal((await response.json()).error.code, 'UNAUTHORIZED', `${method} ${path}`);
      }

      assert.equal(seen.operations.length, before, 'unauthenticated requests must not reach Operations');
    });
  });

  it('forwards an authenticated Operations request, including its method, query, body and required headers', async () => {
    let checkedToken;
    const tokenCheck = async (token) => {
      checkedToken = token;
      return { ok: true };
    };

    await withGateway({ tokenCheck }, async (base) => {
      const response = await fetch(`${base}/api/operations/transactions?office=abc`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer operations-token',
          'content-type': 'application/json',
          'x-correlation-id': 'operations-correlation-123',
        },
        body: JSON.stringify({ service_id: 'service-1' }),
      });

      assert.equal(response.status, 200);
      assert.equal(checkedToken, 'operations-token');
      assert.equal(response.headers.get('x-correlation-id'), 'operations-correlation-123');

      const request = lastRequest();
      assert.equal(request.method, 'POST');
      assert.equal(request.url, '/api/transactions?office=abc');
      assert.equal(request.headers.authorization, 'Bearer operations-token');
      assert.equal(request.headers['x-correlation-id'], 'operations-correlation-123');
      assert.equal(request.headers['x-forwarded-proto'], 'http');
      assert.ok(request.headers['x-forwarded-host']);
      assert.deepEqual(JSON.parse(request.body), { service_id: 'service-1' });
    });
  });

  it('never exposes Operations job endpoints through the Gateway', async () => {
    const tokenCheck = async () => ({ ok: true });

    await withGateway({ tokenCheck }, async (base) => {
      const before = seen.operations.length;
      for (const path of [
        '/api/operations/jobs/outbox',
        '/api/operations/jobs/auto-close',
        '/api/operations/jobs/compute-pending',
        '/api/operations/jobs/receipt-emails',
      ]) {
        for (const method of ['GET', 'POST']) {
          const response = await fetch(`${base}${path}`, {
            method,
            headers: { authorization: 'Bearer operations-token' },
            body: method === 'POST' ? '{}' : undefined,
          });
          assert.equal(response.status, 404, `${method} ${path}`);
          assert.equal((await response.json()).error.code, 'ROUTE_NOT_FOUND', `${method} ${path}`);
        }
      }
      assert.equal(seen.operations.length, before, 'job requests must not reach Operations');
    });
  });

  it('the Operations route exports every supported method and uses OPERATIONS_URL', async () => {
    process.env.OPERATIONS_URL = targets.operations;
    process.env.VERIFY_TOKENS = 'false';
    process.env.REQUIRE_TLS = 'false';
    globalThis.__ccmsGateway = undefined;

    try {
      const route = await import('../src/app/api/operations/[...path]/route.js');
      for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
        assert.equal(typeof route[method], 'function', method);
      }

      const response = await route.GET(new Request('http://localhost/api/operations/health'));
      assert.equal(response.status, 200);
      assert.equal(lastRequest().url, '/api/health');
    } finally {
      globalThis.__ccmsGateway = undefined;
      delete process.env.OPERATIONS_URL;
      delete process.env.VERIFY_TOKENS;
      delete process.env.REQUIRE_TLS;
    }
  });
});
