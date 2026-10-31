import { strict as assert } from 'node:assert';
import { after, before, describe, it } from 'node:test';
import { makeWithGateway, startUpstreams } from './helpers.js';
import { isMachineKeyRequest } from '../src/lib/routes.js';

// EB6 / EB7: FMS pulls GET /api/calendar/declarations with a machine key, which is not a user token.
// The gateway lets exactly that request through to Core (Core checks the key); everything else
// still needs a valid user token.

let stack;
let targets;
let seen;
before(async () => {
  stack = await startUpstreams(['catalogue']);
  ({ targets, seen } = stack);
});
after(() => stack.close());

// Catalogue and Calendar are two names for the same service (Core), as in the real routing table.
const withGateway = makeWithGateway(() => ({ ...targets, calendar: targets.catalogue }));
const last = () => seen.catalogue[seen.catalogue.length - 1];
const KEY = 'ccms_mk_abc123.secretsecretsecret';

// A user-token check that refuses everything it is given, so any request that reaches it is a failure to pass.
const refuseAll = async () => ({ ok: false, status: 401, code: 'INVALID_TOKEN', message: 'Invalid or expired token' });

describe('EB6 machine key on the calendar pull route', () => {
  it('forwards GET /api/calendar/declarations with a machine key to Core, unchanged, without a user-token check', async () => {
    let checked = 0;
    const tokenCheck = async (token) => {
      checked += 1;
      return refuseAll(token);
    };
    await withGateway({ tokenCheck }, async (base) => {
      const before = seen.catalogue.length;
      const response = await fetch(`${base}/api/calendar/declarations?from=2026-08-17&to=2026-12-12&limit=100`, {
        headers: { authorization: `Bearer ${KEY}` },
      });
      assert.equal(response.status, 200);
      assert.equal(checked, 0, 'the user-token check must not run for a machine key');
      assert.equal(seen.catalogue.length, before + 1);
      assert.equal(last().method, 'GET');
      assert.equal(last().url, '/api/declarations?from=2026-08-17&to=2026-12-12&limit=100');
      assert.equal(last().headers.authorization, `Bearer ${KEY}`);
    });
  });

  it('accepts a trailing slash on the same path', async () => {
    await withGateway({ tokenCheck: refuseAll }, async (base) => {
      const response = await fetch(`${base}/api/calendar/declarations/`, { headers: { authorization: `Bearer ${KEY}` } });
      assert.equal(response.status, 200);
    });
  });

  it('never lets the shared service key reach Core from outside', async () => {
    await withGateway({ tokenCheck: refuseAll }, async (base) => {
      await fetch(`${base}/api/calendar/declarations`, { headers: { authorization: `Bearer ${KEY}`, 'x-service-key': 'guess' } });
      assert.equal(last().headers['x-service-key'], undefined);
    });
  });

  it('still requires a user token for a machine key on any other path', async () => {
    await withGateway({ tokenCheck: refuseAll }, async (base) => {
      const before = seen.catalogue.length;
      for (const path of ['/api/calendar/exceptions', '/api/calendar/machine-keys', '/api/calendar/schedule', '/api/calendar/declarations/extra', '/api/calendar/declarations-other']) {
        const response = await fetch(`${base}${path}`, { headers: { authorization: `Bearer ${KEY}` } });
        assert.equal(response.status, 401, path);
        assert.equal((await response.json()).error.code, 'INVALID_TOKEN');
      }
      assert.equal(seen.catalogue.length, before, 'nothing may reach Core');
    });
  });

  it('still requires a user token for a machine key on the catalogue name (same service, different name)', async () => {
    await withGateway({ tokenCheck: refuseAll }, async (base) => {
      const before = seen.catalogue.length;
      const response = await fetch(`${base}/api/catalogue/declarations`, { headers: { authorization: `Bearer ${KEY}` } });
      assert.equal(response.status, 401);
      assert.equal(seen.catalogue.length, before);
    });
  });

  it('does not allow a machine key to write: POST, PUT, PATCH and DELETE need a user token', async () => {
    await withGateway({ tokenCheck: refuseAll }, async (base) => {
      const before = seen.catalogue.length;
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        const response = await fetch(`${base}/api/calendar/declarations`, { method, headers: { authorization: `Bearer ${KEY}` }, body: method === 'DELETE' ? undefined : '{}' });
        assert.equal(response.status, 401, method);
      }
      assert.equal(seen.catalogue.length, before);
    });
  });

  it('still checks an ordinary token on the pull route (a user token is not skipped)', async () => {
    let checked = 0;
    const tokenCheck = async () => {
      checked += 1;
      return { ok: false, status: 401, code: 'INVALID_TOKEN', message: 'Invalid or expired token' };
    };
    await withGateway({ tokenCheck }, async (base) => {
      const response = await fetch(`${base}/api/calendar/declarations`, { headers: { authorization: 'Bearer aaa.bbb.ccc' } });
      assert.equal(response.status, 401);
      assert.equal(checked, 1);
    });
  });

  it('refuses a request with no credential at all', async () => {
    await withGateway({ tokenCheck: refuseAll }, async (base) => {
      const response = await fetch(`${base}/api/calendar/declarations`);
      assert.equal(response.status, 401);
      assert.equal((await response.json()).error.code, 'UNAUTHORIZED');
    });
  });

  it('refuses a key that only looks like a machine key through another scheme or case', async () => {
    await withGateway({ tokenCheck: refuseAll }, async (base) => {
      for (const authorization of ['Basic ccms_mk_abc.secret', 'Bearer CCMS_MK_abc.secret', 'Bearer xccms_mk_abc.secret', `Token ${KEY}`]) {
        const response = await fetch(`${base}/api/calendar/declarations`, { headers: { authorization } });
        assert.equal(response.status, 401, authorization);
      }
    });
  });

  it('the rule itself: only GET/HEAD, only calendar, only this exact path, only the key prefix', () => {
    assert.equal(isMachineKeyRequest('calendar', '/api/declarations', 'GET', KEY), true);
    assert.equal(isMachineKeyRequest('calendar', '/api/declarations?from=a', 'HEAD', KEY), true);
    assert.equal(isMachineKeyRequest('calendar', '/api/declarations/', 'GET', KEY), true);
    assert.equal(isMachineKeyRequest('calendar', '/api/declarations', 'POST', KEY), false);
    assert.equal(isMachineKeyRequest('catalogue', '/api/declarations', 'GET', KEY), false);
    assert.equal(isMachineKeyRequest('calendar', '/api/exceptions', 'GET', KEY), false);
    assert.equal(isMachineKeyRequest('calendar', '/api/declarations', 'GET', 'aaa.bbb.ccc'), false);
    assert.equal(isMachineKeyRequest('calendar', '/api/declarations', 'GET', null), false);
  });
});
