import http from 'node:http';
import { createGateway } from '../src/lib/gateway.js';

export const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));

/** Runs a (Request) => Response handler on a real port, the way a platform would call a Route Handler. */
export function serveHandler(handler) {
  return http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) headers.set(name, Array.isArray(value) ? value.join(', ') : value);
    const request = new Request(`http://${req.headers.host}${req.url}`, {
      method: req.method,
      headers,
      body: ['GET', 'HEAD'].includes(req.method) || chunks.length === 0 ? undefined : Buffer.concat(chunks),
    });
    const response = await handler(request);
    const out = {};
    for (const [name, value] of response.headers) if (name !== 'set-cookie') out[name] = value;
    const cookies = response.headers.getSetCookie();
    if (cookies.length) out['set-cookie'] = cookies;
    res.writeHead(response.status, out);
    res.end(Buffer.from(await response.arrayBuffer()));
  });
}

/** A fake service that records what reached it. */
export function upstream(name, seen, { cookies } = {}) {
  return http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen[name].push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
      const headers = { 'content-type': 'application/json', 'x-from': name };
      if (cookies) headers['set-cookie'] = cookies;
      res.writeHead(200, headers);
      res.end(JSON.stringify({ service: name, url: req.url }));
    });
  });
}

export async function startUpstreams(names, options = {}) {
  const seen = Object.fromEntries(names.map((n) => [n, []]));
  const servers = [];
  const targets = {};
  for (const name of names) {
    const server = upstream(name, seen, options[name]);
    servers.push(server);
    targets[name] = `http://127.0.0.1:${await listen(server)}`;
  }
  return { seen, targets, close: () => servers.forEach((s) => s.close()) };
}

export function makeWithGateway(getTargets) {
  return async function withGateway(options, fn) {
    const server = serveHandler(createGateway({ targets: getTargets(), ...options }));
    const port = await listen(server);
    try {
      return await fn(`http://127.0.0.1:${port}`);
    } finally {
      server.closeAllConnections?.();
      server.close();
    }
  };
}
