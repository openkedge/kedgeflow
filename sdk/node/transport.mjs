import { request } from 'node:https';

export function fixedHttps(value) {
  const u = new URL(value);
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || u.href !== value) throw new Error('fixed HTTPS URL required');
  return value;
}

// Documented SDK fetch injection, native verified mTLS, explicit endpoint pins,
// bounded non-streaming responses, no redirects or environment proxy routing.
export function mtlsFetch({ ca, cert, key, allowedUrls, timeoutMs = 5000 }) {
  if (![ca, cert, key].every(v => (typeof v === 'string' || Buffer.isBuffer(v)) && v.length > 0) || !Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 30000) throw new Error('pinned TLS material and bounded timeout required');
  const allowed = new Set(allowedUrls.map(fixedHttps));
  return (input, init = {}) => new Promise((resolve, reject) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (!allowed.has(url) || (init.method ?? 'POST') !== 'POST' || typeof init.body !== 'string' || Buffer.byteLength(init.body) > 1 << 20) { reject(new Error('unapproved transport request')); return; }
    const headers = Object.fromEntries(new Headers(init.headers));
    let timer;
    const fail = error => { clearTimeout(timer); reject(new Error(`pinned transport unavailable (${error?.code ?? 'deadline'})`)); };
    const req = request(url, { method: 'POST', ca, cert, key, rejectUnauthorized: true, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'], headers, signal: init.signal, agent: false }, res => {
      let size = 0; const chunks = [];
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 1 << 20) { req.destroy(); fail(); } else chunks.push(chunk);
      });
      res.on('error', fail);
      res.on('end', () => {
        clearTimeout(timer);
        if (size > 1 << 20) return;
        const response = new Response(Buffer.concat(chunks), { status: res.statusCode, headers: res.headers });
        Object.defineProperty(response, 'url', { value: url });
        resolve(response);
      });
    });
    req.on('error', fail);
    timer = setTimeout(() => { req.destroy(); fail(); }, timeoutMs);
    req.end(init.body);
  });
}
