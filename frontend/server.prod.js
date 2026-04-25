/**
 * Production HTTP server for TanStack Start.
 * 
 * The compiled dist/server/server.js only exports a `fetch()` handler.
 * This wrapper creates an actual HTTP listener for Render deployment.
 */
import { createServer } from 'node:http';
import { Readable } from 'node:stream';

const PORT = process.env.PORT || 3000;

async function loadApp() {
  const mod = await import('./dist/server/server.js');
  return mod.default;
}

loadApp().then((app) => {
  const server = createServer(async (req, res) => {
    try {
      // Build the full URL from the incoming request
      const protocol = req.headers['x-forwarded-proto'] || 'http';
      const host = req.headers['host'] || `localhost:${PORT}`;
      const url = new URL(req.url || '/', `${protocol}://${host}`);

      // Collect the request body if present
      let body = null;
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const chunks = [];
        for await (const chunk of req) {
          chunks.push(chunk);
        }
        body = Buffer.concat(chunks);
      }

      // Build a standard Web Request object
      const webRequest = new Request(url.toString(), {
        method: req.method,
        headers: Object.entries(req.headers).reduce((h, [k, v]) => {
          if (v) h.set(k, Array.isArray(v) ? v.join(', ') : v);
          return h;
        }, new Headers()),
        body: body?.length ? body : undefined,
        duplex: 'half',
      });

      // Call the TanStack Start fetch handler
      const webResponse = await app.fetch(webRequest);

      // Write status + headers
      res.writeHead(webResponse.status, Object.fromEntries(webResponse.headers.entries()));

      // Stream the body
      if (webResponse.body) {
        const reader = webResponse.body.getReader();
        const push = async () => {
          while (true) {
            const { done, value } = await reader.read();
            if (done) { res.end(); return; }
            res.write(value);
          }
        };
        await push();
      } else {
        res.end();
      }
    } catch (err) {
      console.error('[Server Error]', err);
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Server Error');
    }
  });

  server.listen(PORT, () => {
    console.log(`\n🔥 Phoenix Frontend running on http://localhost:${PORT}\n`);
  });
}).catch((err) => {
  console.error('Failed to load app:', err);
  process.exit(1);
});
