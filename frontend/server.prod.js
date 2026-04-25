/**
 * Production HTTP server for TanStack Start.
 *
 * The compiled dist/server/server.js only exports a `fetch()` handler.
 * This wrapper creates an actual HTTP listener and serves static assets
 * from dist/client/ for Render deployment.
 */
import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const PORT = process.env.PORT || 3000;
const CLIENT_DIR = join(__dirname, 'dist', 'client');

// MIME type mapping for static assets
const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.mjs': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.webp': 'image/webp',
};

/**
 * Try to serve a static file from dist/client.
 * Returns true if the file was served, false otherwise.
 */
function tryServeStatic(req, res) {
  const url = new URL(req.url || '/', `http://localhost`);
  const filePath = join(CLIENT_DIR, url.pathname);

  // Security: prevent directory traversal
  if (!filePath.startsWith(CLIENT_DIR)) return false;

  try {
    const stat = statSync(filePath);
    if (!stat.isFile()) return false;

    const ext = extname(filePath).toLowerCase();
    const mime = MIME_TYPES[ext] || 'application/octet-stream';
    const content = readFileSync(filePath);

    // Cache hashed assets aggressively (they have content hashes in filenames)
    const isHashed = /\.[a-zA-Z0-9]{8,}\.(js|css|png|jpg|svg|woff2?)$/.test(filePath);

    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Length': content.length,
      'Cache-Control': isHashed
        ? 'public, max-age=31536000, immutable'
        : 'public, max-age=3600',
    });
    res.end(content);
    return true;
  } catch {
    return false;
  }
}

async function loadApp() {
  const mod = await import('./dist/server/server.js');
  return mod.default;
}

loadApp().then((app) => {
  const server = createServer(async (req, res) => {
    try {
      // 1. Try serving static assets first (CSS, JS, images, fonts)
      if (tryServeStatic(req, res)) return;

      // 2. Otherwise, delegate to TanStack Start SSR handler
      const protocol = req.headers['x-forwarded-proto'] || 'http';
      const host = req.headers['host'] || `localhost:${PORT}`;
      const url = new URL(req.url || '/', `${protocol}://${host}`);

      // Collect body for non-GET requests
      let body = null;
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        body = Buffer.concat(chunks);
      }

      // Build Web Standard Request
      const webRequest = new Request(url.toString(), {
        method: req.method,
        headers: Object.entries(req.headers).reduce((h, [k, v]) => {
          if (v) h.set(k, Array.isArray(v) ? v.join(', ') : v);
          return h;
        }, new Headers()),
        body: body?.length ? body : undefined,
        duplex: 'half',
      });

      // Call TanStack Start fetch handler
      const webResponse = await app.fetch(webRequest);

      // Write response
      const headers = {};
      webResponse.headers.forEach((v, k) => { headers[k] = v; });
      res.writeHead(webResponse.status, headers);

      if (webResponse.body) {
        const reader = webResponse.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
        }
      }
      res.end();
    } catch (err) {
      console.error('[Server Error]', err);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
      }
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
