/* DateScan service worker
 * Caches the app shell and heavy third-party assets (Tailwind, idb,
 * MediaPipe WASM + face-landmarker model) so the app starts fast on
 * weak connections and works mostly offline.
 *
 * Strategies:
 *   - Navigation requests:        network-first, fall back to cached shell
 *   - App shell + CDN libraries:  stale-while-revalidate
 *   - MediaPipe assets:           cache-first (immutable URLs)
 *   - api.datescan.app and any
 *     weather / geocoding APIs:   network-only (never cache personal data)
 */

const VERSION = 'v2';
const SHELL_CACHE = `datescan-shell-${VERSION}`;
const RUNTIME_CACHE = `datescan-runtime-${VERSION}`;
const MODEL_CACHE = `datescan-models-${VERSION}`;

// Things we want available immediately after install.
const SHELL_URLS = [
  '/',
  '/index.html',
  'https://cdn.tailwindcss.com',
  'https://cdn.jsdelivr.net/npm/idb@8.0.0/build/umd.js',
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Playfair+Display:ital,wght@0,500;0,600;0,700;1,500&display=swap',
];

// Hostnames we should NEVER cache — they carry personal data or change often.
const NO_CACHE_HOSTS = new Set([
  'api.datescan.app',
  'api.open-meteo.com',
  'api.bigdatacloud.net',
]);

// Hostnames whose assets are large but content-addressed/immutable
// (MediaPipe WASM + model files) → cache-first.
const MODEL_HOSTS = new Set([
  'storage.googleapis.com', // mediapipe model
]);

// CDNs whose assets are big but versioned → stale-while-revalidate.
const RUNTIME_HOSTS = new Set([
  'cdn.jsdelivr.net',
  'cdn.tailwindcss.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
]);

// ---------- install ----------
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE).then((cache) =>
      // Use addAll-with-individual-fallback so one failing CDN doesn't abort install.
      Promise.all(
        SHELL_URLS.map((url) =>
          cache.add(new Request(url, { mode: 'no-cors' })).catch((err) => {
            console.warn('[SW] precache failed for', url, err);
          })
        )
      )
    )
  );
  // Don't auto-skip waiting; the page will postMessage SKIP_WAITING when ready.
});

// ---------- activate ----------
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => ![SHELL_CACHE, RUNTIME_CACHE, MODEL_CACHE].includes(k))
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// ---------- fetch ----------
self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Only handle GET; POST/PUT etc. should always hit the network.
  if (req.method !== 'GET') return;

  let url;
  try { url = new URL(req.url); } catch { return; }

  // Never cache personal-data endpoints.
  if (NO_CACHE_HOSTS.has(url.hostname)) return;

  // Navigation requests → network-first, fall back to cached shell.
  if (req.mode === 'navigate') {
    event.respondWith(networkFirstShell(req));
    return;
  }

  // MediaPipe / model files (immutable) → cache-first into MODEL_CACHE.
  if (MODEL_HOSTS.has(url.hostname) ||
      url.pathname.includes('/mediapipe-models/') ||
      url.pathname.endsWith('.task') ||
      url.pathname.endsWith('.wasm') ||
      url.pathname.endsWith('.binarypb')) {
    event.respondWith(cacheFirst(req, MODEL_CACHE));
    return;
  }

  // CDN scripts/fonts/styles (versioned but cacheable) → SWR.
  if (RUNTIME_HOSTS.has(url.hostname)) {
    event.respondWith(staleWhileRevalidate(req, RUNTIME_CACHE));
    return;
  }

  // Same-origin static assets → SWR via shell cache.
  if (url.origin === self.location.origin) {
    event.respondWith(staleWhileRevalidate(req, SHELL_CACHE));
    return;
  }

  // Default: just go to network.
});

// ---------- strategies ----------
async function networkFirstShell(request) {
  try {
    const fresh = await fetch(request);
    const cache = await caches.open(SHELL_CACHE);
    cache.put('/index.html', fresh.clone()).catch(() => {});
    return fresh;
  } catch (err) {
    const cached = await caches.match('/index.html')
                || await caches.match('/');
    if (cached) return cached;
    throw err;
  }
}

async function cacheFirst(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);
  if (cached) return cached;
  const fresh = await fetch(request);
  if (fresh && fresh.ok) cache.put(request, fresh.clone()).catch(() => {});
  return fresh;
}

async function staleWhileRevalidate(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cached = await cache.match(request);
  const networkPromise = fetch(request)
    .then((res) => {
      if (res && (res.ok || res.type === 'opaque')) {
        cache.put(request, res.clone()).catch(() => {});
      }
      return res;
    })
    .catch(() => null);
  return cached || (await networkPromise) || Response.error();
}
