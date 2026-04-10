/* DateScan Service Worker
 *
 * Purpose: satisfy the PWA / TWA installability requirements for
 * Google Play and provide a basic offline fallback. This SW uses:
 *
 *   - Precache for the app shell (HTML, manifest, core icons)
 *   - Network-first for navigation requests, falling back to the
 *     cached shell when offline
 *   - Stale-while-revalidate for static assets (JS, CSS, images)
 *   - Network-only (bypass cache) for API calls — the AI chat and
 *     payment endpoints MUST NOT be served from cache
 *
 * Bump CACHE_VERSION whenever you ship a breaking change to the shell.
 */

const CACHE_VERSION = 'datescan-v1';
const SHELL_CACHE = `${CACHE_VERSION}-shell`;
const ASSET_CACHE = `${CACHE_VERSION}-assets`;

const SHELL_URLS = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/icon-192.png',
  '/icon-512.png',
  '/apple-touch-icon.png',
  '/offline.html'
];

// Paths that must never be cached — requests go straight to network.
const NETWORK_ONLY_PREFIXES = [
  '/api/',
  '/checkout',
  '/auth'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE).then((cache) => {
      // addAll is all-or-nothing; if any shell URL 404s the install
      // fails. We fall back to per-URL puts so a missing optional
      // asset (e.g. offline.html) doesn't block install.
      return Promise.all(
        SHELL_URLS.map((url) =>
          fetch(url, { cache: 'reload' })
            .then((res) => (res && res.ok ? cache.put(url, res) : null))
            .catch(() => null)
        )
      );
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => !k.startsWith(CACHE_VERSION))
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

function isNetworkOnly(url) {
  return NETWORK_ONLY_PREFIXES.some((p) => url.pathname.startsWith(p));
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // let cross-origin pass

  if (isNetworkOnly(url)) return; // bypass cache entirely

  // Navigation → network-first, fallback to cached shell, then offline page.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(SHELL_CACHE).then((c) => c.put('/', copy)).catch(() => {});
          return res;
        })
        .catch(() =>
          caches.match(req).then((m) => m || caches.match('/') || caches.match('/offline.html'))
        )
    );
    return;
  }

  // Static assets → stale-while-revalidate
  event.respondWith(
    caches.open(ASSET_CACHE).then(async (cache) => {
      const cached = await cache.match(req);
      const fetchPromise = fetch(req)
        .then((res) => {
          if (res && res.ok) cache.put(req, res.clone());
          return res;
        })
        .catch(() => cached);
      return cached || fetchPromise;
    })
  );
});
