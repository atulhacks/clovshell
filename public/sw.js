// clovshell service worker: cache-first for engine wasm + hashed assets,
// network-first for the app shell so deploys show up on the next reload.
// The engines are ~7 MB — caching them is what makes "works offline" real.
//
// ignoreVary everywhere: the dev/preview server tags assets with
// `Vary: Origin`, which would make an entry stored by one fetch mode
// (plain SW fetch, no Origin header) invisible to another (module script,
// with Origin) — every lookup here is same-origin, so Vary is noise.

const CACHE = 'clovshell-v1.1';

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      // precache the app shell + the two stable-named engine wasm files so
      // the very first offline reload works — the document that installed
      // this worker was fetched before the worker controlled the page, so
      // it is not in the cache otherwise
      await cache
        .addAll(['./', './index.html', './manifest.webmanifest', './favicon.svg', './wasm/keystone.wasm', './wasm/capstone.wasm'])
        .catch(() => {});
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      for (const key of await caches.keys()) {
        if (key !== CACHE) await caches.delete(key);
      }
      await self.clients.claim();
    })(),
  );
});

self.addEventListener('message', (event) => {
  // the page reports the hashed assets it already loaded (they were fetched
  // before this worker took control, so the fetch handler never saw them)
  const urls = event.data?.type === 'precache' ? event.data.urls : null;
  if (!Array.isArray(urls)) return;
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      await Promise.all(
        urls.map(async (url) => {
          if (typeof url !== 'string' || !url.startsWith(self.location.origin)) return;
          if (await cache.match(url, { ignoreVary: true })) return;
          try {
            const res = await fetch(url);
            if (res.ok) await cache.put(url, res);
          } catch {
            /* best-effort */
          }
        }),
      );
    })(),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // hashed build assets + wasm engines: immutable, cache-first
  const isAsset = /-[A-Za-z0-9_-]{8}\.[a-z0-9]+$/.test(url.pathname) || url.pathname.endsWith('.wasm');
  if (isAsset) {
    event.respondWith(
      caches.match(request, { ignoreVary: true }).then(
        (hit) =>
          hit ??
          fetch(request).then((res) => {
            if (res.ok) {
              const copy = res.clone();
              caches.open(CACHE).then((c) => c.put(request, copy));
            }
            return res;
          }),
      ),
    );
    return;
  }

  // app shell + everything else: network-first, fall back to cache offline
  event.respondWith(
    fetch(request)
      .then((res) => {
        if (res.ok && request.mode === 'navigate') {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(request, copy));
        }
        return res;
      })
      .catch(() => caches.match(request, { ignoreVary: true }).then((hit) => hit ?? Response.error())),
  );
});
