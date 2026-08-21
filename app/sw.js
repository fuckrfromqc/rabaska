// Rabaska service worker.
//
// Hand-written, not generated. Every line here is part of the security story, so
// it is not a place to take a dependency on a build plugin whose update policy
// you inherit rather than choose.
//
// The policy that matters: THIS WORKER NEVER SILENTLY UPDATES. A stock service
// worker fetches a new version in the background and swaps it in on next launch.
// For an app whose pitch is "trust me with your private keys" that is a remote
// code execution channel: an attacker who compromises the origin pushes new
// JavaScript to every device that already installed. Here, a new build is
// downloaded but parked, the user is told, and it activates only on an explicit
// action. Combined with the build hash shown on both screens during a transfer,
// two devices running different code is visible in one glance.

const BUILD = "__BUILD_HASH__"; // replaced at build time
const CACHE = `rabaska-${BUILD}`;

// Generated at build time. Listed explicitly rather than globbed, because a
// glob will happily cache something that should not be there.
const PRECACHE = [
  './',
  './index.html',
  './app.js',
  './style.css',
  './rabaska_core.js',
  './rabaska_core_bg.wasm',
  './manifest.webmanifest',
  './icon-192.png',
  './icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      // No-store so an intermediary cache cannot serve a stale or substituted
      // bundle into the precache.
      await cache.addAll(PRECACHE.map((u) => new Request(u, { cache: 'no-store' })));
      // Deliberately NOT skipWaiting(). The new build waits.
    })()
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n)));
      await self.clients.claim();
    })()
  );
});

// Cache-first, and network only for what is missing. After install the app never
// needs the network again: turn on airplane mode and it still works, which is a
// two-second test the user can run themselves and is more persuasive than any
// privacy policy.
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Nothing outside our own origin, ever. The CSP already forbids it; this is
  // the second lock on the same door.
  if (url.origin !== self.location.origin) {
    event.respondWith(new Response('blocked: cross-origin', { status: 403 }));
    return;
  }

  event.respondWith(
    (async () => {
      const hit = await caches.match(event.request, { cacheName: CACHE });
      if (hit) return hit;
      try {
        return await fetch(event.request);
      } catch {
        // Offline and not precached. Fall back to the shell so a deep link
        // still opens the app rather than a browser error page.
        return (await caches.match('./index.html', { cacheName: CACHE }))
          || new Response('offline', { status: 503 });
      }
    })()
  );
});

// Explicit update path. The page checks on user action, never on a timer.
self.addEventListener('message', (event) => {
  if (event.data === 'rabaska:activate-update') {
    self.skipWaiting();
  }
  if (event.data === 'rabaska:build') {
    event.source.postMessage({ build: BUILD });
  }
});
