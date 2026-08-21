// CyberWatch service worker.
//
// Paths are RELATIVE. The previous version precached "/", "/index.html", … —
// absolute root paths that, on a project page like
// https://<user>.github.io/Cyberwatch/, resolved to the USER root instead of
// the project subpath. cache.addAll() rejects if any request 404s, so install
// failed and the worker never activated: no offline support at all, which was
// the entire point of shipping one.

const CACHE = "cyberwatch-v3";
const PRECACHE = [
  "./",
  "./index.html",
  "./style.css",
  "./app.js",
  "./manifest.json",
];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE)
      // addAll() is atomic — one 404 discards the whole precache. Add
      // individually so a single missing asset can't block activation.
      .then((c) => Promise.allSettled(PRECACHE.map((u) => c.add(u))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") return;

  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;   // never cache third-party

  // `includes` rather than `startsWith("/data/")`: under a project subpath the
  // real path is /Cyberwatch/data/intel.json, which the old check never matched,
  // so live intel fell through to the cache-first branch.
  if (url.pathname.includes("/data/") || url.pathname.includes("/api/")) {
    e.respondWith(networkFirst(e.request));
  } else {
    e.respondWith(staleWhileRevalidate(e.request));
  }
});

async function staleWhileRevalidate(req) {
  const cache = await caches.open(CACHE);
  const hit = await cache.match(req, { ignoreSearch: true });
  const fetching = fetch(req)
    .then((res) => {
      if (res && res.ok) cache.put(req, res.clone());
      return res;
    })
    .catch(() => hit);
  return hit || fetching;
}

async function networkFirst(req) {
  const cache = await caches.open(CACHE);
  try {
    const res = await fetch(req);
    if (res.ok) {
      // Strip the ?v= cache-buster so the fallback lookup can find this later.
      cache.put(new Request(new URL(req.url).pathname), res.clone());
    }
    return res;
  } catch {
    const fallback = await cache.match(new Request(new URL(req.url).pathname));
    if (fallback) return fallback;
    return new Response(JSON.stringify({ items: [], offline: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
}
