// OpenThreat service worker.
//
// Paths are RELATIVE. The previous version precached "/", "/index.html", … —
// absolute root paths that, on a project page like
// https://<user>.github.io/OpenThreat/, resolved to the USER root instead of
// the project subpath. cache.addAll() rejects if any request 404s, so install
// failed and the worker never activated: no offline support at all, which was
// the entire point of shipping one.

// Bump on every release. The activate handler deletes every cache whose name
// is not this one, which is what stops old versioned entries accumulating now
// that staleWhileRevalidate keys on the full URL including ?v=.
const CACHE = "openthreat-v8";
const PRECACHE = [
  "./",
  "./index.html",
  "./style.css",
  "./app.js",
  "./js/query.js",
  "./js/research.js",
  "./js/timetravel.js",
  "./js/library.js",
  "./js/hunt.js",
  "./js/leaks.js",
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
  // real path is /OpenThreat/data/intel.json, which the old check never matched,
  // so live intel fell through to the cache-first branch.
  if (url.pathname.includes("/data/") || url.pathname.includes("/api/")) {
    e.respondWith(networkFirst(e.request));
  } else {
    e.respondWith(staleWhileRevalidate(e.request));
  }
});

async function staleWhileRevalidate(req) {
  const cache = await caches.open(CACHE);

  // Exact match FIRST, query string included.
  //
  // This used to be `cache.match(req, { ignoreSearch: true })`, which made the
  // asset versioning in index.html (`app.js?v=4.0.1`) inert: every version of
  // a file collapsed onto one cache entry, so after a deploy a returning
  // visitor was served the OLD app.js against the NEW data and kept it until
  // some later load happened to revalidate. A version in the URL only forces a
  // reload if the cache treats it as a different URL.
  const exact = await cache.match(req);
  const fetching = fetch(req)
    .then((res) => {
      if (res && res.ok) cache.put(req, res.clone());
      return res;
    })
    .catch(async () => {
      // Offline. NOW the search-agnostic lookup is the right thing: a
      // previous version of the file beats a blank page, and the precache
      // stores unversioned URLs.
      if (exact) return exact;
      return cache.match(req, { ignoreSearch: true });
    });
  return exact || fetching;
}

async function networkFirst(req) {
  const cache = await caches.open(CACHE);
  try {
    const res = await fetch(req);
    if (res.ok) {
      // Key on the bare pathname so the offline fallback below can find this
      // entry regardless of any query string on the original request.
      cache.put(new Request(new URL(req.url).pathname), res.clone());
    }
    return res;
  } catch {
    const fallback = await cache.match(new Request(new URL(req.url).pathname));
    if (fallback) return fallback;
    // Last resort: nothing cached and no network. This is a 200 so that the
    // page keeps working offline rather than throwing, but `offline: true` is
    // load-bearing — app.js MUST treat it as a failed load. Without that check
    // an unreachable network renders as a successful load of an empty feed:
    // "TOTAL 0", no error, which reads as a quiet day rather than a broken
    // one. Do not remove the flag, and do not add a consumer that ignores it.
    return new Response(JSON.stringify({ items: [], offline: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
}
