// Service worker for shared board links (/b/<token>). Registered with scope /b/
// so it never touches the main app. Keeps the page shell, the last board data and
// its images so a link still opens on set with no signal.
const CACHE = 'shared-board-v1';
const SHELL = '/b/_shell';

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.add(new Request(SHELL, { cache: 'reload' }))).catch(() => {}).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k.startsWith('shared-board-') && k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});

// Signed image URLs change on every load (new token in the query string), so
// images are cached by origin + path only.
const imgKey = url => { const u = new URL(url); return u.origin + u.pathname; };
const isImage = url => /\/storage\/v1\/object\/sign\//.test(url);

self.addEventListener('message', e => {
  const d = e.data || {};
  if (d.type !== 'precache' || !Array.isArray(d.urls)) return;
  e.waitUntil(caches.open(CACHE).then(c => Promise.all(d.urls.slice(0, 300).map(async url => {
    try {
      if (await c.match(imgKey(url))) return;
      const r = await fetch(url, { mode: 'no-cors' });
      if (r.ok || r.type === 'opaque') await c.put(imgKey(url), r);
    } catch (err) {}
  }))));
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = req.url;

  // Page navigations under /b/: network first, fall back to the cached shell
  if (req.mode === 'navigate') {
    e.respondWith(fetch(req).then(r => {
      if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(SHELL, copy)); }
      return r;
    }).catch(() => caches.match(SHELL)));
    return;
  }
  // Board images: serve from cache when present (they are immutable per path), else network + store
  if (isImage(url)) {
    e.respondWith(caches.open(CACHE).then(async c => {
      const hit = await c.match(imgKey(url));
      if (hit) return hit;
      const r = await fetch(req);
      if (r.ok || r.type === 'opaque') c.put(imgKey(url), r.clone());
      return r;
    }).catch(() => fetch(req)));
  }
  // Everything else (including /api/public/...) goes straight to the network;
  // the page keeps its own saved copy of the board data for offline use.
});
