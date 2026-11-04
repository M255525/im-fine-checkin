// 加入主畫面＋收通知。network-first＋同源快取備援，不快取跨網域請求。
const CACHE_NAME = 'im-fine-checkin-shell-v3';
const API = 'https://im-fine-checkin.content-workflow.workers.dev';
const SHELL_FILES = [
  './',
  './index.html',
  './manual.html',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(SHELL_FILES))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== location.origin) return;
  event.respondWith(
    fetch(event.request, { cache: 'reload' })
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return res;
      })
      .catch(() => caches.match(event.request, { ignoreSearch: true }))
  );
});

self.addEventListener('push', (event) => {
  let d = {};
  try { d = event.data ? event.data.json() : {}; } catch (e) { /* 內容讀不到也要跳通知 */ }
  event.waitUntil(self.registration.showNotification(d.title || '「我很好」平安通知', {
    body: d.body || '請打開看看今天的狀況。',
    tag: d.tag || 'ifc',
    renotify: true,
    lang: 'zh-TW',
    icon: 'icons/icon-192.png',
    badge: 'icons/icon-192.png',
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) if ('focus' in c) return c.focus();
      return self.clients.openWindow('./index.html');
    })
  );
});

// 瀏覽器自己換掉訂閱時，把新的補回後端，避免之後默默收不到
self.addEventListener('pushsubscriptionchange', (event) => {
  const old = event.oldSubscription;
  if (!old) return;
  event.waitUntil(
    self.registration.pushManager.subscribe(old.options).then((s) =>
      fetch(API + '/api/renew', { method: 'POST', body: JSON.stringify({ oldEndpoint: old.endpoint, subscription: s.toJSON() }) })
    )
  );
});
