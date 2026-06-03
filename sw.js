const CACHE_NAME = 'relay-cache-v1';
const ASSETS = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './cloudflare-words.js',
  './icon.svg',
  './manifest.json',
  './version.js',
  'https://unpkg.com/peerjs@1.5.2/dist/peerjs.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js',
  'https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500&family=JetBrains+Mono:wght@400;500&display=swap'
];

// Install Event - Caching Assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS);
    }).then(() => self.skipWaiting())
  );
});

// Activate Event - Cleaning old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch Event - Cache First Strategy
self.addEventListener('fetch', (event) => {
  // Do not intercept non-GET requests or WebSocket connections (e.g. wss://, ws://)
  if (event.request.method !== 'GET' || event.request.url.startsWith('ws') || event.request.url.startsWith('http://localhost') && event.request.url.includes('relay')) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        // Fetch fresh copy in the background to update cache for next time (Stale While Revalidate)
        fetch(event.request).then((networkResponse) => {
          if (networkResponse.status === 200) {
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, networkResponse));
          }
        }).catch(() => {/* Ignore network update errors offline */});
        
        return cachedResponse;
      }
      return fetch(event.request);
    })
  );
});
