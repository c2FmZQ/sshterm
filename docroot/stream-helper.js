/*
 * MIT License
 *
 * Copyright (c) 2024 TTBT Enterprises LLC
 * Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

'use strict';

self.oninstall = e => e.waitUntil(self.skipWaiting());
self.onactivate = e => e.waitUntil(self.clients.claim());

function makeResponse(data) {
  if (!data || !data.body) {
    return new Response('Errrrr!', {'status': 500, 'statusText': 'Internal Server Error'});
  }
  try {
    return new Response(data.body, data.options);
  } catch (err) {
    if (data.body instanceof ReadableStream) {
      data.body.cancel(err);
    }
    console.error('makeResponse failed:', err);
    return new Response('Internal Server Error', {'status': 500, 'statusText': 'Internal Server Error'});
  }
}

const appStreams = new Map();

self.onmessage = e => {
  const id = e.data?.streamId;
  const s = appStreams.get(id);
  // Only accept the response from the client that made the request.
  if (s && e.source?.id === s.clientId) {
    appStreams.delete(id);
    s.resolve(e.data);
  }
};

const streamPath = /\/stream\/([0-9a-f]{32})$/;
self.onfetch = e => {
  if (!e.clientId || e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  const m = url.origin === self.location.origin && url.pathname.match(streamPath);
  if (!m) return;
  const id = m[1];
  e.respondWith(new Promise(resolve => {
    self.clients.get(e.clientId).then(c => {
      if (!c) {
        resolve(new Response('client not found', {status: 404, statusText: 'Not Found'}));
        return;
      }
      const timeoutId = setTimeout(() => {
        appStreams.delete(id);
        resolve(new Response('client did not respond in time', {status: 504, statusText: 'Gateway Timeout'}));
      }, 5000);
      appStreams.set(id, {
        clientId: c.id,
        resolve: data => {
          clearTimeout(timeoutId);
          resolve(makeResponse(data));
        },
      });
      c.postMessage({streamId: id});
    });
  }));
};
