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
  if (!data || !data.readableStream) {
    return new Response('Errrrr!', {'status': 500, 'statusText': 'Internal Server Error'});
  }
  return new Response(data.readableStream, {'status': 200, 'statusText': 'OK', 'headers': data.headers});
}

let appStreams = {};

self.onmessage = e => {
  const id = e.data.streamId;
  if (id in appStreams) {
    appStreams[id].then(f => f(e.data));
    delete appStreams[id];
  }
};

const streamWord = '/stream/';
self.onfetch = e => {
  if (!e.clientId || e.request.method !== 'GET') return;
  const pos = e.request.url.lastIndexOf(streamWord);
  if (pos === -1) return;
  const id = e.request.url.substring(pos+streamWord.length);
  appStreams[id] = new Promise(r1 => {
    e.respondWith(new Promise(r2 => r1(data => r2(makeResponse(data)))));
  });
  self.clients.get(e.clientId)
  .then(c => {
    if (!c) {
      appStreams[id].then(f => f(null));
      delete appStreams[id];
      return;
    }
    c.postMessage({streamId: id});
  });
};
