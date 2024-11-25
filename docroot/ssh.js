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

window.sshApp = {};
window.sshApp.ready = new Promise(resolve => {
  sshApp.sshIsReady = () => {
    console.log('SSH WASM is ready');
    resolve();
  };
});

const go = new Go();
WebAssembly.instantiateStreaming(fetch('ssh.wasm'), go.importObject)
  .then(r => go.run(r.instance));

window.addEventListener('load', () => {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('stream-helper.js').then(r => r.update());
  }
  const term = new Terminal({
    convertEol: true,
    cursorBlink: true,
    cursorInactiveStyle: 'outline',
    cursorStyle: 'block',
  });
  const fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(document.getElementById('terminal'));
  term.onTitleChange(t => document.querySelector('head title').textContent = t);
  term.onSelectionChange(() => {
    const v = term.getSelection();
    if (v !== '') {
      navigator.clipboard.writeText(v);
    }
  });
  // Override the right-click to paste instead of bring up the context menu.
  term.element.addEventListener('contextmenu', event => {
    event.preventDefault();
    event.stopPropagation();
    navigator.clipboard.readText().then(t => term.paste(t));
  });
  window.addEventListener('resize', () => fitAddon.fit())
  fitAddon.fit();
  sshApp.ready
    .then(() => sshApp.start({term}))
    .then(v => console.log('SSH', v))
    .catch(e => {
      console.log('SSH ERROR', e);
      term.writeln(e.message);
    });
});
