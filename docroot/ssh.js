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
sshApp.exited = null;
sshApp.onExit = result => {
  for (let i = 0; i < sshApp.disposables; i++) {
    sshApp.disposables[i]('dispose');
  }
  window.sshApp.exited = result;
  const b = document.createElement('button');
  b.id = 'done';
  b.addEventListener('click', () => window.location.reload());
  b.textContent = 'reload';
  b.style = 'position: fixed; top: 0; right: 0;';
  document.body.appendChild(b);
  console.log('SSH', result);
};
window.sshApp.ready = new Promise(resolve => {
  sshApp.sshIsReady = () => {
    console.log('SSH WASM is ready');
    resolve();
  };
});

const go = new Go();
const wasmFile = window.location.pathname.indexOf('tests.html') !== -1 ? 'tests.wasm' : 'ssh.wasm';
WebAssembly.instantiateStreaming(fetch(wasmFile), go.importObject)
  .then(r => go.run(r.instance));

window.addEventListener('load', () => {
  const term = new Terminal({
    cursorBlink: true,
    cursorInactiveStyle: 'outline',
    cursorStyle: 'block',
  });
  const fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(document.getElementById('terminal'));
  sshApp.disposables = [
    term.onTitleChange(t => document.querySelector('head title').textContent = t),
    term.onSelectionChange(() => {
      const v = term.getSelection();
      if (v !== '' && navigator.clipboard) {
        navigator.clipboard.writeText(v);
      }
    }),
  ];
  // Override the right-click to paste instead of bring up the context menu.
  term.element.addEventListener('contextmenu', event => {
    event.preventDefault();
    event.stopPropagation();
    navigator.clipboard.readText().then(t => term.paste(t));
  });
  window.addEventListener('resize', () => fitAddon.fit())
  fitAddon.fit();
  sshApp.term = term;
  Promise.all([
    sshApp.ready,
    fetch('config.json')
    .then(r => {
      if (r.ok) return r.json();
      return {};
    })
    .catch(e => {
      term.writeln('\x1b[31mError reading config.json:\x1b[0m');
      term.writeln('\x1b[31m'+e.message+'\x1b[0m');
      term.writeln('');
      return {};
    }),
  ]).then(v => {
    let cfg = v[1];
    cfg.term = term;
    sshApp.start(cfg)
    .then(v => sshApp.onExit(v))
    .catch(e => {
      console.log('SSH ERROR', e);
      term.writeln(e.message);
      sshApp.onExit(e.message);
    });
  });
});
