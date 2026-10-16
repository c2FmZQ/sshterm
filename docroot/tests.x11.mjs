/*
 * MIT License
 *
 * Copyright (c) 2025 TTBT Enterprises LLC
 * Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
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

import './wasm_exec.js';

window.sshApp = {};
window.sshApp.exited = null;
window.sshApp.ready = new Promise(resolve => {
  window.sshApp.sshIsReady = () => {
    console.log('SSH WASM is ready');
    resolve();
  };
});

const go = new Go();
const wasmFile = 'tests.x11.wasm';
WebAssembly.instantiateStreaming(fetch(wasmFile), go.importObject)
  .then(r => go.run(r.instance));

window.sshApp.ready
  .then(() => window.sshApp.start())
  .then(res => {
    console.log(`Exit status ${res}`);
    let div = document.createElement('div');
    div.id = 'x11-wasm-tests-done';
    div.textContent = 'X11 WASM TESTS DONE';
    div.style = 'position: absolute; top: 0; left: 0; color: white; background-color: black;';
    document.body.appendChild(div);
  });
