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

import './wasm_exec.js';
import { Terminal, FitAddon } from './xterm.mjs';

function isTest() {
  return window.location.pathname.indexOf('tests.html') !== -1;
}

export const workarounds = {
  // Protects @xterm/xterm (5.5.0) InputHandler.repeatPrecedingCharacter
  // (CSI Ps b) from throwing an uncaught RangeError on large Ps values and
  // permanently wedging WriteBuffer.
  csiRepGuard: true,

  // Protects @xterm/xterm (5.5.0) InputHandler from 2^31-1 synchronous
  // while(param--) loops in CSI I, Z, L, M, S, and T.
  csiLoopGuard: true,
};

export function sanitizeTitle(title) {
  const clean = String(title).replace(/[\x00-\x1f\x7f-\x9f]/g, ' ').trim();
  return clean.length > 128 ? clean.slice(0, 128) + '…' : clean;
}

export function applyXtermWorkarounds(term, flags = workarounds) {
  const disposables = [];
  const registerClampCsi = (final, getMax) => {
    disposables.push(
      term._core.registerCsiHandler({ final }, params => {
        const active = final === 'b' ? flags.csiRepGuard : flags.csiLoopGuard;
        if (!active) return false;
        const maxVal = Math.max(1, getMax());
        if (params.length > 0 && params.params[0] > maxVal) {
          params.params[0] = maxVal;
        }
        return false;
      })
    );
  };

  registerClampCsi('b', () => term.cols * term.rows);
  registerClampCsi('I', () => term.cols);
  registerClampCsi('Z', () => term.cols);
  registerClampCsi('L', () => term.rows);
  registerClampCsi('M', () => term.rows);
  registerClampCsi('S', () => term.rows);
  registerClampCsi('T', () => term.rows);

  return disposables;
}

class TerminalManager {
  constructor(elem, setTitle, onBell) {
    this.term = new Terminal({
      cursorBlink: true,
      cursorInactiveStyle: 'outline',
      cursorStyle: 'block',
    });
    this.fitAddon = new FitAddon();
    this.term.loadAddon(this.fitAddon);
    this.term.open(elem);
    this.fitAddon.fit();

    const workaroundDisposables = applyXtermWorkarounds(this.term, workarounds);

    this.disposables = [
      ...workaroundDisposables,
      this.term.onTitleChange(setTitle),
      this.term.onBell(onBell),
      this.term.onSelectionChange(() => {
        const v = this.term.getSelection();
        if (v !== '' && navigator.clipboard) {
          navigator.clipboard.writeText(v);
        }
      }),
      this.term,
    ];

    // Remove escape characters from pasted text so that it can't end
    // bracketed paste mode early, e.g. with "\x1b[201~some command\r".
    const paste = t => this.term.paste(t.replace(/[\x1b\x9b]/g, ''));
    this.contextmenuHandler = event => {
      event.preventDefault();
      event.stopPropagation();
      navigator.clipboard.readText().then(paste);
    };
    this.mousedownHandler = event => {
      if (event.button === 1) {
        navigator.clipboard.readText().then(paste);
      }
    };
    this.pasteHandler = event => {
      event.preventDefault();
      event.stopImmediatePropagation();
      paste(event.clipboardData?.getData('text/plain') ?? '');
    };
    this.resizeHandler = () => this.fitAddon.fit();

    this.term.element.addEventListener('contextmenu', this.contextmenuHandler);
    this.term.element.addEventListener('mousedown', this.mousedownHandler);
    // Capture phase, to run before xterm's own paste handler.
    this.term.element.addEventListener('paste', this.pasteHandler, true);
    window.addEventListener('resize', this.resizeHandler);

    if (isTest()) {
      window.sshApp.term = this.term;
    }
  }

  cleanup(result) {
    this.term.element.removeEventListener('contextmenu', this.contextmenuHandler);
    this.term.element.removeEventListener('mousedown', this.mousedownHandler);
    this.term.element.removeEventListener('paste', this.pasteHandler, true);
    window.removeEventListener('resize', this.resizeHandler);
    for (let i = 0; i < this.disposables.length; i++) {
      this.disposables[i].dispose();
    }
    if (isTest()) {
      window.sshApp.exited = result;
      const b = document.createElement('button');
      b.id = 'done';
      b.addEventListener('click', () => window.location.reload());
      b.textContent = 'reload';
      b.style = 'position: fixed; top: 0; right: 0;';
      document.body.appendChild(b);
    }
    console.log('SSH', result);
  }

  getTerm() {
    return this.term;
  }
}

export class TabManager {
  constructor(parent) {
    this.parent = parent;
    this.parent.style.display = 'grid';
    this.buttons = null;
    this.count = 1;
    this.screens = {};

    this.init();
  }

  async init() {
    await window.sshApp.ready;
    this.addScreen();
  }

  selectScreen(id) {
    for (const screenId of Object.keys(this.screens)) {
      const screen = this.screens[screenId];
      const isSelected = screenId === id;
      screen.selected = isSelected;
      screen.e.style.zIndex = isSelected ? 1 : 0;
      screen.b.style.backgroundColor = isSelected ? 'black' : 'white';
      screen.b.style.color = isSelected ? 'white' : 'black';
      screen.b.style.fontWeight = isSelected ? 'bold' : 'normal';
    }
    this.screens[id].terminalManager.getTerm().focus();
    document.querySelector('head title').textContent = this.screens[id].title;
  }

  async addScreen() {
    if (!this.buttons) {
      this.buttons = document.createElement('div');
      this.buttons.className = 'buttons';
      this.buttons.style = 'position: fixed; top: 0; right: 0; z-index: 1000; opacity: 0.2;';
      this.parent.appendChild(this.buttons);
      const b = document.createElement('button');
      b.addEventListener('click', () => this.addScreen());
      b.textContent = '➕';
      this.buttons.appendChild(b);
      this.buttons.addEventListener('mouseenter', () => {
        this.buttons.style.opacity = 1;
      });
      this.buttons.addEventListener('mouseleave', () => {
        this.buttons.style.opacity = 0.2;
      });
    }

    const id = this.count++;
    const e = document.createElement('div');
    e.id = 'screen-' + id;
    e.style = 'grid-row: 1; grid-column: 1; z-index: 1';
    this.parent.appendChild(e);

    const b = document.createElement('button');
    b.id = 'button-' + id;
    b.title = 'sshterm';
    b.style.fontFamily = 'monospace';
    b.addEventListener('click', () => {
      this.selectScreen(b.id);
    });
    b.textContent = '' + id;
    this.buttons.insertBefore(b, this.buttons.lastChild);

    this.screens[b.id] = { e, b };
    this.screens[b.id].title = 'sshterm';

    const setTitle = rawTitle => {
      const title = sanitizeTitle(rawTitle) || 'sshterm';
      this.screens[b.id].title = title;
      this.screens[b.id].b.title = title;
      document.querySelector('head title').textContent = title;
      if (title !== 'sshterm') {
        this._showMessage(e, title);
      }
    };
    const onBell = () => {
      this._showMessage(e, '** BEEP **');
    };

    const terminalManager = new TerminalManager(e, setTitle, onBell);
    this.screens[b.id].terminalManager = terminalManager;
    this.selectScreen(b.id);

    const term = terminalManager.getTerm();
    term.showMessage = text => this._showMessage(e, text);
    const cfg = await fetch('config.json')
      .then(r => {
        if (r.ok) return r.json();
        return {};
      })
      .catch(e => {
        term.writeln('\x1b[31mError reading config.json:\x1b[0m');
        term.writeln('\x1b[31m' + e.message + '\x1b[0m');
        term.writeln('');
        return {};
      });
    cfg.term = term;

    const app = await window.sshApp.start(cfg);
    this.screens[b.id].close = app.close;

    app.done
      .then(done => {
        terminalManager.cleanup(done);
        if (isTest()) return;
        const wasSelected = this.screens[b.id].selected;
        delete this.screens[b.id];
        this.parent.removeChild(e);
        this.buttons.removeChild(b);
        if (wasSelected && this.buttons.firstChild.id in this.screens) {
          this.selectScreen(this.buttons.firstChild.id);
        }
      })
      .catch(e => {
        console.log('SSH ERROR', e);
        term.writeln(e.message);
        terminalManager.cleanup(e.message);
      });
  }

  _showMessage(element, text) {
    const safeText = sanitizeTitle(text);
    let msg = element._toastMsg;
    if (!msg || msg.parentNode !== element) {
      msg = document.createElement('div');
      msg.className = 'sshterm-toast';
      msg.style = 'position: absolute; bottom: 0; right: 0; max-width: 80%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; pointer-events: none; padding: 0.5rem; background-color: white; color: black; font-family: monospace; border: solid 1px black; z-index: 10;';
      element.appendChild(msg);
      element._toastMsg = msg;
    }
    msg.textContent = safeText;
    if (element._toastTimer) {
      clearTimeout(element._toastTimer);
    }
    element._toastTimer = setTimeout(() => {
      if (msg.parentNode === element) {
        element.removeChild(msg);
      }
      element._toastMsg = null;
      element._toastTimer = null;
    }, 3000);
  }
}

window.sshApp = {};
if (isTest()) {
  window.sshApp.workarounds = workarounds;
  window.sshApp.applyXtermWorkarounds = applyXtermWorkarounds;
  window.sshApp.Terminal = Terminal;
}
window.sshApp.exited = null;
window.sshApp.ready = new Promise(resolve => {
  window.sshApp.sshIsReady = () => {
    console.log('SSH WASM is ready');
    if (navigator.webdriver) {
      console.log('User-Agent:', navigator.userAgent);
    }
    resolve();
  };
});

const go = new Go();
const wasmFile = isTest() ? 'tests.wasm' : 'ssh.wasm';
WebAssembly.instantiateStreaming(fetch(wasmFile), go.importObject)
  .then(r => go.run(r.instance));
