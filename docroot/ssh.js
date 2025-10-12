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

    this.disposables = [
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

    this.contextmenuHandler = event => {
      event.preventDefault();
      event.stopPropagation();
      navigator.clipboard.readText().then(t => this.term.paste(t));
    };
    this.mousedownHandler = event => {
      if (event.button === 1) {
        navigator.clipboard.readText().then(t => this.term.paste(t));
      }
    };
    this.resizeHandler = () => this.fitAddon.fit();

    this.term.element.addEventListener('contextmenu', this.contextmenuHandler);
    this.term.element.addEventListener('mousedown', this.mousedownHandler);
    window.addEventListener('resize', this.resizeHandler);

    if (window.location.pathname.indexOf('tests.html') !== -1) {
      window.sshApp.term = this.term;
    }
  }

  cleanup(result) {
    this.term.element.removeEventListener('contextmenu', this.contextmenuHandler);
    this.term.element.removeEventListener('mousedown', this.mousedownHandler);
    window.removeEventListener('resize', this.resizeHandler);
    for (let i = 0; i < this.disposables.length; i++) {
      this.disposables[i].dispose();
    }
    const isTest = window.location.pathname.indexOf('tests.html') !== -1;
    if (isTest) {
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
    for (let s in this.screens) {
      if (s !== id) {
        this.screens[s].selected = false;
        this.screens[s].e.style.zIndex = 0;
        this.screens[s].b.style.backgroundColor = 'white';
        this.screens[s].b.style.color = 'black';
        this.screens[s].b.style.fontWeight = 'normal';
      }
    }
    this.screens[id].selected = true;
    this.screens[id].e.style.zIndex = 1;
    this.screens[id].b.style.backgroundColor = 'black';
    this.screens[id].b.style.color = 'white';
    this.screens[id].b.style.fontWeight = 'bold';
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

    const setTitle = title => {
      this.screens[b.id].title = title;
      this.screens[b.id].b.title = title;
      document.querySelector('head title').textContent = title;
      if (title !== 'sshterm') {
        const msg = document.createElement('div');
        msg.style = 'position: absolute; bottom: 0; right: 0; padding: 0.5rem; background-color: white; color: black; font-family: monospace; border: solid 1px black;';
        msg.textContent = title;
        e.appendChild(msg);
        setTimeout(() => e.removeChild(msg), 3000);
      }
    };
    const onBell = () => {
      const msg = document.createElement('div');
      msg.style = 'position: absolute; bottom: 0; right: 0; padding: 0.5rem; background-color: white; color: black; font-family: monospace; border: solid 1px black;';
      msg.textContent = '** BEEP **';
      e.appendChild(msg);
      setTimeout(() => e.removeChild(msg), 3000);
    };

    const terminalManager = new TerminalManager(e, setTitle, onBell);
    this.screens[b.id].terminalManager = terminalManager;
    this.selectScreen(b.id);

    const term = terminalManager.getTerm();
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
        const isTest = window.location.pathname.indexOf('tests.html') !== -1;
        if (isTest) return;
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
}

window.sshApp = {};
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
const isTest = window.location.pathname.indexOf('tests.html') !== -1;
const wasmFile = isTest ? 'tests.wasm' : 'ssh.wasm';
WebAssembly.instantiateStreaming(fetch(wasmFile), go.importObject)
  .then(r => go.run(r.instance));
