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
window.sshApp.ready = new Promise(resolve => {
  sshApp.sshIsReady = () => {
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

function createTerminal(elem, setTitle, onBell) {
  const term = new Terminal({
    cursorBlink: true,
    cursorInactiveStyle: 'outline',
    cursorStyle: 'block',
  });
  const fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.open(elem);
  fitAddon.fit();
  const disposables = [
    term.onTitleChange(setTitle),
    term.onBell(onBell),
    term.onSelectionChange(() => {
      const v = term.getSelection();
      if (v !== '' && navigator.clipboard) {
        navigator.clipboard.writeText(v);
      }
    }),
    term,
  ];
  const contextmenuHandler = event => {
    event.preventDefault();
    event.stopPropagation();
    navigator.clipboard.readText().then(t => term.paste(t));
  };
  const mousedownHandler = event => {
    if (event.button === 1) {
      navigator.clipboard.readText().then(t => term.paste(t));
    }
  };
  const resizeHandler = () => fitAddon.fit();

  term.element.addEventListener('contextmenu', contextmenuHandler);
  term.element.addEventListener('mousedown', mousedownHandler);
  window.addEventListener('resize', resizeHandler);

  const cleanup = result => {
    term.element.removeEventListener('contextmenu', contextmenuHandler);
    term.element.removeEventListener('mousedown', mousedownHandler);
    window.removeEventListener('resize', resizeHandler);
    for (let i = 0; i < disposables; i++) {
      disposables[i]('dispose');
    }
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
  };

  if (isTest) {
    sshApp.term = term;
  }
  return {term,cleanup};
}

let buttons;
let count = 1;
let screens = {};

function selectScreen(id) {
  for (let s in screens) {
    if (s !== id) {
      screens[s].selected = false;
      screens[s].e.style.zIndex = 0;
      screens[s].b.style.backgroundColor = 'white';
      screens[s].b.style.color = 'black';
      screens[s].b.style.fontWeight = 'normal';
    }
  }
  screens[id].selected = true;
  screens[id].e.style.zIndex = 1;
  screens[id].b.style.backgroundColor = 'black';
  screens[id].b.style.color = 'white';
  screens[id].b.style.fontWeight = 'bold';
  screens[id].term.focus();
  document.querySelector('head title').textContent = screens[id].title;
}

async function addScreen() {
  await sshApp.ready;
  const parent = document.getElementById('terminal');
  parent.style.display = 'grid';
  if (!buttons) {
    buttons = document.createElement('div');
    buttons.className = 'buttons';
    buttons.style = 'position: fixed; top: 0; right: 0; z-index: 1000; opacity: 0.2;';
    parent.appendChild(buttons);
    const b = document.createElement('button');
    b.addEventListener('click', addScreen);
    b.textContent = '➕';
    buttons.appendChild(b);
    buttons.addEventListener('mouseenter', () => {
      buttons.style.opacity = 1;
    });
    buttons.addEventListener('mouseleave', () => {
      buttons.style.opacity = 0.2;
    });
  }

  const id = count++;
  const e = document.createElement('div');
  e.id = 'screen-' + id;
  e.style = 'grid-row: 1; grid-column: 1; z-index: 1';
  parent.appendChild(e);

  const b = document.createElement('button');
  b.id = 'button-'+id;
  b.title = 'sshterm';
  b.style.fontFamily = 'monospace';
  b.addEventListener('click', () => {
    selectScreen(b.id);
  });
  b.textContent = '' + id;
  buttons.insertBefore(b, buttons.lastChild);

  screens[b.id] = {e,b};
  screens[b.id].title = 'sshterm';

  const setTitle = title => {
    screens[b.id].title = title;
    screens[b.id].b.title = title;
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

  const {term,cleanup} = createTerminal(e, setTitle, onBell);
  screens[b.id].term = term;
  selectScreen(b.id);

  const cfg = await fetch('config.json')
  .then(r => {
    if (r.ok) return r.json();
    return {};
  })
  .catch(e => {
    term.writeln('\x1b[31mError reading config.json:\x1b[0m');
    term.writeln('\x1b[31m'+e.message+'\x1b[0m');
    term.writeln('');
    return {};
  });
  cfg.term = term;

  const app = await sshApp.start(cfg);
  screens[b.id].close = app.close;

  app.done
  .then(done => {
    cleanup(done);
    if (isTest) return;
    const wasSelected = screens[b.id].selected;
    delete screens[b.id];
    parent.removeChild(e);
    buttons.removeChild(b);
    if (wasSelected && buttons.firstChild.id in screens) {
      selectScreen(buttons.firstChild.id);
    }
  })
  .catch(e => {
    console.log('SSH ERROR', e);
    term.writeln(e.message);
    cleanup(e.message);
  });
}

window.addEventListener('load', addScreen);
