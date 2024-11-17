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
