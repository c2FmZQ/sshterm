import { TabManager } from './ssh.js';

window.addEventListener('load', () => {
  new TabManager(document.getElementById('terminal'));
});
