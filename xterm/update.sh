#!/bin/bash -e

cd $(dirname $0)

npm install

npx browserify browser.js -o ../docroot/xterm.js
cp node_modules/@xterm/xterm/css/xterm.css ../docroot/xterm.css
cp node_modules/@xterm/xterm/LICENSE ../docroot/LICENSE.xterm.txt
