#!/bin/bash -e

cd $(dirname $0)

npm install @xterm/xterm @xterm/addon-fit

if ! which browserify >& /dev/null; then
  echo "browserify missing. See https://browserify.org/#install"
  exit 1
fi
browserify browser.js > ../docroot/xterm.js
cp node_modules/@xterm/xterm/css/xterm.css ../docroot/xterm.css
