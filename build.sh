#!/bin/bash -e

cd $(dirname $0)
if [[ ! -f docroot/xterm.js ]]; then
  echo "Updating xtermjs..."
  ./xterm/update.sh
fi
echo "Updating ssh.wasm..."
./go/build.sh
echo "Files in ./docroot/"
ls ./docroot/
echo "Done"
