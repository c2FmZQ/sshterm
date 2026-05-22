#!/bin/bash -e

cd $(dirname $0)

mkdir -p output
exec &> >(tee output/build.log)

if [[ ! -f docroot/xterm.mjs ]]; then
  echo "Updating xtermjs..."
  ./xterm/update.sh
fi
echo "Updating ssh.wasm..."
./go/build.sh "$@"
echo "Files in ./docroot/"
ls ./docroot/
echo "Done"
