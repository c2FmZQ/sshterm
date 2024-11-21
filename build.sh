#!/bin/bash -e

cd $(dirname $0)
echo "Updating xtermjs..."
./xterm/update.sh
echo "Updating ssh.wasm..."
./go/build.sh
echo "Files in ./docroot/"
ls -l ./docroot/
echo "Done"
