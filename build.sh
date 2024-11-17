#!/bin/bash

cd $(dirname $0)
echo "Updating xtermjs..."
./xterm/update.sh
echo "Updating ssh.wasm..."
./go/build.sh
echo "Done"
