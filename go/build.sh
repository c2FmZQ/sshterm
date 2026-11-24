#!/bin/bash -e

cd $(dirname $0)

export GOTOOLCHAIN="go$(cat ../.goversion)"
if [[ -e ../version.sh ]]; then
  source ../version.sh
fi

export CGO_ENABLED=0
GOOS=js GOARCH=wasm go build -ldflags="-extldflags=-s -w -X main.Version=${VERSION:-dev}" -o ../docroot/ssh.wasm .
GOOS=js GOARCH=wasm go test -c -o ../docroot/tests.wasm ./internal/tests
cp -f $(go env GOROOT)/lib/wasm/wasm_exec.js ../docroot/

rm -rf sshterm-server/internal/docroot
mkdir -p sshterm-server/internal/docroot
cp -r ../docroot/* sshterm-server/internal/docroot/
rm -f sshterm-server/internal/docroot/tests.* sshterm-server/internal/docroot/config.json*

go build -trimpath -ldflags="-extldflags=-s -w -X main.Version=${VERSION:-dev}" -o ../sshterm-server ./sshterm-server

