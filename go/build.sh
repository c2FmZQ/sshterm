#!/bin/sh -e

cd $(dirname $0)

GOOS=js GOARCH=wasm go build -ldflags="-extldflags=-s -w" -o ../docroot/ssh.wasm .
GOOS=js GOARCH=wasm go test -c -o ../docroot/tests.wasm ./internal/tests
cp -f $(go env GOROOT)/lib/wasm/wasm_exec.js ../docroot/
