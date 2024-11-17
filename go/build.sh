#!/bin/sh -e

cd $(dirname $0)

GOOS=js GOARCH=wasm go build -ldflags="-extldflags=-s -w" -o ../docroot/ssh.wasm .
cp $(go env GOROOT)/misc/wasm/wasm_exec.js ../docroot/
