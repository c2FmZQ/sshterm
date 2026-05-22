#!/bin/bash -e

cd $(dirname $0)

build_tags=()
for arg in "$@"; do
  case "$arg" in
    -x11)
      build_tags+=("x11")
      ;;
    -debug)
      build_tags+=("debug")
      ;;
  esac
done

tags=""
if [[ ${#build_tags[@]} -gt 0 ]]; then
  tags="-tags $(IFS=,; echo "${build_tags[*]}")"
fi
GOOS=js GOARCH=wasm go build $tags -ldflags="-extldflags=-s -w" -o ../docroot/ssh.wasm .
GOOS=js GOARCH=wasm go test $tags -c -o ../docroot/tests.wasm ./internal/tests
GOOS=js GOARCH=wasm go test $tags -c -o ../docroot/tests.x11.wasm ./internal/x11
cp -f $(go env GOROOT)/lib/wasm/wasm_exec.js ../docroot/
