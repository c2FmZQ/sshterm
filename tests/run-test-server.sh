#!/bin/bash -e
# This script runs the test server by itself.

cd $(dirname $0)/..

export CGO_ENABLED=0

./build.sh
(cd go && go build -ldflags="-s -w" -o ../testserver ./internal/testserver/)

docker build -f tests/Dockerfile -t sshterm-testserver .
rm -f testserver

docker run \
  --user=65534:65534 \
  --volume=/tmp:/tmp \
  --publish=8880:8880 \
  --rm -it \
  --name=testserver \
  sshterm-testserver
