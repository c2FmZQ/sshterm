#!/bin/bash -e
# This script runs the test server by itself.

cd $(dirname $0)/..

export CGO_ENABLED=0

./build.sh
(cd go && go build -ldflags="-s -w" -o ../testserver ./internal/testserver/)

docker build -f tests/Dockerfile -t sshterm-testserver .
rm -f testserver

docker run \
  --rm -it \
  --user=65534:65534 \
  --mount=type=tmpfs,destination=/tmp,tmpfs-mode=1777 \
  --publish=8880:8880 \
  --name=testserver \
  sshterm-testserver
