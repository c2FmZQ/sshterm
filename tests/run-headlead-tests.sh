#!/bin/bash -e
# This script runs the browser tests with chromedp in docker containers.

cd $(dirname $0)/..

export CGO_ENABLED=0

./build.sh
(cd go && go build -ldflags="-s -w" -o ../testserver ./internal/testserver/)

docker build -f tests/Dockerfile -t sshterm-testserver .
rm -f testserver

export USERID=65534
docker compose -f tests/docker-compose-browser-tests.yaml up \
  --abort-on-container-exit \
  --exit-code-from=devtest
RES=$?
docker compose -f tests/docker-compose-browser-tests.yaml rm -f

if [[ $RES == 0 ]]; then
  echo PASS
else
  echo FAIL
  exit 1
fi
