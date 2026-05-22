#!/bin/bash -e
# This script runs the browser tests with chromedp in docker containers.

cd $(dirname $0)/..

mkdir -p output
exec &> >(grep -v "^headless-shell.*:CONSOLE" | tee output/headless-tests.log)
echo "# $0 $*"

export CGO_ENABLED=0
(cd go && go test -tags x11 ./...)

./build.sh -x11 -debug
(cd go && go test -tags docker,x11,debug -c -o ../testserver ./internal/testserver/)

docker build -f tests/Dockerfile -t sshterm-testserver .
rm -f testserver

mkdir -p ./output

export TEST_RUN="$1"
export TEST_UID=$(id -u)
export TEST_GID=$(id -g)
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
