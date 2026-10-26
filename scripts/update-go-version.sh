#!/bin/bash
#
# Check the latest Go version and update Dockerfile, .goversion, go/go.mod, and CHANGELOG.md.

cd "$(dirname "$0")/.."

latest=$(curl -s 'https://go.dev/dl/?mode=json' | jq -r '[.[] | select(.stable == true)][0].version')
version="${latest#go}"
osversion="alpine3.24"
if [[ "${latest}" =~ ^go ]]; then
  sed -i -re "s/^FROM golang:.*/FROM golang:${version}-${osversion} AS build/" Dockerfile
  echo "${version}" > .goversion
  sed -i -re "s/^go .*/go ${version}/" go/go.mod
fi

export GOTOOLCHAIN="go$(cat .goversion)"

deps=$(
  (
    cd go &&
    GOOS=js GOARCH=wasm go get -u -t ./... 2>&1 &&
    go get -u -t -tags docker ./... 2>&1 &&
    go mod tidy 2>&1
  ) | grep upgrade | sed -re 's/go: //g' | awk '!seen[$0]++'
)

if [[ -n $(git status -s Dockerfile .goversion) || -n "${deps}" ]]; then
  sed -n '1,2p' < CHANGELOG.md > CHANGELOG.md-new
  echo '## next' >> CHANGELOG.md-new
  echo >> CHANGELOG.md-new
  echo '### :wrench: Misc' >> CHANGELOG.md-new
  echo >> CHANGELOG.md-new
  if [[ -n $(git status -s Dockerfile .goversion) ]]; then
    echo "* Update go: ${version}" | tee -a CHANGELOG.md-new
  fi
  if [[ -n "${deps}" ]]; then
    echo "* Update go dependencies:" | tee -a CHANGELOG.md-new
    echo "${deps}" | sed -re 's/^/  * /g' | tee -a CHANGELOG.md-new
  fi
  echo >> CHANGELOG.md-new
  sed -n '3,$p' < CHANGELOG.md >> CHANGELOG.md-new
  mv CHANGELOG.md-new CHANGELOG.md
fi

exit 0
