#!/bin/bash
set -e

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR="$DIR/../.."

echo "Building sshterm..."
(cd "$ROOT_DIR" && ./build.sh -x11)

echo "Building standalone X11 test environment (setup)..."
cd "$DIR"

# Build x11-apps to get the host key
docker compose build x11-apps

cleanup() {
    docker compose down --remove-orphans >/dev/null 2>&1 || true
    rm -f standalone.config.json tkinter_ui.log tkinter_state.json test-server
    (cd "$ROOT_DIR" && ./build.sh >/dev/null 2>&1 || true)
}
trap cleanup EXIT

echo "Building standalone test runner..."
CGO_ENABLED=0 go build -o test-server main.go

echo "Retrieving host keys from image..."
KEY_ED25519=$(docker compose run --rm -T --no-deps --entrypoint cat x11-apps /etc/ssh/ssh_host_ed25519_key.pub | tr -d '\r' | cut -d' ' -f1-2)
KEY_ECDSA=$(docker compose run --rm -T --no-deps --entrypoint cat x11-apps /etc/ssh/ssh_host_ecdsa_key.pub | tr -d '\r' | cut -d' ' -f1-2)

if [ -z "$KEY_ED25519" ]; then
    echo "Failed to read host keys from image"
    exit 1
fi
echo "Found ed25519 key: $KEY_ED25519"
echo "Found ecdsa key: $KEY_ECDSA"

# Update local config with the host keys
sed "s|\"hosts\": \[\]|\"hosts\": [{\"name\": \"x11-apps\", \"key\": \"$KEY_ED25519\"}, {\"name\": \"x11-apps\", \"key\": \"$KEY_ECDSA\"}]|" config.json.template > standalone.config.json

export TEST_UID=$(id -u)
export TEST_GID=$(id -g)
rm -f x11-standalone-screenshot.png x11-standalone-screenshot-failed.png debug-*.png

echo "Running tests..."
# Prevent bash from exiting immediately if docker compose fails, so we can copy logs
set +e
timeout --foreground 180s docker compose up --menu=false --build --abort-on-container-exit --exit-code-from tester
TEST_EXIT_CODE=$?
set -e

if [ $TEST_EXIT_CODE -eq 124 ]; then
    echo "Error: Standalone integration test timed out after 3 minutes"
fi

echo "Test finished with exit code $TEST_EXIT_CODE. Check tests/x11-standalone/x11-standalone-screenshot.png for results."

exit $TEST_EXIT_CODE
