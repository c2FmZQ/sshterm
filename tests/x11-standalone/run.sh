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

echo "Retrieving host keys from image..."
KEY_ED25519=$(docker run --rm x11-standalone-x11-apps cat /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f1-2)
KEY_ECDSA=$(docker run --rm x11-standalone-x11-apps cat /etc/ssh/ssh_host_ecdsa_key.pub | cut -d' ' -f1-2)

if [ -z "$KEY_ED25519" ]; then
    echo "Failed to read host keys from image"
    exit 1
fi
echo "Found ed25519 key: $KEY_ED25519"
echo "Found ecdsa key: $KEY_ECDSA"

# Update local config with the host keys
sed "s|\"hosts\": \[\]|\"hosts\": [{\"name\": \"x11-apps\", \"key\": \"$KEY_ED25519\"}, {\"name\": \"x11-apps\", \"key\": \"$KEY_ECDSA\"}]|" config.json.template > standalone.config.json

echo "Running tests..."
# Prevent bash from exiting immediately if docker compose fails, so we can copy logs
set +e
timeout 180s docker compose up --build --abort-on-container-exit --exit-code-from tester
TEST_EXIT_CODE=$?
set -e

if [ $TEST_EXIT_CODE -eq 124 ]; then
    echo "Error: Standalone integration test timed out after 3 minutes"
fi


echo "Copying logs and state from containers..."
docker compose cp x11-apps:/tmp/tkinter_ui.log ./tkinter_ui.log || true
docker compose cp x11-apps:/tmp/tkinter_state.json ./tkinter_state.json || true

echo "Test finished with exit code $TEST_EXIT_CODE. Check tests/x11-standalone/x11-standalone-screenshot.png for results."

# Cleanup
rm -f standalone.config.json

exit $TEST_EXIT_CODE

