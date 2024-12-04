# Configuration for testing with tlsproxy and chrome

## Clone the tlsproxy and sshterm repos

```bash
git clone https://github.com/c2FmZQ/sshterm.git
git clone https://github.com/c2FmZQ/tlsproxy.git
```

## Build sshterm

```bash
(cd sshterm && ./build.sh)
```

## Create the tlsproxy config

```bash
cat << EOF > tlsproxy/config.yaml
tlsAddr: localhost:8443

backends:
  - serverNames:
      - localhost
    mode: local
    documentRoot: ../sshterm/docroot

webSockets:
  - endpoint: wss://localhost/websocket
    address: 192.168.0.100:22

EOF
```

Edit `config.yaml` as needed.

## Run tlsproxy

```bash
cd tlsproxy
CERTMANAGER_STATE_FILE=$HOME/.certmanager-state go run . --config=config.yaml --passphrase=test --use-ephemeral-certificate-manager
```

## Open sshterm

Point your browser at [localhost:8443](https://localhost:8443).

For test purposes with chrome, consider adding `https://localhost:8443` to `chrome://flags/#unsafely-treat-insecure-origin-as-secure`

## Configure the endpoint in sshterm

```
ep add myserver wss://localhost/websocket
```

## Connect to your server

```
ssh username@myserver
```

