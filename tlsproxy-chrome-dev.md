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

This builds `docroot/` and the standalone `./sshterm/sshterm-server` binary.

## Run sshterm-server

Start `sshterm-server` locally with a test endpoint (or with `--authorized-keys` to test the built-in jump host):

```bash
./sshterm/sshterm-server --addr=127.0.0.1:8080 --ep myserver=192.168.0.100:22
```

## Create the tlsproxy config

```bash
cat << EOF > tlsproxy/config.yaml
tlsAddr: localhost:8443

sshCertificateAuthorities:
  - name: "TEST SSH CA"
    keyType: ecdsa-p256
    publicKeyEndpoint: https://localhost:8443/ca
    certificateEndpoint: https://localhost:8443/cert
    maximumCertificateLifetime: 24h

backends:
  - serverNames:
      - localhost
    mode: http
    addresses:
      - 127.0.0.1:8080
    backendProto: h2

EOF
```

Edit `config.yaml` as needed.

## Run tlsproxy

```bash
cd tlsproxy
go generate ./...
CERTMANAGER_STATE_FILE=$HOME/.certmanager-state go run . --config=config.yaml --passphrase=test --use-ephemeral-certificate-manager
```

## Open sshterm

Point your browser at [localhost:8443](https://localhost:8443).

For test purposes with chrome, consider adding `https://localhost:8443` to `chrome://flags/#unsafely-treat-insecure-origin-as-secure`

## Connect to your server

Since `sshterm-server` automatically injects the configured endpoints into `/config.json`, you can connect directly without running `ep add`:

```
ssh username@myserver
```

