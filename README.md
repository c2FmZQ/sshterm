# SSH Term

SSH Term is an SSH client written in GO, compiled to WASM, that runs entirely in your web browser.

It uses [xterm.js](https://xtermjs.org/) as terminal, and [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh) for the SSH client functionality.

The connection between the client and the server uses [WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket) and [tlsproxy](https://github.com/c2FmZQ/tlsproxy).

![screenshot](https://github.com/c2FmZQ/sshterm/blob/main/images/sshterm.png "SSH Term")

Supported features:

* [x] Connect to any WebSocket endpoints configured in tlsproxy.
* [x] Connect to remote servers via jump hosts.
* [x] Generate SSH keys (rsa, ecdsa, ed25519).
* [x] Import and export SSH keys (rsa, dsa, ecdsa, ed25519).
* [x] Backup & restore.
* [x] Persist data to local storage (optional, on by default).
* [x] Keyboard interactive authentication.
* [x] Public key authentication, with or without certificates.
* [x] In-memory SSH agent and agent forwarding.
* [x] SFTP client with Streaming upload and download.
* [x] Accept host certificates signed by a trusted authority.

Not implemented:

* [ ] Port forwarding.
* [ ] Security keys.

## How to install

### Check out the repo and build everything yourself:

```bash
git clone https://github.com/c2FmZQ/sshterm.git
cd sshterm
./build.sh
```

If all goes well, all the needed files will be in the `docroot` directory.

```
$ ls docroot/
index.html  ssh.js  ssh.wasm  wasm_exec.js  xterm.css  xterm.js
```

### Download a release package

Check out the [release page](https://github.com/c2FmZQ/sshterm/releases). The `sshterm-docroot-${VERSION}.tar.gz` files contain everything ready to go.

## Configure tlsproxy

The simplest tlsproxy config looks like this:

```yaml
backends:
  - serverNames:
      - ssh.EXAMPLE.COM
    mode: local
    documentRoot: /path/to/docroot/

webSockets:
  - endpoint: wss://ssh.EXAMPLE.COM/myserver
    address: 192.168.0.100:22
```

## Open the app

Open `https://ssh.EXAMPLE.COM/` in a browser. It should open a terminal.

The first time you connect, the server endpoint must be configured when the `ep` command:

```bash
ep add myserver wss://ssh.EXAMPLE.COM/myserver
```

Then, you can SSH to your server with:

```bash
ssh username@myserver
```

:warning: Replace _ssh.EXAMPLE.COM_, _myserver_, _/path/to/docroot/_, ... with something appropriate for your environment.

## Run tests

To run the tests in a headless browser, use:

```bash
./tests/run-headless-tests.sh
```

To run the tests and watch the output, start the test server:

```bash
./tests/run-test-server.sh
```

and then open `http://<hostname>:8880/tests.html` in your favorite browser.
