# SSH Term Release Notes

## v0.2.0

### :star2: New features

* Import and export SSH keys (rsa, dsa, ecdsa, ed25519).
* Backup and restore the database. Optionally turn off local storage and keep data in memory only.

## v0.1.0

### :star2: First release

SSH Term is an SSH client written in GO, compiled to WASM, that runs entirely in your web browser.

It uses [xterm.js](https://xtermjs.org/) as terminal, and [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh) for the SSH client functionality.

The connection between the client and the server uses [WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket) and [tlsproxy](https://github.com/c2FmZQ/tlsproxy).

Supported features:

* [x] Connect to any WebSocket endpoints configured in tlsproxy.
* [x] Generate and use SSH keys.
* [x] Keyboard interactive authentication.
* [x] In-memory SSH agent and agent forwarding.
