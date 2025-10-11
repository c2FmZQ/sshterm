# SSH Term Release Notes

## next

### :wrench: Misc

* Add browserify to the devDependencies in xterm/package.json.

## v0.8.0

### :star2: New features

* Add WebAuthn keys. The keys can be generated with `keys generate -t ecdsa-sk <name>`. The private key is on a hardware security key, or in a passkey manager.
  Note that the SSH server config needs to have `PubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com`.
* Add `keys change-pass` command to change the passphrase of keys.

### :wrench: Misc

* Update go 1.25.2

## v0.7.8

### :wrench: Bug fix

* Update to use the new TLSPROXY csrf token format. This only affected ssh certificates coming from a TLSPROXY SSH CA.

### :wrench: Misc

* Update go 1.25.1, and go deps.

## v0.7.7

### :wrench: Misc

* Update go 1.25.0, and go deps.
* Small fix for a change in term/Terminal (https://cs.opensource.google/go/x/term/+/4f53e0cd3924d70667107169374a480bfd208348)

## v0.7.6

### :wrench: Misc

* Update go 1.24.5, and go deps.
* Fix tests for recents changes to golang.org/x/crypto.

## v0.7.5

### :wrench: Misc

* Update go 1.24.3, and go deps.

## v0.7.4

### :wrench: Misc

* Update go 1.24.2, and go deps.

## v0.7.3

### :wrench: Misc

* Update go 1.24.1, and go deps.

## v0.7.2

### :wrench: Misc

* Update go 1.24.0, and go deps.

## v0.7.1

### :wrench: Misc

* Add SSH keepalive. Keepalive messages are sent every 30 seconds. No user-visible change.

## v0.7.0

### :star2: New features

* Add support for multiple screens.

### :wrench: Misc

* File drops are now accepted when sftp is running. Files are uploaded to the current directory.

## v0.6.3

### :star2: New features

* Add light and dark themes. (`set theme -h`)

### :wrench: Misc

* Let the middle mouse button paste.
* Other usability changes.

## v0.6.2

### :wrench: Misc

* Update go v1.23.5
* Update go dependencies

## v0.6.1

### :wrench: Bug fix

* Fix the sftp mkdir command to accept more than one argument.

## v0.6.0

### :star2: New features

* Add an option to automatically fetch and refresh user certificates from an identity provider. This feature is intended to be used with tlsproxy's built-in SSH Certificate Authority. See `keys generate -h`
* Add an option to connect to remote servers via jump hosts. See `ssh --help`.
* Read a preset configuration from config.json, if present. See `config/config.go` and `docroot/config.json.example`.
* Replace the `file` command with `sftp`, which implements a basic sftp client.

## v0.5.1

### :star: Feature improvements

* Add an option to generate ECDSA and RSA keys (in addition to ED25519 that is already there).

## v0.5.0

### :star2: New features

* Add support for user certificates. After a certificate is imported, it is used automatically when the matching key is used for authentication.
* Add support for server certificates signed by a trusted authority. CAs are managed with the ca command.

### :wrench: Misc

* Build with go1.23.4

## v0.4.0

### :star2: New features

* Add tab completion for most commands.

## v0.3.2

### :star: Feature improvements

* Add the optional [command] argument to the ssh command, which runs a command on the remote server instead of opening a shell.
* Add keyboard shortcuts.

### :wrench: Bug fixes

* Fix db backup.

## v0.3.1

### :wrench: Bug fixes

* Fixed handling of CR, and other terminal issues.

## v0.3.0

### :star2: New features

* Streaming upload and download with the `file` command.

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
