# SSH Term Release Notes

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
