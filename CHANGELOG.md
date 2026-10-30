# SSH Term Release Notes

## v0.11.7

### :wrench: Misc

* Disable multipathtcp
* Update go dependencies:
  * upgraded github.com/chromedp/cdproto v0.0.0-20250803210736-d308e07a266d => v0.158.5
  * upgraded github.com/chromedp/chromedp v0.14.2 => v0.21.0
  * upgraded github.com/go-json-experiment/json v0.0.0-20250725192818-e39067aee2d2 => v0.0.0-20260820222146-c27c302e5fc3

## v0.11.6

### :lock: Security fixes

* Upgrade `github.com/pkg/sftp` to `v1.13.12` (fixing truncated packet unmarshaling panics and `Client.RemoveAll` directory symlink traversal).
* Harden SSH client and forwarded agent (`golang.org/x/crypto/ssh`):
  * Implement `ssh.MultiAlgorithmSigner` on `dynSigner` and `agent.ExtendedAgent` (`SignWithFlags`) on `keyRing` and `forwardedAgent` so RSA keys and user certificates use `rsa-sha2-256` / `rsa-sha2-512` instead of falling back to deprecated SHA-1 (`ssh-rsa`).
  * Reject deprecated SHA-1 (`ssh-rsa`) and DSA (`ssh-dss`) CA signatures in `checkCertificate`.
* Fix a trailing-backslash parsing bug in `shellwords.Parse` that could cause a slice-bounds panic during tab auto-completion.
* Set upstream TCP write deadlines and WebSocket `HandshakeTimeout` in `sshterm-server`.
* Harden `@xterm/xterm` terminal handling in `docroot/ssh.mjs`:
  * Clamp `CSI Ps b` (`REP`) and `CSI I`, `Z`, `L`, `M`, `S`, `T` parameters to terminal dimensions to prevent `RangeError` crashes (which wedged `WriteBuffer` and deadlocked WASM writes) and `2^31 - 1` synchronous main-thread loops.
  * Sanitize and truncate `OSC 0`/`OSC 2` window titles while reusing a single toast element in `_showMessage`, and reset terminal modes and pending input buffers when an SSH or SFTP session exits.

## v0.11.5

### :star: Feature improvements

* The lightweight sshterm server is now built automatically.

## v0.11.4

### :star2: New features

* Add a lightweight standalone server option that embeds the docroot.

### :wrench: Misc

* Update go 1.27.3

## v0.11.3

### :lock: Security fixes

* Only trust a host certificate when the Certificate Authority is trusted for the certificate's hostname, not the endpoint alias name, and only offer principals in the host-key prompt for which the CA is trusted.
* Reject certificates with `ValidBefore == 0` as expired, while continuing to accept `ssh.CertTimeInfinity` (`0xffffffffffffffff`).
* Expand SFTP wildcard patterns after CLI flag parsing so remote file names starting with `-` cannot inject command flags, and strip directory components from uploaded local file names.
* Require confirmation when `CTRL-ALT-W` triggers `db wipe`, and only process keyboard shortcuts at the top-level `sshterm>` prompt.
* Clear keys from the in-memory SSH agent on `db wipe`, `db restore`, `keys delete`, `keys generate`, `keys discover`, and `keys import`, even when the agent is locked. `db wipe` and `db restore` also reset the agent lock.
* Reject invalid host keys in `config.json`'s `hosts[].key`. The error is reported and the remaining preset config is still applied.
* Bind the WebAuthn public key blob as AES-GCM additional authenticated data (AAD) in encrypted WebAuthn key files (existing v1 keys can still be loaded), verify the registration challenge in `WebAuthn.Create`, and enforce a minimum of 1,000 PBKDF2 iterations on encrypted WebAuthn keys and database backups.
* Sanitize certificate critical option names, certificate comments in `keys show`, and error messages in the host-key prompt, and strip 8-bit `CSI` (`\x9b`) characters from pasted text.
* Show a popup notification in addition to the terminal message when a forwarded agent signs a request.

### :wrench: Bug fixes

* Fix `agent remove <name>` for WebAuthn (`ecdsa-sk`) keys and deleted keys, and avoid holding the agent lock while fetching user certificates from an identity provider.
* Fix `caTrustedFor` and host-certificate trust updates when the hostname includes a `:port` suffix (such as jump hosts).
* Fix `db restore` when restoring empty maps, keys with identity providers, or backups with `persist: false`, and respect `config.json`'s `persist` setting.
* Keep `sftp get` working across multiple screens when one screen exits.
* Prevent `autoConnect` from overwriting keys and settings saved by other open tabs.
* Fix a race condition when aborting a ZMODEM transfer with `Ctrl-C`, and reject negative file sizes in ZMODEM `ZFILE` headers.
* Fix WebSocket connection cancellation and release `js.Func` callbacks across `websocket`, `terminal`, `jsutil`, `indexeddb`, `sftp`, and `app`.

### :wrench: Misc

* Update go 1.27.2
* Update go dependencies:
  * upgraded github.com/fxamacker/cbor/v2 v2.9.4 => v2.9.6
  * upgraded github.com/xrash/smetrics v0.0.0-20250705151800-55b8f293f342 => v0.0.0-20261013231157-39c47d93efba
  * upgraded golang.org/x/crypto v0.57.0 => v0.58.0
  * upgraded golang.org/x/sys v0.48.0 => v0.49.0
  * upgraded golang.org/x/term v0.46.0 => v0.47.0

## v0.11.2

### :lock: Security fixes

This release fixes a number of issues found in a security review. Some of them change the app's behavior:

* Host certificates are now only trusted when the hostname is one of the certificate's principals. Before, a certificate signed by a trusted authority was accepted for any hostname that the authority was trusted for, so any host with a valid certificate could impersonate the others. Like OpenSSH, a certificate with no principals is valid for any host.
  * Endpoints have a new optional hostname, which is used to validate host certificates when the endpoint's name is different from the server's hostname, e.g. `ep add --hostname myserver.example.com myserver <url>`, or `"hostname"` in `config.json`. Without it, the endpoint's name is used, as before.
  * When a host certificate is otherwise trusted but doesn't list the endpoint's hostname, the prompt offers to use one of the certificate's principals as the endpoint's hostname.
* ZMODEM transfers must now be confirmed before they start. Before, any output containing a ZMODEM header, e.g. `cat` of a file, could save files to the Downloads folder or open the file picker.
  * ZMODEM downloads now require the service worker, like `sftp get`.
* With agent forwarding (`ssh -A`), each signature request from the remote host is shown in the terminal. The remote host can no longer lock, unlock, or remove keys from the agent.
* Text from remote servers is sanitized before it is displayed: SSH banners, host certificate details, SFTP file names, ZMODEM file names, and error messages. Like OpenSSH, banners are now displayed without colors. File names with control characters are shown with `?`.
* Escape characters are removed from pasted text, so that text copied from a malicious web page can't end bracketed paste mode early and run commands.
* SSH Term now refuses to run inside a frame. The README has the HTTP headers that deployments should also set when they can.
* The Content Security Policy uses `'wasm-unsafe-eval'` instead of `'unsafe-eval'`. SSH Term now requires Chrome 97, Firefox 102, Safari 16, or newer.
* Database backups now use 600,000 PBKDF2 iterations by default, and `db backup --iter` must be at least 100,000. Existing backups can still be restored.
* Keys from `generateKeys` in `config.json` are no longer re-generated when they already exist. Before, they were re-generated on every page load, and resident keys were replaced on the security key each time.

### :wrench: Bug fixes

* Fix crashes and hangs caused by unexpected input:
  * SFTP transfers of empty files, or of files whose size is reported as 0 by the server, e.g. in `/proc`.
  * Downloads of files with non-ASCII names.
  * Malformed WebAuthn key files and backup files.
  * Invalid endpoint URLs and unexpected WebSocket messages.
* Only send the tlsproxy CSRF token to identity providers on the same origin.
* Harden the stream helper service worker.
* Fix `sftp get` after a ZMODEM download.

## v0.10.0

### :star: Feature improvements

* Add support for discoverable WebAuthn keys. (Thanks to @tbutter)
  * WebAuthn keys generated with `--resident` (or `-r`) can easily be recovered without backups with `keys discover`.

### :wrench: Misc

* Update go dependencies:
  * upgraded github.com/fxamacker/cbor/v2 v2.9.3 => v2.9.4
  * upgraded golang.org/x/crypto v0.56.0 => v0.57.0
  * upgraded golang.org/x/sys v0.47.0 => v0.48.0
  * upgraded golang.org/x/term v0.45.0 => v0.46.0

## v0.9.0

### :star2: New features

* Add support for ZMODEM in-band file transfers (`rz`/`sz`). File uploads and downloads can now be triggered natively within SSH sessions using the `-z` or `--zmodem` flag.

### :wrench: Misc
* Update go 1.27.1
* Update go dependencies:
  * golang.org/x/crypto v0.55.0 => v0.56.0

## v0.8.5

* Update go 1.27.0
* Update go dependencies:
  * upgraded github.com/fxamacker/cbor/v2 v2.9.2 => v2.9.3

## v0.8.4

* Update go 1.26.6
* Update go dependencies:
  * github.com/fxamacker/cbor/v2 v2.9.1 => v2.9.2
  * github.com/pkg/sftp v1.13.10 => v1.13.11
  * golang.org/x/crypto v0.49.0 => v0.55.0
  * golang.org/x/term v0.42.0 => v0.45.0
  * golang.org/x/sys v0.43.0 => v0.47.0

## v0.8.3

* Update go 1.26.2
* Update go dependencies:
  * github.com/fxamacker/cbor/v2 v2.9.0 => v2.9.1
  * golang.org/x/crypto v0.45.0 => v0.49.0
  * golang.org/x/sys v0.38.0 => v0.43.0
  * golang.org/x/term v0.37.0 => v0.42.0

## v0.8.2

* Update go dependencies:
  * github.com/pkg/sftp v1.13.9 => v1.13.10
  * golang.org/x/crypto v0.43.0 => v0.45.0
  * golang.org/x/sys v0.37.0 => v0.38.0
  * golang.org/x/term v0.36.0 => 0.37.0

## v0.8.1

### :wrench: Misc

* Allow @ in usernames.
* Convert javascript to use ES Modules.
* Update go 1.25.3
* Update go dependencies:
  * upgraded github.com/chromedp/chromedp v0.14.1 => v0.14.2
  * upgraded golang.org/x/crypto v0.42.0 => v0.43.0
  * upgraded golang.org/x/sys v0.36.0 => v0.37.0
  * upgraded golang.org/x/term v0.35.0 => v0.36.0

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
