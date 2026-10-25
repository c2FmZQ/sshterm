# Dependency Security Remediations (`depfix` & `ssh.mjs`)

This package and the `workarounds` object in [`docroot/ssh.mjs`](../../../docroot/ssh.mjs) centralize security remediations for third-party Go and JavaScript dependencies.

## How the Mechanism Works

1. **Feature Flags**:
   * In Go ([`depfix.go`](./depfix.go)), each remediation is controlled by an exported boolean flag (defaulting to `true`).
   * In JavaScript ([`docroot/ssh.mjs`](../../../docroot/ssh.mjs)), each `@xterm/xterm` remediation is controlled by a property on `window.sshApp.workarounds` (defaulting to `true`).
2. **Dual-Mode Verification Tests**:
   * Every remediation has a corresponding test with two subtests:
     * `VulnerabilityWithoutRemediation`: Temporarily disables the flag via `depfix.WithDisabled(&Flag, ...)` (or `workarounds.<flag> = false`) and asserts that the underlying dependency still exhibits the vulnerability.
     * `RemediationEnabled`: Runs with the flag enabled (`true`) and asserts that the remediation prevents the vulnerability.
3. **Removing a Remediation After an Upstream Fix**:
   * When a dependency is upgraded in `go/go.mod` or `xterm/package.json` and fixes the issue upstream, the `VulnerabilityWithoutRemediation` subtest will fail with an explicit message indicating which flag/wrapper can now be removed.
   * To remove the remediation:
     1. Replace the `depfix.*` wrapper call at the call site with the direct upstream call (or remove the handler registration in `applyXtermWorkarounds`).
     2. Delete the corresponding flag in `depfix.go` / `ssh.mjs` and the `VulnerabilityWithoutRemediation` subtest, keeping the `RemediationEnabled` test as a regression test against the upstream package.

## Remediations Inventory

| Flag / Workaround | Dependency | Vulnerability Remediated | Call Site(s) |
| :--- | :--- | :--- | :--- |
| `EnableSFTPPacketGuard` | `github.com/pkg/sftp@v1.13.11` | Out-of-bounds slice panics in `unmarshalStatus`, `RealPath`, `ReadLink`, `ReadDirContext`, `opendir`, `open`, `readChunkAt`, and `readAt` on truncated/malformed packets | [`go/internal/app/sftp.go`](../app/sftp.go) |
| `EnableSFTPPathAndRemoveGuard` | `github.com/pkg/sftp@v1.13.11` | `ReadDirContext` path-sanitization bypass (`"/.."` -> `".."` via `path.Base`) and `Client.RemoveAll` following directory symlinks via `Stat` | [`go/internal/app/sftp.go`](../app/sftp.go) |
| `EnableSFTPResourceGuard` | `github.com/pkg/sftp@v1.13.11` | Infinite `SSH_FXP_READ` loop on 0-byte `SSH_FXP_DATA` packets and unbounded `ReadDirContext` entry accumulation | [`go/internal/app/sftp.go`](../app/sftp.go) |
| `EnableSSHAgentGuard` | `golang.org/x/crypto@v0.58.0` (`ssh/agent`) | Unbounded concurrent `"auth-agent@openssh.com"` channels, 16 MiB unread pre-allocation per channel in `ServeAgent`, and CPU exhaustion in `parseRSAKey` on disallowed `AddIdentity` requests | [`go/internal/app/ssh.go`](../app/ssh.go) |
| `EnableRSASHA2` | `golang.org/x/crypto@v0.58.0` (`ssh`, `ssh/agent`) | Downgrade to deprecated SHA-1 (`ssh-rsa`) when `dynSigner` omits `ssh.MultiAlgorithmSigner` or `forwardedAgent`/`keyRing` omits `agent.ExtendedAgent` | [`go/internal/app/keys.go`](../app/keys.go), [`go/internal/app/agent.go`](../app/agent.go) |
| `EnableSSHSessionExitGuard` | `golang.org/x/crypto@v0.58.0` (`ssh`) | Multiplexer (`mux.loop()`) and `(*Session).Wait()` deadlock when a server sends a malformed `"exit-status"` or `"exit-signal"` request followed by >16 channel requests | [`go/internal/app/ssh.go`](../app/ssh.go) |
| `EnableCertSignatureGuard` | `golang.org/x/crypto@v0.58.0` (`ssh`) | Acceptance of deprecated SHA-1 (`ssh-rsa`) / DSA (`ssh-dss`) CA signatures and rejection of `no-touch-required` (`Flags=0`) `sk-*` CA signatures | [`go/internal/app/cert_util.go`](../app/cert_util.go) |
| `EnableTermEscapeGuard` | `golang.org/x/term@v0.47.0` | Synchronous 100% CPU 0-byte `Read` infinite loop when `Terminal.inBuf` (`[256]byte`) fills with an unterminated escape sequence | [`go/internal/terminal/terminal.go`](../terminal/terminal.go), [`go/internal/app/sftp.go`](../app/sftp.go) |
| `workarounds.csiRepGuard` | `@xterm/xterm@5.5.0` | Uncaught `RangeError: Invalid typed array length` in `CSI Ps b` (`repeatPrecedingCharacter`) permanently wedging `WriteBuffer` and deadlocking Go WASM `Write` | [`docroot/ssh.mjs`](../../../docroot/ssh.mjs) |
| `workarounds.csiLoopGuard` | `@xterm/xterm@5.5.0` | Unbounded $2^{31}-1$ synchronous `while (param--)` loops in `CSI I`, `Z`, `L`, `M`, `S`, and `T` freezing the browser main thread | [`docroot/ssh.mjs`](../../../docroot/ssh.mjs) |
| `workarounds.oscQueryAndLinkGuard` | `@xterm/xterm@5.5.0` | `OSC 4` chained color query amplification and unbounded `OSC 8` hyperlink `Marker`/listener retention | [`docroot/ssh.mjs`](../../../docroot/ssh.mjs) |

## Documented Residual Risks

1. **Single-Threaded 32-bit WebAssembly Runtime (`GOOS=js GOARCH=wasm`)**:
   * All tabs (`AddScreen`) within the same browser page share a single Go WASM instance with a 32-bit address space (2–4 GiB maximum linear memory) and cooperative goroutine scheduling on a single OS/WebWorker thread. While `depfix` caps per-channel agent frames (`256 KiB`), SFTP packet frames (`256 KiB`), and `ReadDir` entry counts (`100,000`), an authenticated remote server that streams continuous high-bandwidth output across many tabs can still contend for CPU time and memory within that browser tab.
2. **OpenSSH Ed25519 Private Key Public-Half Consistency (`golang.org/x/crypto/ssh`)**:
   * In `golang.org/x/crypto/ssh`, `parseOpenSSHPrivateKey` does not verify that the 32-byte public key embedded inside an unencrypted/decrypted `ed25519` private key matches `ed25519.NewKeyFromSeed(priv[:32])[32:]`. Because private keys are only imported explicitly by the local user (`keys import`), this is only relevant if a user imports an intentionally corrupted private key file.
3. **Terminal Emulator Escape Sequence Surface (`@xterm/xterm`)**:
   * `applyXtermWorkarounds` intercepts the known unbounded CSI/OSC handlers in `@xterm/xterm@5.5.0`, and `Terminal.ResetSessionState()` resets terminal modes and drains pending `onData` query responses when an SSH or SFTP session exits. However, while an interactive SSH session is actively running, standard terminal auto-responses (such as primary/secondary Device Attributes `CSI c` and cursor position reports `CSI 6n`) remain active as required for terminal compatibility (`vim`, `tmux`, `less`, etc.).
