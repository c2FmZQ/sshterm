---
name: update-and-audit-deps
description: >-
  Runs scripts/update-go-version.sh (and optionally updates xterm npm
  dependencies) to update the Go toolchain, Go module dependencies, and
  frontend npm packages, then audits all upstream dependency changes for
  supply-chain attacks, security vulnerabilities, regressions, or API contract
  hazards that are exploitable in sshterm or sshterm-server. Use when the user
  asks to update Go or npm/xterm dependencies, run update-go-version.sh, or
  audit updated upstream libraries.
---

# Update and Audit Go & NPM Dependencies

## Overview

This skill updates the Go version and upstream module dependencies using [`scripts/update-go-version.sh`](../../../scripts/update-go-version.sh) (and optionally frontend npm dependencies in `xterm/`), extracts the exact source code diffs between the old and new versions from `GOMODCACHE` and npm registry tarballs, and audits every change for malicious/suspicious code, security vulnerabilities, or subtle behavioral changes before any build, bundle, or test command is executed.

> [!CAUTION]
> **CRITICAL: Never run `go build`, `go test`, `go run`, `go generate`, `./build.sh`, `./go/build.sh`, `./xterm/update.sh`, `npx rollup`, or `npm` without `--ignore-scripts` BEFORE completing the full source diff audit in Step 3, and NEVER run them if suspicious or malicious code is detected in any dependency.**
> Compiling or testing untrusted Go dependency updates can execute attacker-controlled code on the host (via `init()` functions, test binaries, CGo, or compiler directives). Running npm without `--ignore-scripts` or bundling with `npx rollup` can execute attacker-controlled JavaScript on the host (via `preinstall`/`install`/`postinstall` hooks or bundler plugins). If suspicious code is found during Step 3, stop immediately, do not build or run tests, and report the finding to the user.

## Workflow

### 1. Check Working Tree & Update Dependencies

1. Check `git status -s` in the repository root:
   - Confirm what baseline git ref (`BASE_REF`, typically `HEAD`) holds the pre-update `go/go.mod` and `xterm/package-lock.json`.
   - If `go/go.mod` has not yet been updated in the working tree, run:
     ```bash
     ./scripts/update-go-version.sh
     ```
   - If npm/xterm dependencies in `xterm/` should also be updated (and have not yet been updated in the working tree), update `xterm/package-lock.json` using `--package-lock-only --ignore-scripts` (do **not** run `./xterm/update.sh` or `npx rollup` before Step 4):
     ```bash
     (cd xterm && npm update --package-lock-only --ignore-scripts)
     ```
2. Inspect `git diff Dockerfile .goversion go/go.mod CHANGELOG.md xterm/package.json xterm/package-lock.json` to see which Go version, Go modules, and npm packages were updated.
   - Note: `scripts/update-go-version.sh` prepends a new `## next` block to `CHANGELOG.md` when the Go version or Go modules change. If `CHANGELOG.md` already had a `## next` section, merge the duplicate `## next` heading cleanly.

### 2. Generate Upstream Source Diffs

Run the helper script [`scripts/diff-go-deps.sh`](./scripts/diff-go-deps.sh) against the pre-update git ref (`HEAD` if changes are uncommitted, or `HEAD~1` if the update was already committed):

```bash
./.agents/skills/update-and-audit-deps/scripts/diff-go-deps.sh HEAD /tmp/sshterm-dep-audit
```

- The script downloads both the previous and updated versions of each changed Go module in `go/go.mod` into `GOMODCACHE` and unpacks both the previous and updated tarballs of each changed npm package in `xterm/package-lock.json` without executing any scripts, locates every `.go` file in `go/` that imports each changed Go module, and writes:
  - `/tmp/sshterm-dep-audit/summary.md`: Overview of all changed Go modules and npm packages, their unpacked source directories, importing files in this repo, install lifecycle script warnings, and diff line counts.
  - `/tmp/sshterm-dep-audit/<module>.diff`: Unified diff of non-test Go source files between the old and new versions.
  - `/tmp/sshterm-dep-audit/npm_<package>.diff`: Unified diff of unpacked npm package files between the old and new versions.
- Read `/tmp/sshterm-dep-audit/summary.md` first.

### 3. Audit Upstream Changes and `sshterm` / `sshterm-server` Call Sites

For each upgraded Go module or npm package (delegate to parallel `research` subagents if multiple large diffs exist):

1. **Read the upstream diff** (`/tmp/sshterm-dep-audit/<module>.diff` or `/tmp/sshterm-dep-audit/npm_<package>.diff`) and the surrounding upstream code in `GOMODCACHE` or `/tmp/sshterm-dep-audit/npm/`.
2. **Read every call site** in `sshterm` (`go/internal/app/`, `go/internal/webauthnsk/`, `go/internal/terminal/`, `go/internal/websocket/`, `go/internal/jsutil/`, `go/internal/indexeddb/`, `go/internal/zmodem/`, `go/internal/shellwords/`, `go/internal/termsafe/`, `docroot/ssh.mjs`, `xterm/`) and `sshterm-server` (`go/sshterm-server/`) that interacts with the upgraded dependency.
3. **Evaluate against supply-chain threats and the `sshterm` / `sshterm-server` threat model**:
   - **Supply-Chain & Suspicious Code Inspection (Must Pass Before Any Build/Test)**:
     - **Go modules**: Check for newly added or modified `init()` functions, `os/exec` commands, `syscall` / `syscall/js` / `unsafe` / `reflect` abuse, `//go:linkname` or `//go:cgo_*` directives, CGo/assembly files, obfuscated strings or encoded payloads (base64/hex blobs), unexpected outbound network calls (`net`, `net/http`), environment variable access (`os.Getenv`, `os.Environ`), or unexpected filesystem reads/writes.
     - **NPM packages**: Check for `preinstall` / `install` / `postinstall` / `prepare` scripts in `package.json`, `child_process` / `fs` / `net` / `http` / `https` / `fetch` / `WebSocket` / `eval` / `Function` calls, obfuscated or minified payloads, prototype pollution, DOM / `IndexedDB` / `localStorage` exfiltration (e.g., reading encrypted/decrypted SSH keys or database state in the browser), or Rollup/Babel plugin changes that inject unauthorized code into `docroot/xterm.mjs`.
     - **If any suspicious, backdoored, or unexplained code is detected: STOP IMMEDIATELY. Do NOT proceed to Step 4 (`./build.sh`, `./xterm/update.sh`, `go test`, or `go build`).** Alert the user with the exact file path and line numbers.
   - **Parsing, Terminal Emulation & Input Validation**:
     - Can malformed network or peer input from an untrusted SSH/SFTP server or WebSocket peer (SSH handshake/kex/channel/agent packets in `golang.org/x/crypto/ssh`, SFTP packet headers/attributes/paths/symlinks in `github.com/pkg/sftp`, WebSocket frames in `github.com/gorilla/websocket`, CBOR/COSE WebAuthn attestation/assertion structures in `github.com/fxamacker/cbor/v2`, CLI flags/arguments in `github.com/urfave/cli/v2`, or ANSI/CSI/OSC/DCS escape sequences in `@xterm/xterm` and `golang.org/x/term`) trigger panics, uncaught JS exceptions (such as `RangeError` wedging `WriteBuffer` and deadlocking WASM writes), slice bounds errors, nil-pointer dereferences, or command/flag/path injection?
     - Does any `@xterm/xterm` or `@xterm/addon-fit` change break or bypass the terminal hardening in `docroot/ssh.mjs` (`applyXtermWorkarounds` via `term._core.registerCsiHandler`, `csiRepGuard`, `csiLoopGuard`, `sanitizeTitle`, or capture-phase paste handler stripping `\x1b` and `\x9b`) or `go/internal/termsafe`?
     - In `sshterm-server`, does any change affect `ParseEndpoint`, `checkOrigin`, WebSocket upgrade handling, static file serving, or Content-Security-Policy enforcement?
   - **Cryptographic, SSH, Certificate & WebAuthn Verification**:
     - Are SSH host key verification, host/user certificate checks (`checkCertificate`, `ValidAfter`/`ValidBefore`, `CertTimeInfinity`, CA domain/principal matching in `caTrustedFor`, rejection of `ssh-rsa` SHA-1 and `ssh-dss` signatures), RSA SHA-2 (`rsa-sha2-256` / `rsa-sha2-512`) signing in `dynSigner` and `agent.ExtendedAgent` (`SignWithFlags`), OpenSSH private key encryption, IndexedDB backup encryption (`pbkdf2` + `nacl/secretbox`), and WebAuthn `ecdsa-sk` COSE/CBOR validation and AES-GCM AAD key wrapping still strictly enforced?
   - **Resource Exhaustion, Memory/Callback Leaks & DoS**:
     - Can an untrusted SSH/SFTP server, ZMODEM sender, or WebSocket client cause unbounded memory allocation (e.g., pre-allocating buffers from untrusted length fields in `sftp` or `ssh`, or synchronous main-thread loops in `@xterm/xterm`)?
     - Are WebSocket connections, SFTP streams/service-worker downloads, `syscall/js` `js.Func` callbacks, and `sshterm-server` TCP proxy connections (`HandshakeTimeout`, `tcpDeadlineWriter`, ping/pong watchdog) properly closed and released on early close, context cancellation, or error paths?

### 4. Build, Test, and Report Findings

> [!IMPORTANT]
> **Only run the build, bundle, and test commands below if Step 3 confirmed that no suspicious or malicious code was introduced in any dependency diff.** If suspicious code was detected, skip Step 4.1 entirely and report the suspicious code immediately.

1. Run the bundle, build, vet, and test checks (only after all diffs pass inspection):
   ```bash
   # If xterm/package.json or xterm/package-lock.json changed, rebuild docroot/xterm.mjs:
   ./xterm/update.sh

   # Build ssh.wasm, tests.wasm, and sshterm-server:
   ./build.sh

   # Run go vet (WASM target) and unit tests:
   (cd go && GOTOOLCHAIN="go$(cat ../.goversion)" GOOS=js GOARCH=wasm go vet ./...)
   (cd go && GOTOOLCHAIN="go$(cat ../.goversion)" go test -count=1 ./...)
   ```
   - If WASM, browser, or `@xterm/xterm` integration behavior was affected and Docker is available, also run `./tests/run-headless-tests.sh`.
2. Present a concise, triaged report of the audit:
   - **Summary Table of Upgraded Dependencies**: Module/package name, ecosystem (Go / npm), old -> new version, and audit status.
   - **Triaged Findings (Critical / High / Medium / Low)**:
     - Exact upstream file and line numbers in `GOMODCACHE` or unpacked npm tarball
     - Exact `sshterm` / `sshterm-server` call-site file and line numbers
     - Exploitability preconditions and impact
     - Recommended fix location (`sshterm`/`sshterm-server`, sibling `github.com/c2FmZQ/*` repository, or upstream third-party library)
