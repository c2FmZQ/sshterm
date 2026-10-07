# Security review TODO

Tracking list for issues found in the 2026-10-06 security review. Check items
off as they are fixed. Delete this file once every item is done.

## High

- [x] **1. Host certificate principals are not checked.**
  `go/internal/app/cert_util.go`, `go/internal/app/ssh.go` (`hostCertificateCallback`).
  A host cert from a CA trusted for `*.example.com` is accepted for any
  matching hostname, regardless of `cert.ValidPrincipals`. Any host with a
  valid cert can impersonate the others. Require the hostname to be in the
  cert's principals; add a regression test.

## Medium

- [x] **2. ZMODEM downloads start without user consent.**
  `go/internal/zmodem/filter.go`, `go/internal/zmodem/receive.go`,
  `go/internal/app/zmodem.go`. Any output containing `**\x18B00` (cat of a log,
  git log, etc.) starts a receive session and drops attacker-named files into
  Downloads; protocol replies are typed into the remote's stdin. Prompt the
  user (name + size) before accepting each file; skip/cancel on decline.

## Low

- [ ] **3. Divide-by-zero in SFTP progress crashes the app.**
  `go/internal/app/sftp.go` (`get` progress, `sftpUploadFile`). Server-reported
  size 0 for a non-empty file panics in the stream `pull` goroutine (no
  recover → WASM exits). Dropping an empty file in sftp crashes too.
- [ ] **4. Downloads hang on non-Latin-1 filenames.**
  `go/internal/jsutil/streams.go` (`filename=%q`), `docroot/stream-helper.js`.
  `new Response` throws on non-ByteString header; promise never settles and
  `Download` blocks forever. Use `filename*=UTF-8''…` with ASCII fallback;
  try/catch in the service worker; don't wait forever.
- [ ] **5. Server-controlled strings written to the terminal unescaped.**
  SSH banner (`ssh.go` `BannerCallback`), SFTP `ls` names and symlink targets
  (`sftp.go`), ZMODEM file names (`zmodem/filter.go`). Mask control chars (and
  bidi overrides) before printing and before using as download names.
- [ ] **6. Forwarded-agent sign requests give no context; mutex held during WebAuthn.**
  `go/internal/app/agent.go` (`keyRing.Sign`), `go/internal/webauthnsk/key.go`.
  Print which key is being used for a forwarded request before prompting;
  don't hold `r.mu` for the duration of the WebAuthn call.
- [ ] **7. CSP is meta-only; framing allowed; CSP broader than needed.**
  `docroot/index.html`. Document/serve CSP as an HTTP header with
  `frame-ancestors 'none'`; add `base-uri 'none'; form-action 'none'`; replace
  `'unsafe-eval'` with `'wasm-unsafe-eval'`. Add a frame-busting check if needed.
- [ ] **8. Paste can break out of bracketed paste mode.**
  `docroot/ssh.mjs` (right/middle-click paste), xterm 5.5 paste path. Strip
  `ESC` (at least `ESC[201~`) from pasted text.
- [ ] **9. Crafted local files crash or hang the app.**
  `go/internal/webauthnsk/key.go`: nil `pem.Decode` block, nil point from
  `elliptic.Unmarshal`, unbounded PBKDF2 `numIter`.
  `go/internal/app/db.go` restore: `enc[:4]` / `enc[40:]` without length check.
- [ ] **10. WebSocket panics on bad input.**
  `go/internal/websocket/websocket.go`: invalid endpoint URL throws in the
  `WebSocket` constructor (Go panic); text frames make `arrayBuffer` undefined.
  Validate URL scheme in `ep add`, catch constructor errors, set
  `binaryType = "arraybuffer"`.
- [ ] **11. Unbounded memory in ZMODEM download fallback.**
  `go/internal/app/zmodem.go`: `io.ReadAll` when no service worker. Refuse or
  cap at declared size.

## Info / hardening

- [ ] **12. Weak backup KDF defaults.** `go/internal/app/db.go`: 50k
  PBKDF2-SHA256 by default, `--iter 0` accepted. Raise default / enforce minimum.
- [ ] **13. Agent unlock can be brute-forced by forwarded remote.**
  `go/internal/app/agent.go` (`Unlock`): add a delay on failure.
- [ ] **14. CSRF token sent to any identity-provider URL; cookie regex unanchored.**
  `go/internal/jsutil/jsutil.go` (`TLSProxySID`), `go/internal/app/keys.go`
  (`updateCert`). Only send for same-origin URLs; anchor regex.
- [ ] **15. `generateKeys` with `resident: true` re-creates the resident
  credential on every page load.** `go/internal/app/app.go` (`initPresetConfig`).
- [ ] **16. Service worker message handling hardening.**
  `docroot/stream-helper.js`: use a `Map`, only accept responses from the
  client the request was posted to, match `/stream/` on the path only.
- [ ] **17. Each ZMODEM download creates a new StreamHelper.**
  `go/internal/app/zmodem.go`: replaces `navigator.serviceWorker.onmessage`,
  breaking subsequent `sftp get`; leaks `js.FuncOf`. Share one helper and
  honor `StreamHook`.
