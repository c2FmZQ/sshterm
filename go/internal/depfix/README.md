# Dependency Security Remediations (`internal/depfix`)

This package centralizes workarounds for security issues in third-party dependencies so that:

1. **Isolation**: Each workaround is controlled by a boolean flag in [`depfix.go`](depfix.go) (or `workarounds` in [`docroot/ssh.mjs`](../../../docroot/ssh.mjs) for `@xterm/xterm`).
2. **Dual-Mode Verification**: Every workaround has unit/integration tests that run in two subtests:
   * `VulnerabilityWithoutRemediation`: Temporarily disables the workaround via `depfix.WithDisabled(&depfix.Enable..., ...)` and asserts that the upstream dependency still exhibits the vulnerable behavior.
   * `RemediationEnabled`: Runs with the workaround enabled (the default) and asserts that the vulnerability is blocked.
3. **Automatic Retirement Signal**: When a dependency is upgraded in `go.mod` or `docroot/` and an upstream fix resolves the underlying issue, the corresponding `VulnerabilityWithoutRemediation` subtest will **fail**, signaling that the workaround can be retired.

## Active Workarounds

| Flag | Dependency | Issue |
| :--- | :--- | :--- |
| *(Retired in `v1.13.12`)* | `github.com/pkg/sftp` `v1.13.11` | Unchecked `unmarshalUint32` / `unmarshalString` slice bounds panics and `Client.RemoveAll` directory symlink traversal (`TestSFTPPacketGuard` and `TestSFTPRemoveAllSymlink` retained as regression tests). |
| `EnableSFTPResourceGuard` | `github.com/pkg/sftp` `v1.13.12` | Infinite read loop on 0-byte `SSH_FXP_DATA` in `File.readChunkAt`, infinite loop on 0-count `SSH_FXP_NAME`, and unbounded slice growth in `ReadDirContext`. |
| `EnableSSHAgentGuard` | `golang.org/x/crypto` `v0.58.0` | Unbounded concurrent `"auth-agent@openssh.com"` channels in `agent.ForwardToAgent` and 16 MiB per-channel buffer pre-allocation on a 4-byte length header in `agent.ServeAgent`. |
| `workarounds.csiRepGuard` | `@xterm/xterm` `5.5.0` | `CSI Ps b` (`repeatPrecedingCharacter`) uncaught `RangeError` permanently wedging `WriteBuffer`. |
| `workarounds.csiLoopGuard` | `@xterm/xterm` `5.5.0` | Unbounded $2^{31}-1$ synchronous `while (param--)` loops in `CSI I`, `Z`, `L`, `M`, `S`, and `T`. |

## Retiring a Workaround After an Upstream Fix

1. Upgrade the dependency and run `go test ./...` (and browser tests if applicable).
2. For any `VulnerabilityWithoutRemediation` test that fails because the upstream library now handles the case safely:
   * Remove the `VulnerabilityWithoutRemediation` subtest, keeping the `RemediationEnabled` subtest as a regression test.
   * Remove the corresponding `Enable...` flag and wrapper logic from `internal/depfix` (or `docroot/ssh.mjs`) and call the upstream API directly.
