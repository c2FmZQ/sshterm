// MIT License
//
// Copyright (c) 2026 TTBT Enterprises LLC
// Copyright (c) 2026 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package depfix centralizes security workarounds and remediations for
// third-party dependencies so they can be tested in both vulnerable and
// remediated states and cleanly removed when fixed upstream.
package depfix

var (
	// EnableSFTPPathAndRemoveGuard rejects SSH_FXP_READDIR filenames that
	// contain '/' or resolve to '.' or '..' after path.Base.
	// Remove when github.com/pkg/sftp (v1.13.12) validates ReadDirContext
	// filenames before passing them to path.Base.
	EnableSFTPPathAndRemoveGuard = true

	// EnableSFTPResourceGuard rejects 0-byte SSH_FXP_DATA packets (which
	// cause an infinite read loop in File.readChunkAt), 0-count
	// SSH_FXP_NAME responses to SSH_FXP_READDIR, and caps cumulative
	// SSH_FXP_READDIR entries per directory listing.
	// Remove when github.com/pkg/sftp (v1.13.12) handles 0-byte
	// SSH_FXP_DATA and bounds ReadDirContext.
	EnableSFTPResourceGuard = true

	// EnableSSHAgentGuard bounds concurrent "auth-agent@openssh.com"
	// channels, caps incoming agent request frames to 256 KiB before
	// golang.org/x/crypto/ssh/agent (v0.58.0) ServeAgent pre-allocates up
	// to 16 MiB per channel, and rejects non-list/sign agent request types
	// before ServeAgent parses attacker-supplied private keys.
	// Remove when golang.org/x/crypto/ssh/agent bounds channel concurrency
	// and request pre-allocation.
	EnableSSHAgentGuard = true

	// EnableRSASHA2 enables ssh.MultiAlgorithmSigner on dynSigner and
	// agent.ExtendedAgent on keyRing and forwardedAgent so RSA keys and
	// certificates use rsa-sha2-256 / rsa-sha2-512 instead of falling back
	// to SHA-1 (ssh-rsa) in golang.org/x/crypto/ssh (v0.58.0).
	EnableRSASHA2 = true

	// EnableSSHSessionExitGuard wraps "session" channel request streams so
	// malformed "exit-status" or "exit-signal" requests close the session
	// channel and drain remaining channel requests instead of deadlocking
	// the SSH connection multiplexer in golang.org/x/crypto/ssh (v0.58.0).
	// Remove when (*ssh.Session).wait drains reqs and unblocks Wait on
	// malformed exit requests.
	EnableSSHSessionExitGuard = true

	// EnableCertSignatureGuard rejects deprecated SHA-1 (ssh-rsa) and DSA
	// (ssh-dss) CA signatures in checkCertificate and supports security-key
	// (sk-*) CA signatures that omit the UserPresence flag.
	EnableCertSignatureGuard = true

	// EnableTermEscapeGuard terminates runaway (>64-byte) unterminated
	// escape sequences before golang.org/x/term (v0.47.0) fills its fixed
	// 256-byte Terminal.inBuf and spins in a synchronous 0-byte Read loop.
	// Remove when golang.org/x/term handles full inBuf escape sequences.
	EnableTermEscapeGuard = true
)

// WithDisabled temporarily sets *flag to false while running fn, then restores
// its previous value so tests can verify both the underlying vulnerability and
// its remediation.
func WithDisabled(flag *bool, fn func()) {
	prev := *flag
	*flag = false
	defer func() {
		*flag = prev
	}()
	fn()
}
