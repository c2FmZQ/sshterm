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
	// EnableSFTPResourceGuard rejects 0-byte SSH_FXP_DATA packets (which
	// cause an infinite read loop in File.readChunkAt), 0-count
	// SSH_FXP_NAME responses to SSH_FXP_READDIR, and caps cumulative
	// SSH_FXP_READDIR entries per directory listing.
	// Remove when github.com/pkg/sftp (v1.13.12) handles 0-byte
	// SSH_FXP_DATA and bounds ReadDirContext.
	EnableSFTPResourceGuard = true

	// EnableSSHAgentGuard bounds concurrent "auth-agent@openssh.com"
	// channels and caps incoming agent request frames to 256 KiB before
	// golang.org/x/crypto/ssh/agent (v0.58.0) ServeAgent pre-allocates up
	// to 16 MiB per channel upon reading a 4-byte length header.
	// Remove when golang.org/x/crypto/ssh/agent bounds channel concurrency
	// and request pre-allocation.
	EnableSSHAgentGuard = true
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
