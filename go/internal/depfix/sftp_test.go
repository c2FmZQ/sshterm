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

package depfix

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/pkg/sftp"
)

func buildSFTPPacket(pktType byte, payload []byte) []byte {
	length := uint32(1 + len(payload))
	out := make([]byte, 4+length)
	binary.BigEndian.PutUint32(out[:4], length)
	out[4] = pktType
	copy(out[5:], payload)
	return out
}

func readClientPacket(r io.Reader) (byte, uint32, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:4])
	pktType := hdr[4]
	payload := make([]byte, length-1)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, err
	}
	var sid uint32
	if len(payload) >= 4 {
		sid = binary.BigEndian.Uint32(payload[:4])
	}
	return pktType, sid, payload, nil
}

// runMockSFTPSession starts a mock SFTP server over an io.Pipe that completes
// the SSH_FXP_INIT / SSH_FXP_VERSION handshake and then invokes handler for
// each request packet sent by the client.
func runMockSFTPSession(t *testing.T, handler func(pktType byte, sid uint32, wr io.Writer)) *sftp.Client {
	t.Helper()
	srvRd, cliWr := io.Pipe()
	cliRd, srvWr := io.Pipe()

	go func() {
		defer srvWr.Close()
		defer srvRd.Close()
		// Expect SSH_FXP_INIT
		pktType, _, _, err := readClientPacket(srvRd)
		if err != nil || pktType != sshFxpInit {
			return
		}
		// Send SSH_FXP_VERSION (version 3)
		ver := make([]byte, 4)
		binary.BigEndian.PutUint32(ver, 3)
		if _, err := srvWr.Write(buildSFTPPacket(sshFxpVersion, ver)); err != nil {
			return
		}
		for {
			pt, sid, _, err := readClientPacket(srvRd)
			if err != nil {
				return
			}
			handler(pt, sid, srvWr)
		}
	}()

	client, err := NewSFTPClientPipe(cliRd, cliWr)
	if err != nil {
		t.Fatalf("NewSFTPClientPipe: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}

func TestSFTPPacketGuard(t *testing.T) {
	cases := []struct {
		name string
		// respond writes a malformed response packet for sid.
		respond func(sid uint32, wr io.Writer)
		// invoke triggers the client operation that unmarshals the response.
		invoke func(c *sftp.Client) error
	}{
		{
			name: "TruncatedStatus",
			respond: func(sid uint32, wr io.Writer) {
				// 4-byte sid only; missing 4-byte status code.
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], sid)
				_, _ = wr.Write(buildSFTPPacket(sshFxpStatus, b[:]))
			},
			invoke: func(c *sftp.Client) error {
				return c.Mkdir("/bad")
			},
		},
		{
			name: "TruncatedRealPathName",
			respond: func(sid uint32, wr io.Writer) {
				// count = 1, filename length = 100, but only 2 bytes follow.
				var b [14]byte
				binary.BigEndian.PutUint32(b[0:4], sid)
				binary.BigEndian.PutUint32(b[4:8], 1)
				binary.BigEndian.PutUint32(b[8:12], 100)
				b[12] = 'a'
				b[13] = 'b'
				_, _ = wr.Write(buildSFTPPacket(sshFxpName, b[:]))
			},
			invoke: func(c *sftp.Client) error {
				_, err := c.Getwd()
				return err
			},
		},
		{
			name: "TruncatedHandle",
			respond: func(sid uint32, wr io.Writer) {
				// handle length = 50, but 0 bytes follow.
				var b [8]byte
				binary.BigEndian.PutUint32(b[0:4], sid)
				binary.BigEndian.PutUint32(b[4:8], 50)
				_, _ = wr.Write(buildSFTPPacket(sshFxpHandle, b[:]))
			},
			invoke: func(c *sftp.Client) error {
				_, err := c.Open("/file")
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/VulnerabilityWithoutRemediation", func(t *testing.T) {
			WithDisabled(&EnableSFTPPacketGuard, func() {
				WithDisabled(&EnableSFTPPathAndRemoveGuard, func() {
					WithDisabled(&EnableSFTPResourceGuard, func() {
						client := runMockSFTPSession(t, func(pktType byte, sid uint32, wr io.Writer) {
							tc.respond(sid, wr)
						})
						panicked := false
						func() {
							defer func() {
								if r := recover(); r != nil {
									panicked = true
								}
							}()
							_ = tc.invoke(client)
						}()
						if !panicked {
							t.Fatalf("expected github.com/pkg/sftp to panic on %s when EnableSFTPPacketGuard is disabled; if fixed upstream, remove EnableSFTPPacketGuard", tc.name)
						}
					})
				})
			})
		})

		t.Run(tc.name+"/RemediationEnabled", func(t *testing.T) {
			client := runMockSFTPSession(t, func(pktType byte, sid uint32, wr io.Writer) {
				tc.respond(sid, wr)
			})
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("unexpected panic with EnableSFTPPacketGuard enabled: %v", r)
					}
				}()
				err = tc.invoke(client)
			}()
			if err == nil {
				t.Fatalf("expected error on %s with EnableSFTPPacketGuard enabled, got nil", tc.name)
			}
		})
	}
}

func TestSFTPPathAndRemoveGuard(t *testing.T) {
	// 1. Verify ReadDirContext path traversal filename ("/..") handling.
	makeReaddirServer := func(t *testing.T) *sftp.Client {
		var sentEntry atomic.Bool
		return runMockSFTPSession(t, func(pktType byte, sid uint32, wr io.Writer) {
			switch pktType {
			case sshFxpOpendir:
				var b [9]byte
				binary.BigEndian.PutUint32(b[0:4], sid)
				binary.BigEndian.PutUint32(b[4:8], 1)
				b[8] = 'h'
				_, _ = wr.Write(buildSFTPPacket(sshFxpHandle, b[:]))
			case sshFxpReaddir:
				if !sentEntry.Swap(true) {
					// Return 1 entry with filename "/.."
					var payload []byte
					var hdr [8]byte
					binary.BigEndian.PutUint32(hdr[0:4], sid)
					binary.BigEndian.PutUint32(hdr[4:8], 1) // count = 1
					payload = append(payload, hdr[:]...)
					// filename = "/.."
					payload = append(payload, 0, 0, 0, 3, '/', '.', '.')
					// longname = "/.."
					payload = append(payload, 0, 0, 0, 3, '/', '.', '.')
					// attrs flags = 0
					payload = append(payload, 0, 0, 0, 0)
					_, _ = wr.Write(buildSFTPPacket(sshFxpName, payload))
					return
				}
				// Second READDIR returns SSH_FX_EOF (1).
				var b [16]byte
				binary.BigEndian.PutUint32(b[0:4], sid)
				binary.BigEndian.PutUint32(b[4:8], 1)
				_, _ = wr.Write(buildSFTPPacket(sshFxpStatus, b[:]))
			default:
				// SSH_FX_OK (0) for SSH_FXP_CLOSE
				var b [16]byte
				binary.BigEndian.PutUint32(b[0:4], sid)
				_, _ = wr.Write(buildSFTPPacket(sshFxpStatus, b[:]))
			}
		})
	}

	t.Run("ReadDirTraversal/VulnerabilityWithoutRemediation", func(t *testing.T) {
		WithDisabled(&EnableSFTPPathAndRemoveGuard, func() {
			client := makeReaddirServer(t)
			entries, err := client.ReadDir("/dir")
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			if len(entries) != 1 || entries[0].Name() != ".." {
				t.Fatalf("expected pkg/sftp ReadDir to return Name() == \"..\" for \"/..\", got %v; if fixed upstream, remove EnableSFTPPathAndRemoveGuard", entries)
			}
		})
	})

	t.Run("ReadDirTraversal/RemediationEnabled", func(t *testing.T) {
		client := makeReaddirServer(t)
		_, err := client.ReadDir("/dir")
		if err == nil {
			t.Fatal("expected ReadDir to reject \"/..\" filename when EnableSFTPPathAndRemoveGuard is enabled")
		}
	})

	// 2. Verify RemoveAll symlink following against a real local sftp.Server.
	setupSymlinkTree := func(t *testing.T) (string, string, string, *sftp.Client) {
		t.Helper()
		tmpDir := t.TempDir()
		targetDir := filepath.Join(tmpDir, "target")
		if err := os.Mkdir(targetDir, 0o755); err != nil {
			t.Fatal(err)
		}
		secretFile := filepath.Join(targetDir, "keep.txt")
		if err := os.WriteFile(secretFile, []byte("important"), 0o600); err != nil {
			t.Fatal(err)
		}
		linkPath := filepath.Join(tmpDir, "link_to_target")
		if err := os.Symlink(targetDir, linkPath); err != nil {
			t.Fatal(err)
		}

		c1, s1 := io.Pipe()
		s2, c2 := io.Pipe()
		srv, err := sftp.NewServer(struct {
			io.Reader
			io.WriteCloser
		}{c1, c2})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_ = srv.Serve()
		}()
		t.Cleanup(func() {
			_ = srv.Close()
		})
		client, err := NewSFTPClientPipe(s2, s1)
		if err != nil {
			t.Fatal(err)
		}
		return linkPath, secretFile, targetDir, client
	}

	t.Run("RemoveAllSymlink/VulnerabilityWithoutRemediation", func(t *testing.T) {
		WithDisabled(&EnableSFTPPathAndRemoveGuard, func() {
			linkPath, secretFile, _, client := setupSymlinkTree(t)
			_ = RemoveAll(client, linkPath)
			if _, err := os.Stat(secretFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected pkg/sftp Client.RemoveAll to follow symlink and delete %s; if fixed upstream, remove RemoveAll wrapper", secretFile)
			}
		})
	})

	t.Run("RemoveAllSymlink/RemediationEnabled", func(t *testing.T) {
		linkPath, secretFile, _, client := setupSymlinkTree(t)
		if err := RemoveAll(client, linkPath); err != nil {
			t.Fatalf("RemoveAll: %v", err)
		}
		if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected symlink %s to be removed, err = %v", linkPath, err)
		}
		if _, err := os.Stat(secretFile); err != nil {
			t.Errorf("expected target file %s to remain intact, err = %v", secretFile, err)
		}
	})
}

func TestSFTPResourceGuard(t *testing.T) {
	// Zero-length SSH_FXP_DATA infinite read loop test.
	makeZeroDataServer := func(t *testing.T, readCalls *atomic.Int32) *sftp.Client {
		return runMockSFTPSession(t, func(pktType byte, sid uint32, wr io.Writer) {
			switch pktType {
			case 3: // SSH_FXP_OPEN
				var b [9]byte
				binary.BigEndian.PutUint32(b[0:4], sid)
				binary.BigEndian.PutUint32(b[4:8], 1)
				b[8] = 'f'
				_, _ = wr.Write(buildSFTPPacket(sshFxpHandle, b[:]))
			case 5: // SSH_FXP_READ
				n := readCalls.Add(1)
				if n >= 5 {
					// Stop the infinite loop in vulnerable mode after 5 iterations.
					var b [16]byte
					binary.BigEndian.PutUint32(b[0:4], sid)
					binary.BigEndian.PutUint32(b[4:8], 1) // SSH_FX_EOF
					_, _ = wr.Write(buildSFTPPacket(sshFxpStatus, b[:]))
					return
				}
				// Respond with 0-byte SSH_FXP_DATA.
				var b [8]byte
				binary.BigEndian.PutUint32(b[0:4], sid)
				binary.BigEndian.PutUint32(b[4:8], 0)
				_, _ = wr.Write(buildSFTPPacket(sshFxpData, b[:]))
			default:
				var b [16]byte
				binary.BigEndian.PutUint32(b[0:4], sid)
				_, _ = wr.Write(buildSFTPPacket(sshFxpStatus, b[:]))
			}
		})
	}

	t.Run("ZeroByteData/VulnerabilityWithoutRemediation", func(t *testing.T) {
		WithDisabled(&EnableSFTPResourceGuard, func() {
			var readCalls atomic.Int32
			client := makeZeroDataServer(t, &readCalls)
			f, err := client.Open("/zero")
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer f.Close()
			buf := make([]byte, 16)
			_, _ = f.Read(buf)
			if got := readCalls.Load(); got < 5 {
				t.Fatalf("expected pkg/sftp to loop on 0-byte SSH_FXP_DATA (readCalls=%d, want >=5); if fixed upstream, remove EnableSFTPResourceGuard", got)
			}
		})
	})

	t.Run("ZeroByteData/RemediationEnabled", func(t *testing.T) {
		var readCalls atomic.Int32
		client := makeZeroDataServer(t, &readCalls)
		f, err := client.Open("/zero")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer f.Close()
		buf := make([]byte, 16)
		_, err = f.Read(buf)
		if err == nil {
			t.Fatal("expected error on 0-byte SSH_FXP_DATA with EnableSFTPResourceGuard enabled")
		}
		if got := readCalls.Load(); got != 1 {
			t.Fatalf("readCalls = %d, want 1", got)
		}
	})
}
