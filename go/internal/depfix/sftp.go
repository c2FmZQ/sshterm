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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	sshFxpInit    = 1
	sshFxpVersion = 2
	sshFxpClose   = 4
	sshFxpOpendir = 11
	sshFxpReaddir = 12
	sshFxpStatus  = 101
	sshFxpHandle  = 102
	sshFxpData    = 103
	sshFxpName    = 104

	sshFileXferAttrSize        = 0x00000001
	sshFileXferAttrUIDGID      = 0x00000002
	sshFileXferAttrPermissions = 0x00000004
	sshFileXferAttrACmodTime   = 0x00000008
	sshFileXferAttrExtended    = 0x80000000

	maxSFTPPacketSize = 256 * 1024
)

var (
	// MaxSFTPReadDirEntries is the maximum number of directory entries
	// permitted in a single directory listing when EnableSFTPResourceGuard
	// is enabled.
	MaxSFTPReadDirEntries = 100000

	ErrMalformedSFTPPacket = errors.New("sftp: malformed packet from server")
	ErrZeroLengthSFTPData  = errors.New("sftp: zero-length SSH_FXP_DATA packet")
	ErrInvalidSFTPFilename = errors.New("sftp: invalid filename in SSH_FXP_NAME response")
	ErrTooManySFTPEntries  = errors.New("sftp: directory listing exceeds maximum entry limit")
)

// NewSFTPClient creates a new *sftp.Client over conn with path and resource
// guards applied when enabled.
func NewSFTPClient(conn *ssh.Client, opts ...sftp.ClientOption) (*sftp.Client, error) {
	if !EnableSFTPPathAndRemoveGuard && !EnableSFTPResourceGuard {
		return sftp.NewClient(conn, opts...)
	}
	s, err := conn.NewSession()
	if err != nil {
		return nil, err
	}
	pw, err := s.StdinPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	pr, err := s.StdoutPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	if err := s.RequestSubsystem("sftp"); err != nil {
		s.Close()
		return nil, err
	}
	sc := newSFTPSafeConn(pr, &sessionWriteCloser{WriteCloser: pw, sess: s})
	client, err := sftp.NewClientPipe(sc, sc, opts...)
	if err != nil {
		sc.Close()
		return nil, err
	}
	return client, nil
}

// NewSFTPClientPipe creates a new *sftp.Client over rd and wr with path and
// resource guards applied when enabled.
func NewSFTPClientPipe(rd io.Reader, wr io.WriteCloser, opts ...sftp.ClientOption) (*sftp.Client, error) {
	if !EnableSFTPPathAndRemoveGuard && !EnableSFTPResourceGuard {
		return sftp.NewClientPipe(rd, wr, opts...)
	}
	sc := newSFTPSafeConn(rd, wr)
	return sftp.NewClientPipe(sc, sc, opts...)
}

type sessionWriteCloser struct {
	io.WriteCloser
	sess *ssh.Session
}

func (s *sessionWriteCloser) Close() error {
	err := s.WriteCloser.Close()
	_ = s.sess.Close()
	return err
}

type sftpSafeConn struct {
	rd  io.Reader
	wr  io.WriteCloser
	buf bytes.Buffer
	err error

	mu             sync.Mutex
	txBuf          bytes.Buffer
	readdirSIDs    map[uint32]bool
	readdirEntries int
}

func newSFTPSafeConn(rd io.Reader, wr io.WriteCloser) *sftpSafeConn {
	return &sftpSafeConn{
		rd:          rd,
		wr:          wr,
		readdirSIDs: make(map[uint32]bool),
	}
}

func (c *sftpSafeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.txBuf.Write(p)
	for c.txBuf.Len() >= 5 {
		hdr := c.txBuf.Bytes()
		pktLen := binary.BigEndian.Uint32(hdr[:4])
		if pktLen == 0 || pktLen > maxSFTPPacketSize {
			c.txBuf.Reset()
			break
		}
		totalLen := int(pktLen) + 4
		if c.txBuf.Len() < totalLen {
			break
		}
		frame := c.txBuf.Next(totalLen)
		pktType := frame[4]
		if len(frame) >= 9 {
			sid := binary.BigEndian.Uint32(frame[5:9])
			switch pktType {
			case sshFxpOpendir:
				c.readdirEntries = 0
			case sshFxpReaddir:
				c.readdirSIDs[sid] = true
			case sshFxpClose:
				c.readdirEntries = 0
			}
		}
	}
	c.mu.Unlock()
	return c.wr.Write(p)
}

func (c *sftpSafeConn) Close() error {
	return c.wr.Close()
}

func (c *sftpSafeConn) Read(p []byte) (int, error) {
	for c.buf.Len() == 0 {
		if c.err != nil {
			return 0, c.err
		}
		if err := c.readAndValidatePacket(); err != nil {
			c.err = err
			_ = c.wr.Close()
			return 0, err
		}
	}
	return c.buf.Read(p)
}

func (c *sftpSafeConn) readAndValidatePacket() error {
	var hdr [5]byte
	if _, err := io.ReadFull(c.rd, hdr[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(hdr[:4])
	if length < 1 || length > maxSFTPPacketSize {
		return fmt.Errorf("%w: invalid packet length %d", ErrMalformedSFTPPacket, length)
	}
	pktType := hdr[4]
	payload := make([]byte, length-1)
	if _, err := io.ReadFull(c.rd, payload); err != nil {
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}

	if err := c.validatePacket(pktType, payload); err != nil {
		return err
	}

	c.buf.Write(hdr[:])
	c.buf.Write(payload)
	return nil
}

func (c *sftpSafeConn) isReaddirSID(sid uint32, remove bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ok := c.readdirSIDs[sid]
	if ok && remove {
		delete(c.readdirSIDs, sid)
	}
	return ok
}

func (c *sftpSafeConn) addReaddirEntries(n int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readdirEntries += n
	if c.readdirEntries > MaxSFTPReadDirEntries {
		return ErrTooManySFTPEntries
	}
	return nil
}

func (c *sftpSafeConn) validatePacket(pktType byte, data []byte) error {
	if len(data) < 4 {
		return nil
	}
	sid := binary.BigEndian.Uint32(data[:4])
	rest := data[4:]

	switch pktType {
	case sshFxpStatus:
		c.isReaddirSID(sid, true)
		return nil

	case sshFxpData:
		if !EnableSFTPResourceGuard {
			return nil
		}
		d, _, err := readStringSafe(rest)
		if err != nil {
			return nil
		}
		if len(d) == 0 {
			return ErrZeroLengthSFTPData
		}
		return nil

	case sshFxpName:
		isReaddir := c.isReaddirSID(sid, true)
		if !isReaddir || (!EnableSFTPPathAndRemoveGuard && !EnableSFTPResourceGuard) {
			return nil
		}
		if len(rest) < 4 {
			return nil
		}
		count := binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
		if EnableSFTPResourceGuard && count == 0 {
			return fmt.Errorf("%w: zero count in SSH_FXP_NAME", ErrMalformedSFTPPacket)
		}
		// Each entry requires at least 12 bytes (filename len + longname len + attr flags).
		if count > uint32(len(rest)/12) {
			return nil
		}
		if EnableSFTPResourceGuard {
			if err := c.addReaddirEntries(int(count)); err != nil {
				return err
			}
		}
		if !EnableSFTPPathAndRemoveGuard {
			return nil
		}
		for i := uint32(0); i < count; i++ {
			filename, r, err := readStringSafe(rest)
			if err != nil {
				return nil
			}
			if err := validateReaddirFilename(filename); err != nil {
				return err
			}
			_, r, err = readStringSafe(r)
			if err != nil {
				return nil
			}
			r, err = skipAttrsSafe(r)
			if err != nil {
				return nil
			}
			rest = r
		}
		return nil

	default:
		return nil
	}
}

func validateReaddirFilename(filename string) error {
	if filename == "." || filename == ".." {
		return nil
	}
	if filename == "" || strings.ContainsAny(filename, "/\x00") {
		return fmt.Errorf("%w: %q", ErrInvalidSFTPFilename, filename)
	}
	base := path.Base(filename)
	if base == "." || base == ".." || base == "/" || base == "" {
		return fmt.Errorf("%w: %q", ErrInvalidSFTPFilename, filename)
	}
	return nil
}

func readStringSafe(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, fmt.Errorf("%w: truncated string length", ErrMalformedSFTPPacket)
	}
	n := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if int64(n) > int64(len(b)) {
		return "", nil, fmt.Errorf("%w: string length %d exceeds remaining %d bytes", ErrMalformedSFTPPacket, n, len(b))
	}
	return string(b[:n]), b[n:], nil
}

func skipAttrsSafe(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("%w: truncated attrs flags", ErrMalformedSFTPPacket)
	}
	flags := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if flags&sshFileXferAttrSize != 0 {
		if len(b) < 8 {
			return nil, fmt.Errorf("%w: truncated attr size", ErrMalformedSFTPPacket)
		}
		b = b[8:]
	}
	if flags&sshFileXferAttrUIDGID != 0 {
		if len(b) < 8 {
			return nil, fmt.Errorf("%w: truncated attr uid/gid", ErrMalformedSFTPPacket)
		}
		b = b[8:]
	}
	if flags&sshFileXferAttrPermissions != 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("%w: truncated attr permissions", ErrMalformedSFTPPacket)
		}
		b = b[4:]
	}
	if flags&sshFileXferAttrACmodTime != 0 {
		if len(b) < 8 {
			return nil, fmt.Errorf("%w: truncated attr acmodtime", ErrMalformedSFTPPacket)
		}
		b = b[8:]
	}
	if flags&sshFileXferAttrExtended != 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("%w: truncated attr extended count", ErrMalformedSFTPPacket)
		}
		count := binary.BigEndian.Uint32(b[:4])
		b = b[4:]
		if count > uint32(len(b)/8) {
			return nil, fmt.Errorf("%w: attr extended count %d exceeds payload", ErrMalformedSFTPPacket, count)
		}
		for i := uint32(0); i < count; i++ {
			var err error
			if _, b, err = readStringSafe(b); err != nil {
				return nil, err
			}
			if _, b, err = readStringSafe(b); err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}
