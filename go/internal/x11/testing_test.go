//go:build x11

package x11

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

var byteOrder = binary.LittleEndian

type testLogger struct {
	t *testing.T
	b bytes.Buffer
}

func (l *testLogger) Errorf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	if l.t != nil {
		l.t.Log(s)
	}
	l.b.WriteString(s)
	l.b.WriteRune('\n')
}
func (l *testLogger) Infof(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	if l.t != nil {
		l.t.Log(s)
	}
	l.b.WriteString(s)
	l.b.WriteRune('\n')
}
func (l *testLogger) Printf(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	if l.t != nil {
		l.t.Log(s)
	}
	l.b.WriteString(s)
	l.b.WriteRune('\n')
}
func (l *testLogger) String() string {
	return l.b.String()
}

type testConn struct {
	r io.Reader
	w io.Writer
}

func (c *testConn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *testConn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *testConn) Close() error {
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return nil
}

func (c *testConn) RemoteAddr() net.Addr {
	return nil
}

func (c *testConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *testConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *testConn) SetWriteDeadline(t time.Time) error {
	return nil
}
