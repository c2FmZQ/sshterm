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

package zmodem

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

// pipeBuf is an in-memory, unbounded, unidirectional byte stream.
type pipeBuf struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    bytes.Buffer
	closed bool
}

func newPipeBuf() *pipeBuf {
	p := &pipeBuf{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

func (p *pipeBuf) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.buf.Len() == 0 && !p.closed {
		p.cond.Wait()
	}
	if p.buf.Len() > 0 {
		return p.buf.Read(b)
	}
	return 0, io.EOF
}

func (p *pipeBuf) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := p.buf.Write(b)
	p.cond.Broadcast()
	return n, err
}

func (p *pipeBuf) Close() error {
	p.mu.Lock()
	p.closed = true
	p.cond.Broadcast()
	p.mu.Unlock()
	return nil
}

type rwPair struct {
	io.Reader
	io.Writer
}

// newConnPair returns two connected io.ReadWriters and a function that closes
// both directions.
func newConnPair() (a, b io.ReadWriter, closeFn func()) {
	aToB, bToA := newPipeBuf(), newPipeBuf()
	return rwPair{bToA, aToB}, rwPair{aToB, bToA}, func() {
		aToB.Close()
		bToA.Close()
	}
}

// runPeer runs fn against one end of a connection and fails the test if it does
// not finish promptly.
func runPeer(t *testing.T, name string, fn func() error) <-chan error {
	t.Helper()
	ch := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- fmt.Errorf("%s panicked: %v", name, r)
			}
		}()
		ch <- fn()
	}()
	return ch
}

func waitPeers(t *testing.T, chans map[string]<-chan error) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for len(chans) > 0 {
		for name, ch := range chans {
			select {
			case err := <-ch:
				if err != nil {
					t.Errorf("%s: %v", name, err)
				}
				delete(chans, name)
			case <-deadline:
				t.Fatalf("timed out waiting for %v", chans)
			default:
			}
		}
		time.Sleep(time.Millisecond)
	}
}

// expectHeader reads the next header and checks its type.
func expectHeader(zr *reader, want uint8) (header, error) {
	h, err := zr.readHeader()
	if err != nil {
		return h, err
	}
	if h.Type != want {
		return h, fmt.Errorf("expected header %d, got %d", want, h.Type)
	}
	return h, nil
}

// TestReceive_ZCRCW checks that a subpacket ending with ZCRCW terminates the
// frame but not the file: the sender waits for a ZACK and then opens another
// ZDATA frame.
func TestReceive_ZCRCW(t *testing.T) {
	client, server, closeFn := newConnPair()
	defer closeFn()

	want := []byte("hello world")

	var got []byte
	recvCh := runPeer(t, "receiver", func() error {
		return receive(client, func(name string, size int64, rc io.Reader) error {
			if name != "split.txt" {
				return fmt.Errorf("unexpected name %q", name)
			}
			b, err := io.ReadAll(rc)
			got = b
			return err
		})
	})

	sendCh := runPeer(t, "sender", func() error {
		zr := newReader(server)
		if _, err := expectHeader(zr, zRINIT); err != nil {
			return err
		}
		if err := writeBinaryHeader(server, header{Type: zFILE}); err != nil {
			return err
		}
		info := fmt.Sprintf("split.txt\x00%d 0 0 0 0 0", len(want))
		if err := writeDataBlock(server, []byte(info), zCRCW, false); err != nil {
			return err
		}
		if _, err := expectHeader(zr, zRPOS); err != nil {
			return err
		}

		// First frame, terminated with ZCRCW.
		if err := writeBinaryHeader(server, header{Type: zDATA}); err != nil {
			return err
		}
		if err := writeDataBlock(server, want[:6], zCRCW, false); err != nil {
			return err
		}
		if _, err := expectHeader(zr, zACK); err != nil {
			return err
		}

		// Second frame with the rest of the file.
		if err := writeBinaryHeader(server, header{Type: zDATA}); err != nil {
			return err
		}
		if err := writeDataBlock(server, want[6:], zCRCE, false); err != nil {
			return err
		}
		if err := writeHexHeader(server, header{Type: zEOF}); err != nil {
			return err
		}
		if _, err := expectHeader(zr, zRINIT); err != nil {
			return err
		}

		if err := writeHexHeader(server, header{Type: zFIN}); err != nil {
			return err
		}
		_, err := expectHeader(zr, zFIN)
		return err
	})

	waitPeers(t, map[string]<-chan error{"receiver": recvCh, "sender": sendCh})

	if !bytes.Equal(got, want) {
		t.Errorf("Data mismatch: expected %q, got %q", want, got)
	}
}

// TestReceive_EmptyFileThenFile checks that a ZEOF arriving in place of ZDATA
// (an empty file) does not abort the rest of the batch.
func TestReceive_EmptyFileThenFile(t *testing.T) {
	client, server, closeFn := newConnPair()
	defer closeFn()

	second := []byte("second file contents")

	type recvd struct {
		name string
		data []byte
	}
	var files []recvd

	recvCh := runPeer(t, "receiver", func() error {
		return receive(client, func(name string, size int64, rc io.Reader) error {
			b, err := io.ReadAll(rc)
			if err != nil {
				return err
			}
			files = append(files, recvd{name, b})
			return nil
		})
	})

	sendCh := runPeer(t, "sender", func() error {
		zr := newReader(server)
		if _, err := expectHeader(zr, zRINIT); err != nil {
			return err
		}

		// First file: empty, so ZEOF follows ZRPOS directly.
		if err := writeBinaryHeader(server, header{Type: zFILE}); err != nil {
			return err
		}
		if err := writeDataBlock(server, []byte("empty.txt\x000 0 0 0 1 0"), zCRCW, false); err != nil {
			return err
		}
		if _, err := expectHeader(zr, zRPOS); err != nil {
			return err
		}
		if err := writeHexHeader(server, header{Type: zEOF}); err != nil {
			return err
		}
		if _, err := expectHeader(zr, zRINIT); err != nil {
			return err
		}

		// Second file, with data.
		if err := writeBinaryHeader(server, header{Type: zFILE}); err != nil {
			return err
		}
		info := fmt.Sprintf("second.txt\x00%d 0 0 0 0 0", len(second))
		if err := writeDataBlock(server, []byte(info), zCRCW, false); err != nil {
			return err
		}
		if _, err := expectHeader(zr, zRPOS); err != nil {
			return err
		}
		if err := writeBinaryHeader(server, header{Type: zDATA}); err != nil {
			return err
		}
		if err := writeDataBlock(server, second, zCRCE, false); err != nil {
			return err
		}
		if err := writeHexHeader(server, header{Type: zEOF}); err != nil {
			return err
		}
		if _, err := expectHeader(zr, zRINIT); err != nil {
			return err
		}

		if err := writeHexHeader(server, header{Type: zFIN}); err != nil {
			return err
		}
		_, err := expectHeader(zr, zFIN)
		return err
	})

	waitPeers(t, map[string]<-chan error{"receiver": recvCh, "sender": sendCh})

	if len(files) != 2 {
		t.Fatalf("Expected 2 files, got %d: %v", len(files), files)
	}
	if files[0].name != "empty.txt" || len(files[0].data) != 0 {
		t.Errorf("First file: expected empty.txt with no data, got %q with %d bytes", files[0].name, len(files[0].data))
	}
	if files[1].name != "second.txt" || !bytes.Equal(files[1].data, second) {
		t.Errorf("Second file: expected second.txt %q, got %q %q", second, files[1].name, files[1].data)
	}
}

// TestSend_UnexpectedZRPOS checks that a ZRPOS arriving outside the
// ZFILE -> ZRPOS window is ignored instead of panicking on a nil file.
func TestSend_UnexpectedZRPOS(t *testing.T) {
	client, server, closeFn := newConnPair()
	defer closeFn()

	data := []byte("payload")
	files := []*File{{Name: "f.txt", Size: int64(len(data)), R: io.NopCloser(bytes.NewReader(data))}}

	sendCh := runPeer(t, "sender", func() error {
		return send(client, files, nil)
	})

	recvCh := runPeer(t, "receiver", func() error {
		zr := newReader(server)
		if err := writeHexHeader(server, header{Type: zRINIT}); err != nil {
			return err
		}
		if _, err := expectHeader(zr, zFILE); err != nil {
			return err
		}
		if _, _, err := zr.readDataBlock(false); err != nil {
			return err
		}
		if err := writeHexHeader(server, header{Type: zRPOS}); err != nil {
			return err
		}
		if _, err := expectHeader(zr, zDATA); err != nil {
			return err
		}
		for {
			_, endType, err := zr.readDataBlock(false)
			if err != nil {
				return err
			}
			if endType == zCRCE {
				break
			}
		}
		if _, err := expectHeader(zr, zEOF); err != nil {
			return err
		}

		// A stray retransmission request after ZEOF: there is no current file.
		if err := writeHexHeader(server, header{Type: zRPOS}); err != nil {
			return err
		}
		if err := writeHexHeader(server, header{Type: zRINIT}); err != nil {
			return err
		}
		if _, err := expectHeader(zr, zFIN); err != nil {
			return err
		}
		return writeHexHeader(server, header{Type: zFIN})
	})

	waitPeers(t, map[string]<-chan error{"sender": sendCh, "receiver": recvCh})
}

// chunkReader hands out data in fixed-size chunks and, like
// jsutil.StreamReader, never returns a non-zero count together with io.EOF.
type chunkReader struct {
	data  []byte
	chunk int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(min(len(p), r.chunk), len(r.data))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func (r *chunkReader) Close() error { return nil }

// TestSendReceive_SizeMismatch checks that the last subpacket is chosen from
// the actual end of the stream and not from the declared file size, which the
// browser's File.size may not match.
func TestSendReceive_SizeMismatch(t *testing.T) {
	data := []byte("the quick brown fox jumps over the lazy dog")

	for _, tc := range []struct {
		name    string
		declare int64
	}{
		{"DeclaredLarger", int64(len(data)) * 3},
		{"DeclaredSmaller", 5},
		{"DeclaredExact", int64(len(data))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server, closeFn := newConnPair()
			defer closeFn()

			files := []*File{{
				Name: "f.bin",
				Size: tc.declare,
				R:    &chunkReader{data: append([]byte(nil), data...), chunk: 7},
			}}

			sendCh := runPeer(t, "sender", func() error {
				return send(client, files, nil)
			})

			var got []byte
			recvCh := runPeer(t, "receiver", func() error {
				return receive(server, func(name string, size int64, rc io.Reader) error {
					b, err := io.ReadAll(rc)
					got = b
					return err
				})
			})

			waitPeers(t, map[string]<-chan error{"sender": sendCh, "receiver": recvCh})

			if !bytes.Equal(got, data) {
				t.Errorf("Data mismatch: expected %q, got %q", data, got)
			}
		})
	}
}
