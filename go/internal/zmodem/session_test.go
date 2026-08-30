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
	"io"
	"sync"
	"testing"
)

type readerFunc func(p []byte) (n int, err error)

func (rf readerFunc) Read(p []byte) (n int, err error) { return rf(p) }

type writerFunc func(p []byte) (n int, err error)

func (wf writerFunc) Write(p []byte) (n int, err error) { return wf(p) }

func TestSessionSendReceive(t *testing.T) {
	// Create two buffered pipes for bidirectional communication
	type bufferedPipe struct {
		buf    bytes.Buffer
		mu     sync.Mutex
		cond   *sync.Cond
		closed bool
	}
	newPipe := func() *bufferedPipe {
		p := &bufferedPipe{}
		p.cond = sync.NewCond(&p.mu)
		return p
	}

	clientToServer := newPipe()
	serverToClient := newPipe()

	rw := func(r, w *bufferedPipe) struct {
		io.Reader
		io.Writer
	} {
		return struct {
			io.Reader
			io.Writer
		}{
			Reader: readerFunc(func(p []byte) (n int, err error) {
				r.mu.Lock()
				defer r.mu.Unlock()
				for r.buf.Len() == 0 && !r.closed {
					r.cond.Wait()
				}
				if r.buf.Len() > 0 {
					return r.buf.Read(p)
				}
				return 0, io.EOF
			}),
			Writer: writerFunc(func(p []byte) (n int, err error) {
				w.mu.Lock()
				defer w.mu.Unlock()
				if w.closed {
					return 0, io.ErrClosedPipe
				}
				n, err = w.buf.Write(p)
				w.cond.Broadcast()
				return n, err
			}),
		}
	}

	clientConn := rw(serverToClient, clientToServer)
	serverConn := rw(clientToServer, serverToClient)

	originalData := [][]byte{
		[]byte("Hello ZMODEM!"),
		{0x00, 0x18, 0x11, 0x13, 0xFF},
	}
	originalFiles := []*File{
		{Name: "test1.txt", Size: int64(len(originalData[0])), R: io.NopCloser(bytes.NewReader(originalData[0]))},
		{Name: "test2.bin", Size: int64(len(originalData[1])), R: io.NopCloser(bytes.NewReader(originalData[1]))},
	}

	type receivedFile struct {
		Name string
		Data []byte
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var mu sync.Mutex
	var receivedFiles []*receivedFile
	var receiveErr error

	// Run Receiver (Server side in this context)
	go func() {
		defer wg.Done()
		receiveErr = receive(serverConn, func(name string, size int64, rc io.Reader) error {
			data, err := io.ReadAll(rc)
			if err != nil {
				return err
			}
			mu.Lock()
			receivedFiles = append(receivedFiles, &receivedFile{Name: name, Data: data})
			mu.Unlock()
			return nil
		})
		serverToClient.mu.Lock()
		serverToClient.closed = true
		serverToClient.cond.Broadcast()
		serverToClient.mu.Unlock()
	}()

	var sendErr error
	// Run Sender (Client side in this context)
	go func() {
		defer wg.Done()
		sendErr = send(clientConn, originalFiles)
		clientToServer.mu.Lock()
		clientToServer.closed = true
		clientToServer.cond.Broadcast()
		clientToServer.mu.Unlock()
	}()

	wg.Wait()

	if sendErr != nil {
		t.Fatalf("Sender failed: %v", sendErr)
	}
	if receiveErr != nil {
		t.Fatalf("Receiver failed: %v", receiveErr)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(receivedFiles) != len(originalFiles) {
		t.Fatalf("Expected %d files, got %d", len(originalFiles), len(receivedFiles))
	}

	for i, recv := range receivedFiles {
		if originalFiles[i].Name != recv.Name {
			t.Errorf("File %d name mismatch: %q != %q", i, originalFiles[i].Name, recv.Name)
		}
		if !bytes.Equal(originalData[i], recv.Data) {
			t.Errorf("File %d data mismatch: expected %x, got %x", i, originalData[i], recv.Data)
		}
	}
}
