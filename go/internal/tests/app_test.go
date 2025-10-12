// MIT License
//
// Copyright (c) 2024 TTBT Enterprises LLC
// Copyright (c) 2024 Robin Thellend <rthellend@rthellend.com>
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

//go:build wasm

package tests

import (
	"bytes"
	"io"
	"net/http"
	"syscall/js"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/internal/app"
)

const prompt = "sshterm> "

type line struct {
	Type   string
	Expect string
	Reset  bool
	Do     func([]string)
	Wait   time.Duration
}

func script(t *testing.T, lines []line) {
	t.Helper()
	for n, line := range lines {
		if line.Reset {
			t.Logf("[%2d] Reset", n)
			terminalIO.Reset()
		}
		if line.Wait != 0 {
			t.Logf("[%2d] Wait: %s", n, line.Wait)
			time.Sleep(line.Wait)
		}
		if line.Type != "" {
			t.Logf("[%2d] Type: %q", n, line.Type)
			terminalIO.Type(line.Type)
		}
		if line.Expect != "" {
			t.Logf("[%2d] Expect: %q", n, line.Expect)
			m := terminalIO.Expect(t, line.Expect)
			if line.Do != nil {
				line.Do(m)
			}
		}
	}
}

func TestHelp(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	script(t, []line{
		{Expect: prompt},
		{Type: "help\n", Expect: "(?s)agent.*clear.*db.*keys.*reload.*sftp.*ssh.*> "},
		{Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestEndpoint(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep list\n", Expect: "<none>"},
		{Type: "ep add test foobar\n", Expect: prompt},
		{Type: "ep list\n", Expect: "test.*foobar.*n/a"},
		{Type: "ep delete test\n", Expect: prompt},
		{Type: "ep list\n", Expect: "<none>"},
		{Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestKeys(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	downloadCh := fileDownloader.wait()

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "keys list\n", Expect: "<none>"},
		{Type: "keys generate test\n", Expect: "Enter a passphrase"},
		{Type: "foobar\n", Expect: "Re-enter the same passphrase"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "keys list\n", Expect: "ssh-ed25519 .* test"},
		{Expect: prompt},
		{Type: "keys change-pass test\n", Expect: "Enter the passphrase"},
		{Type: "foobar\n", Expect: "Enter a NEW passphrase"},
		{Type: "blah\n", Expect: "Re-enter the same new passphrase"},
		{Type: "blah\n", Expect: prompt},
		{Type: "keys export --private test\n", Expect: `Continue\?`},
		{Type: "Y\n"},
	})
	file := <-downloadCh
	if got, want := file.Name, "test.key"; got != want {
		t.Errorf("filename = %q, want %q", got, want)
	}

	fileUploader.enqueue(file.Name, file.Type, int64(len(file.Content)), file.Content)

	script(t, []line{
		{Type: "keys import samekey\n", Expect: "Enter the passphrase for samekey"},
		{Type: "blah\n", Expect: prompt},
		{Type: "keys list\n", Expect: "(?s)ssh-ed25519 .* samekey\r\nssh-ed25519 .* test\r\n"},
		{Expect: prompt},
		{Type: "keys delete test\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "keys list\n", Expect: "ssh-ed25519 .* samekey\r\n"},
		{Expect: prompt},
		{Type: "keys delete samekey\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "keys list\n", Expect: "<none>"},
		{Expect: prompt},
		{Type: "exit\n"},
	})

	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestWebAuthnKeys(t *testing.T) {
	if js.Global().Get("navigator").Get("webdriver").Truthy() {
		t.Skip("TestWebAuthnKeys skipped with chromedp")
	}
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "keys list\n", Expect: "<none>"},
		{Type: "keys generate -t ecdsa-sk test\n", Expect: "Enter a passphrase"},
		{Type: "foobar\n", Expect: "Re-enter the same passphrase"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "keys list\n", Expect: `webauthn-sk-ecdsa-sha2-nistp256@openssh\.com .* test`},
		{Expect: prompt},
		{Type: "exit\n"},
	})

	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestDB(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	downloadCh := fileDownloader.wait()

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep add test websocket\n", Expect: prompt},
		{Type: "ep list\n", Expect: "test .* websocket"},
		{Type: "keys generate test\n", Expect: "Enter a passphrase"},
		{Type: "foobar\n", Expect: "Re-enter the same passphrase"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "keys list\n", Expect: "ssh-ed25519 .* test"},
		{Expect: prompt},
		{Type: "db backup\n", Expect: "Enter a passphrase for the backup:"},
		{Type: "foobar\n", Expect: "Enter the same passphrase:"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep list\n", Expect: "<none>"},
		{Type: "keys list\n", Expect: "<none>"},
		{Expect: prompt},
	})
	file := <-downloadCh

	fileUploader.enqueue(file.Name, file.Type, int64(len(file.Content)), file.Content)

	script(t, []line{
		{Type: "db restore\n", Expect: "Enter the passphrase for the backup:"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "ep list\n", Expect: "test .* websocket"},
		{Type: "keys list\n", Expect: "ssh-ed25519 .* test"},
		{Expect: prompt},
		{Type: "exit\n"},
	})

	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestSSH(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	txt := []byte("Hello World!")
	fileUploader.enqueue("hello.txt", "text/plain", int64(len(txt)), txt)

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep add test-server websocket\n", Expect: prompt},
		{Type: "ssh testuser@test-server\n", Expect: `(?s)Host key for test-server.*Choice>`},
		{Type: "3\n", Expect: "Password: "},
		{Type: "password\n", Expect: "remote> "},
		{Type: "exit\n", Expect: prompt},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "keys generate test\n", Expect: "Enter a passphrase"},
		{Type: "foobar\n", Expect: "Re-enter the same passphrase"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "keys list\n", Expect: "ssh-ed25519 .* test\r\n", Do: func(m []string) {
			t.Logf("Add key: %s", m[0])
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m[0]))
			if err != nil {
				t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
			}
			if _, err := http.Post("/addkey", "text/pem", bytes.NewReader(pub.Marshal())); err != nil {
				t.Fatalf("http.Post: %v", err)
			}
		}},
		{Type: "ssh -i test testuser@test-server\n", Expect: "Enter the passphrase for test:"},
		{Type: "foobar\n", Expect: "remote> "},
		{Type: "exit\n", Expect: prompt},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "agent add test\n", Expect: "Enter the passphrase for test:"},
		{Type: "foobar\n", Expect: prompt},
		{Type: "ssh testuser@test-server\n", Expect: "remote> "},
		{Type: "exit\n", Expect: prompt},
		{Wait: time.Second, Type: "\n\n"},
		{Type: "ssh testuser@test-server foo bar\n", Expect: "exec: foo bar"},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "sftp testuser@test-server\n", Expect: "sftp> "},
		{Type: "put .\n", Expect: "100%"},
		{Type: "exit\n"},

		{Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestDownload(t *testing.T) {
	if js.Global().Get("navigator").Get("serviceWorker").IsUndefined() {
		t.Skip("Service Worker not available")
	}
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	txt := []byte("Hello World!")
	fileUploader.enqueue("hello-again.txt", "text/plain", int64(len(txt)), txt)

	downloadCh := fileDownloader.wait()

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep add test-server websocket\n", Expect: prompt},
		{Type: "sftp testuser@test-server\n", Expect: `(?s)Host key for test-server.*Choice>`},
		{Type: "3\n", Expect: "Password: "},
		{Type: "password\n", Expect: "sftp> "},
		{Type: "put\n", Expect: "100%"},

		{Type: "get hello-again.txt\n", Expect: "100%"},
		{Expect: "sftp> "},
		{Type: "exit\n"},

		{Expect: prompt},
		{Type: "exit\n"},
	})
	file := <-downloadCh
	if got, want := file.Name, "hello-again.txt"; got != want {
		t.Errorf("filename = %q, want %q", got, want)
	}
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestHostCerts(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	resp, err := http.Get("/cakey")
	if err != nil {
		t.Fatalf("/cakey: %v", err)
	}
	defer resp.Body.Close()

	caKey, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	t.Logf("ca key: %s", caKey)

	fileUploader.enqueue("testca.pub", "text/plain", int64(len(caKey)), caKey)

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ca import testca test-server\n", Expect: prompt},
		{Type: "ca list\n", Expect: prompt},
		{Type: "ep add test-server websocket?cert=true\n", Expect: prompt},
		{Type: "ssh testuser@test-server foo\n", Expect: `Host certificate for test-server is trusted`},
		{Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "ep add fooserver websocket?cert=true\n", Expect: prompt},
		{Type: "ssh testuser@fooserver foo\n", Expect: `(?s)Host certificate for fooserver is NOT trusted.*Choice>`},
		{Type: "\n", Expect: prompt},

		{Type: "ssh testuser@fooserver foo\n", Expect: `(?s)Host certificate for fooserver is NOT trusted.*Choice>`},
		{Type: "2\n", Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "ssh testuser@fooserver foo\n", Expect: `(?s)Host certificate for fooserver is NOT trusted.*Choice>`},
		{Type: "3\n", Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "ssh testuser@fooserver foo\n", Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "ca list\n", Expect: "fooserver"},

		{Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestJumpHosts(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	resp, err := http.Get("/cakey")
	if err != nil {
		t.Fatalf("/cakey: %v", err)
	}
	defer resp.Body.Close()

	caKey, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	t.Logf("ca key: %s", caKey)

	fileUploader.enqueue("testca.pub", "text/plain", int64(len(caKey)), caKey)

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ca import testca foo bar baz\n", Expect: prompt},
		{Type: "ep add foo websocket?cert=true\n", Expect: prompt},
		{Type: "ssh -J foo,bar testuser@baz hello\n"},
		{Expect: `(?s)Host certificate for foo is trusted.*Password: `},
		{Type: "password\n"},
		{Expect: `(?s)Host certificate for bar is trusted.*Password: `},
		{Type: "password\n"},
		{Expect: `(?s)Host certificate for baz is trusted.*Password: `},
		{Type: "password\n", Expect: "exec: hello"},
		{Wait: time.Second, Type: "\n\n"},

		{Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestSFTP(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	txt := []byte("Hello World!")
	fileUploader.enqueue("hello.txt", "text/plain", int64(len(txt)), txt)

	script(t, []line{
		{Expect: prompt},
		{Type: "db wipe\n", Expect: `Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep add test-server websocket\n", Expect: prompt},
		{Type: "sftp testuser@test-server\n", Expect: `(?s)Host key for test-server.*Choice>`},
		{Type: "3\n", Expect: "Password: "},
		{Type: "password\n", Expect: "sftp> "},
		{Type: "mkdir test\n", Expect: "sftp> "},
		{Type: "put test\n", Expect: "100%"},
		{Type: "cd test\n", Expect: "sftp> "},
		{Type: "ls -l\n", Expect: "(?s) hello.txt.*sftp> "},
		{Type: "mv hello.txt hello-world.txt\n", Expect: "sftp> "},
		{Type: "ls -l\n", Expect: "(?s) hello-world.txt.*sftp> "},
		{Type: "cd ..\n", Expect: "sftp> "},
		{Type: "ls -l test\n", Expect: "(?s) hello-world.txt.*sftp> "},
		{Type: "rm test/*\n", Expect: "sftp> "},
		{Type: "rmdir test\n", Expect: "sftp> "},
		{Type: "ls -l test\n", Expect: `(?s)"test": file does not exist.*sftp> `},
		{Type: "exit\n"},

		{Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}
