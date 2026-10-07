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
	"encoding/binary"
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
		{Type: "db backup --iter=1000\n", Expect: `(?s)invalid iter value.*sshterm> `},
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
	if len(file.Content) < 40 {
		t.Fatalf("backup file too short: %d", len(file.Content))
	}
	if got, want := binary.BigEndian.Uint32(file.Content[12:16]), uint32(600000); got != want {
		t.Errorf("backup iterations = %d, want %d", got, want)
	}

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
		// Invalid endpoints.
		{Type: "ep add bad-url ws://[invalid\n", Expect: prompt},
		{Type: "ssh testuser@bad-url\n", Expect: `(?s)websocket: .*sshterm> `},
		{Type: "ep add text-message websocket?text=true\n", Expect: prompt},
		{Type: "ssh testuser@text-message\n", Expect: `(?s)websocket: unexpected message type.*sshterm> `},

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

		// The forwarded agent can only list keys and sign.
		{Type: "ssh -A testuser@test-server agent-test\n", Expect: `\[agent\] test-server requested a signature with key "test"`},
		{Expect: `(?s)agent-test: sign: ok.*agent-test: lock: agent: failure.*agent-test: removeall: agent: failure`},
		{Wait: time.Second, Type: "\n\n"},
		{Type: "agent list\n", Expect: `(?s)test .*sshterm> `},

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
	})
	file := <-downloadCh
	if got, want := file.Name, "hello-again.txt"; got != want {
		t.Errorf("filename = %q, want %q", got, want)
	}

	// Empty file.
	fileUploader.enqueue("empty.txt", "text/plain", 0, nil)
	downloadCh = fileDownloader.wait()
	script(t, []line{
		{Type: "put\n", Expect: "100%"},
		{Type: "get empty.txt\n", Expect: "100%"},
		{Expect: "sftp> "},
	})
	file = <-downloadCh
	if got, want := file.Name, "empty.txt"; got != want {
		t.Errorf("filename = %q, want %q", got, want)
	}
	if len(file.Content) != 0 {
		t.Errorf("content = %q, want empty", file.Content)
	}

	// Non-ASCII file name.
	txt = []byte("Hello €!")
	fileUploader.enqueue("héllo-€.txt", "text/plain", int64(len(txt)), txt)
	downloadCh = fileDownloader.wait()
	script(t, []line{
		{Type: "put\n", Expect: "100%"},
		{Type: "get héllo-€.txt\n", Expect: "100%"},
		{Expect: "sftp> "},
	})
	file = <-downloadCh
	if got, want := file.Name, "héllo-€.txt"; got != want {
		t.Errorf("filename = %q, want %q", got, want)
	}
	if got, want := string(file.Content), string(txt); got != want {
		t.Errorf("content = %q, want %q", got, want)
	}

	// The server reports a size of 0 for files in /proc, even though they
	// have content.
	downloadCh = fileDownloader.wait()
	script(t, []line{
		{Type: "get /proc/self/status\n", Expect: "100%"},
		{Expect: "sftp> "},
		{Type: "exit\n"},

		{Expect: prompt},
		{Type: "exit\n"},
	})
	file = <-downloadCh
	if got, want := file.Name, "status"; got != want {
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

		// The certificate's principals don't include fooserver.
		{Type: "ep add fooserver websocket?cert=true\n", Expect: prompt},
		{Type: "ca add-hostname testca fooserver\n", Expect: prompt},
		{Type: "ssh testuser@fooserver foo\n", Expect: `(?s)Host certificate for fooserver is NOT trusted.*not valid for hostname "fooserver".*Choice>`},
		{Type: "\n", Expect: prompt},

		{Type: "ssh testuser@fooserver foo\n", Expect: `(?s)Host certificate for fooserver is NOT trusted.*Choice>`},
		{Type: "2\n", Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},

		// Use one of the certificate's principals as the endpoint's hostname.
		{Type: "ssh testuser@fooserver foo\n", Expect: `(?s)Host certificate for fooserver is NOT trusted.*` +
			`3- Continue, and set the hostname of endpoint fooserver to test-server\..*` +
			`7- Continue, and set the hostname of endpoint fooserver to baz\..*Choice>`},
		{Type: "3\n", Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},
		{Type: "ep list\n", Expect: `fooserver +websocket\?cert=true +test-server `},
		{Type: "ssh testuser@fooserver foo\n", Expect: `Host certificate for fooserver \(test-server\) is trusted`},
		{Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},

		// Endpoint with a hostname.
		{Type: "ep add --hostname=myserver.example.com alias websocket?cert=true\n", Expect: prompt},
		{Type: "ssh testuser@alias foo\n", Expect: `(?s)Host certificate for alias \(myserver.example.com\) is NOT trusted.*` +
			`not trusted for hostname "myserver.example.com".*3- Continue, and trust this authority.*Choice>`},
		{Type: "3\n", Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},
		{Type: "ssh testuser@alias foo\n", Expect: `Host certificate for alias \(myserver.example.com\) is trusted`},
		{Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},

		// The authority isn't trusted for test-server.
		{Type: "ca remove-hostname testca test-server\n", Expect: prompt},
		{Type: "ssh testuser@test-server foo\n", Expect: `(?s)Host certificate for test-server is NOT trusted.*3- Continue, and trust this authority.*Choice>`},
		{Type: "3\n", Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "ssh testuser@test-server foo\n", Expect: `Host certificate for test-server is trusted`},
		{Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "ca list\n", Expect: "test-server"},

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
	})

	// File names from the server are sanitized.
	fileUploader.enqueue("evil\x1b[31m.txt", "text/plain", int64(len(txt)), txt)
	script(t, []line{
		{Type: "put\n", Expect: "100%"},
		{Type: "ls\n", Expect: `(?s)evil\?\[31m\.txt.*sftp> `},
		{Type: "rm evil*\n", Expect: "sftp> "},
		{Type: "exit\n"},

		{Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}
