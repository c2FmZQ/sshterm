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
	"testing"

	"github.com/c2FmZQ/sshterm/internal/app"
)

func TestTab(t *testing.T) {
	a, err := app.New(appConfig)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	content := []byte("hello world 1 2 3")
	fileUploader.enqueue("foo.txt", "text/plain", int64(len(content)), content)

	script(t, []line{
		{Expect: prompt},
		{Type: "db w\t\n", Expect: `(?s)db wipe.*Continue\?`},
		{Type: "Y\n", Expect: prompt},
		{Type: "ep add test-server ./websocket\n", Expect: prompt},
		{Type: "keys gen\tfoo\n", Expect: "(?s)keys generate foo\r\n.*Enter passphrase"},
		{Type: "\n", Expect: "Re-enter the same passphrase"},
		{Type: "\n", Expect: prompt},
		{Type: "agent add \t\n", Expect: "(?s)agent add foo \r\n.*sshterm> "},
		{Type: "keys generate foobar\n", Expect: "Enter passphrase"},
		{Type: "\n", Expect: "Re-enter the same passphrase"},
		{Type: "\n", Expect: prompt},
		{Type: "agent add foo\tb\t\n", Expect: "(?s)agent add foobar \r\n.*sshterm> "},
		{Type: "sf\t--i\tf\t testuser@\t\n", Expect: "(?s)sftp --identity=foo testuser@test-server \r\n.*Choice> "},
		{Type: "3\n", Expect: "Password: "},
		{Type: "password\n", Expect: "sftp> "},
		{Type: "mkd\t-p a/b foo bar\n", Expect: "(?s)mkdir -p a/b foo bar\r\n.*sftp> "},
		{Type: "pu\tfoo\n", Expect: "(?s)put foo\r\n.*100%.*sftp> "},
		{Type: "ln foo/foo.txt bar/bar.txt\n", Expect: "sftp> "},
		{Type: "ls foo/\tbar/\t\n", Expect: "(?s)ls foo/foo.txt bar/bar.txt \r\n.*foo/foo.txt *bar/bar.txt.*sftp> "},
		{Type: "ls -l foo/\tbar/\t\n", Expect: "(?s)ls -l foo/foo.txt bar/bar.txt \r\n.* foo/foo.txt.* bar/bar.txt.*sftp> "},
		{Type: "mv fo\t\tbar/\ta/b\t\n", Expect: "(?s)mv foo/foo.txt bar/bar.txt a/b/\r\n.*sftp> "},
		{Type: "mv a/b/* foo/../b\t\n", Expect: `(?s)mv a/b/\* foo/../bar/\r\n.*sftp> `},
		{Type: "ls -l foo bar\n", Expect: "(?s)ls -l foo bar\r\nfoo:\r\n\r\nbar:\r\n.* bar.txt.* foo.txt.*sftp> "},
		{Type: "rm -R foo bar a\n", Expect: "sftp> "},

		{Type: "exit\n", Expect: prompt},
		{Type: "exit\n"},
	})

	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}
