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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/c2FmZQ/sshterm/internal/app"
)

func TestPresetPersist(t *testing.T) {
	for _, tc := range []bool{true, false} {
		t.Run(fmt.Sprintf("Persist=%v", tc), func(t *testing.T) {
			cfg := *appConfig
			cfg.Persist = &tc
			cfg.Term.Call("writeln", t.Name())
			a, err := app.New(&cfg)
			if err != nil {
				t.Fatalf("app.New: %v", err)
			}
			result := make(chan error)
			go func() {
				result <- a.Run()
			}()
			t.Cleanup(a.Stop)

			var expect string
			if tc {
				expect = "The database is persisted to local storage."
			} else {
				expect = "The database is NOT persisted to local storage."
			}
			script(t, []line{
				{Type: "db persist on\n", Expect: expect},
				{Type: "db persist off\n", Expect: expect},
				{Type: "db persist toggle\n", Expect: expect},
				{Type: "db persist\n", Expect: expect},
				{Expect: prompt},
				{Type: "exit\n"},
			})
			if err := <-result; err != nil {
				t.Fatalf("Run(): %v", err)
			}
		})
	}
}

func TestPresetAuthorities(t *testing.T) {
	cfg := *appConfig
	cfg.Term.Call("writeln", t.Name())

	resp, err := http.Get("/cakey")
	if err != nil {
		t.Fatalf("/cakey: %v", err)
	}
	defer resp.Body.Close()

	caKey, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(caKey)
	if err != nil {
		t.Fatalf("ssh.ParseAuthorizedKey: %v", err)
	}
	fp := ssh.FingerprintSHA256(key)

	if err := json.Unmarshal(
		[]byte(`{
			"certificateAuthorities": [{
				"name": "testca",
				"publicKey": "`+strings.TrimSpace(string(caKey))+`",
				"hostnames": ["*.example.com"]}
			],
			"endpoints": [{
				"name": "myserver.example.com",
				"url": "./websocket?cert=true"
			}]
		}`),
		&cfg,
	); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	a, err := app.New(&cfg)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	script(t, []line{
		{Type: "db persist on\n", Expect: prompt},
		{Type: "ca list\n", Expect: `testca ` + regexp.QuoteMeta(fp) + ` \*\.example\.com`},
		{Type: "ssh testuser@myserver.example.com foo\n", Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "ca remove-hostname testca *.example.com\n", Expect: prompt},
		{Type: "ca add-hostname testca foobar\n", Expect: prompt},
		{Type: "ca list\n", Expect: `testca ` + regexp.QuoteMeta(fp) + ` foobar`},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}

	if a, err = app.New(&cfg); err != nil {
		t.Fatalf("app.New: %v", err)
	}
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	script(t, []line{
		{Type: "ca list\n", Expect: `testca ` + regexp.QuoteMeta(fp) + ` \*\.example\.com`},
		{Type: "ssh testuser@myserver.example.com foo\n", Expect: "Password: "},
		{Type: "password\n", Expect: "exec: foo"},
		{Wait: time.Second, Type: "\n\n"},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}

func TestPresetKeys(t *testing.T) {
	cfg := *appConfig
	cfg.Term.Call("writeln", t.Name())

	resp, err := http.Get("/cakey")
	if err != nil {
		t.Fatalf("/cakey: %v", err)
	}
	defer resp.Body.Close()

	caKey, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}

	if err := json.Unmarshal(
		[]byte(`{
			"certificateAuthorities": [{
				"name": "testca",
				"publicKey": "`+strings.TrimSpace(string(caKey))+`",
				"hostnames": ["*.example.com"]}
			],
			"endpoints": [{
				"name": "myserver.example.com",
				"url": "./websocket?cert=true"
			}],
			"generateKeys": [{
				"name": "foo",
				"identityProvider": "./cert",
				"addToAgent": true
			}]
		}`),
		&cfg,
	); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	a, err := app.New(&cfg)
	if err != nil {
		t.Fatalf("app.New: %v", err)
	}
	result := make(chan error)
	go func() {
		result <- a.Run()
	}()
	t.Cleanup(a.Stop)

	script(t, []line{
		{Type: "ssh testuser@myserver.example.com foo\n", Expect: `(?s)Host certificate for myserver.example.com is trusted.\r\nexec: foo`},
		{Wait: time.Second, Type: "\n\n"},

		{Type: "keys show foo\n", Expect: prompt},
		{Type: "exit\n"},
	})
	if err := <-result; err != nil {
		t.Fatalf("Run(): %v", err)
	}
}
