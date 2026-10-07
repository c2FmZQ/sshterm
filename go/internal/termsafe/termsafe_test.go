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

package termsafe

import (
	"testing"
)

func TestText(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"hello", "hello"},
		{"line 1\r\nline 2\n\tindented", "line 1\nline 2\n\tindented"},
		{"\x1b[2J\x1b]0;title\a", "#[2J#]0;title#"},
		{"csi\u009b31m", "csi#31m"},
		{"del\x7f", "del#"},
		{"invoice\u202efdp.exe", "invoice#fdp.exe"},
		{"héllo €", "héllo €"},
	} {
		if got := Text(tc.in); got != tc.want {
			t.Errorf("Text(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestName(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"hello.txt", "hello.txt"},
		{"a\r\nb\tc", "a??b?c"},
		{"\x1b[2Jevil.exe", "?[2Jevil.exe"},
		{"invoice\u202efdp.exe", "invoice?fdp.exe"},
		{"x\u2066y\u2069", "x?y?"},
		{"héllo-€.txt", "héllo-€.txt"},
	} {
		if got := Name(tc.in); got != tc.want {
			t.Errorf("Name(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
