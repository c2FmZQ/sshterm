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

// Package termsafe makes untrusted strings safe to display in a terminal.
package termsafe

import (
	"strings"
)

// Text returns s with all the control characters replaced with '#', except
// for tabs and newlines. Carriage returns are removed. It is meant for
// multi-line text received from a remote server, e.g. banners and error
// messages.
func Text(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n':
			return r
		case r == '\r':
			return -1
		case isUnsafe(r):
			return '#'
		default:
			return r
		}
	}, s)
}

// Name returns s with all the control characters replaced with '?'. It is
// meant for single-line strings received from a remote server, e.g. file
// names.
func Name(s string) string {
	return strings.Map(func(r rune) rune {
		if isUnsafe(r) {
			return '?'
		}
		return r
	}, s)
}

func isUnsafe(r rune) bool {
	switch {
	case r < ' ', r >= 0x7f && r <= 0x9f: // C0 and C1 controls, DEL
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069: // bidi overrides
		return true
	}
	return false
}
