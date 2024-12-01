// Copied from https://github.com/mattn/go-shellwords/tree/f3bbb6f7f6510c6059561a79e3f105578be4fcce
// Original license below.
//
// The MIT License (MIT)
//
// Copyright (c) 2017 Yasuhiro Matsumoto
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

package shellwords

import (
	"reflect"
	"testing"
)

var testcases = []struct {
	line        string
	expected    []string
	expectedRaw []string
}{
	{``, nil, nil},
	{`""`, []string{``}, []string{`""`}},
	{`''`, []string{``}, []string{`''`}},
	{`var --bar=baz`, []string{`var`, `--bar=baz`}, []string{`var`, `--bar=baz`}},
	{`var --bar="baz"`, []string{`var`, `--bar=baz`}, []string{`var`, `--bar="baz"`}},
	{`var "--bar=baz"`, []string{`var`, `--bar=baz`}, []string{`var`, `"--bar=baz"`}},
	{`var "--bar='baz'"`, []string{`var`, `--bar='baz'`}, []string{`var`, `"--bar='baz'"`}},
	{"var --bar=`baz`", []string{`var`, "--bar=`baz`"}, []string{`var`, "--bar=`baz`"}},
	{`var "--bar=\"baz'"`, []string{`var`, `--bar="baz'`}, []string{`var`, `"--bar=\"baz'"`}},
	{`var "--bar=\'baz\'"`, []string{`var`, `--bar='baz'`}, []string{`var`, `"--bar=\'baz\'"`}},
	{`var --bar='\'`, []string{`var`, `--bar=\`}, []string{`var`, `--bar='\'`}},
	{`var "--bar baz"`, []string{`var`, `--bar baz`}, []string{`var`, `"--bar baz"`}},
	{`var --"bar baz"`, []string{`var`, `--bar baz`}, []string{`var`, `--"bar baz"`}},
	{`var  --"bar baz"`, []string{`var`, `--bar baz`}, []string{`var`, `--"bar baz"`}},
	{`a "b"`, []string{`a`, `b`}, []string{`a`, `"b"`}},
	{`a " b "`, []string{`a`, ` b `}, []string{`a`, `" b "`}},
	{`a "   "`, []string{`a`, `   `}, []string{`a`, `"   "`}},
	{`a 'b'`, []string{`a`, `b`}, []string{`a`, `'b'`}},
	{`a ' b '`, []string{`a`, ` b `}, []string{`a`, `' b '`}},
	{`a '   '`, []string{`a`, `   `}, []string{`a`, `'   '`}},
	{"foo bar\\  ", []string{`foo`, `bar `}, []string{`foo`, `bar\ `}},
	{`foo "" bar ''`, []string{`foo`, ``, `bar`, ``}, []string{`foo`, `""`, `bar`, `''`}},
	{`foo \\`, []string{`foo`, `\`}, []string{`foo`, `\\`}},
	{`foo \& bar`, []string{`foo`, `&`, `bar`}, []string{`foo`, `\&`, `bar`}},
	{`sh -c "printf 'Hello\tworld\n'"`, []string{`sh`, `-c`, "printf 'Hello\tworld\n'"}, []string{`sh`, `-c`, `"printf 'Hello\tworld\n'"`}},
}

func TestSimple(t *testing.T) {
	for _, testcase := range testcases {
		args, raw := Parse(testcase.line)
		if !reflect.DeepEqual(args, testcase.expected) {
			t.Fatalf("Expected %#v for %q, but got %#v:", testcase.expected, testcase.line, args)
		}
		if !reflect.DeepEqual(raw, testcase.expectedRaw) {
			t.Fatalf("Expected raw %#v for %q, but got %#v:", testcase.expectedRaw, testcase.line, raw)
		}
	}
}
