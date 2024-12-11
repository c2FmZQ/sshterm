// Copied from https://github.com/mattn/go-shellwords/tree/f3bbb6f7f6510c6059561a79e3f105578be4fcce
// Trimmed down and modified a little bit for sshterm.
//
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

func isSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\r', '\n':
		return true
	}
	return false
}

func isWild(r rune) bool {
	switch r {
	case '*', '?', '[':
		return true
	}
	return false
}

type argType int

const (
	argNo argType = iota
	argSingle
	argQuoted
)

type Option func(*opt)
type opt struct {
	quoteWildcards bool
}

func QuoteWild() Option {
	return func(o *opt) {
		o.quoteWildcards = true
	}
}

func Parse(line string, opts ...Option) ([]string, []string) {
	var options opt
	for _, o := range opts {
		o(&options)
	}
	var args []string
	var argsRaw []string

	var buf string
	var bufRaw string

	var escaped, doubleQuoted, singleQuoted bool

	got := argNo

	i := -1
	for _, r := range line {
		i++
		if escaped {
			bufRaw += string(r)
			if r == 't' {
				r = '\t'
			}
			if r == 'n' {
				r = '\n'
			}
			if options.quoteWildcards && isWild(r) {
				buf += "\\"
			}
			buf += string(r)
			escaped = false
			got = argSingle
			continue
		}

		if r == '\\' {
			bufRaw += string(r)
			if singleQuoted {
				buf += string(r)
			} else {
				escaped = true
			}
			continue
		}

		if options.quoteWildcards && isWild(r) {
			bufRaw += string(r)
			if singleQuoted || doubleQuoted {
				buf += "\\"
			}
			buf += string(r)
			got = argSingle
			continue
		}

		if isSpace(r) {
			if singleQuoted || doubleQuoted {
				buf += string(r)
				bufRaw += string(r)
			} else if got != argNo {
				args = append(args, buf)
				argsRaw = append(argsRaw, bufRaw)
				buf = ""
				bufRaw = ""
				got = argNo
			}
			continue
		}

		bufRaw += string(r)
		switch r {
		case '"':
			if !singleQuoted {
				if doubleQuoted {
					got = argQuoted
				}
				doubleQuoted = !doubleQuoted
				continue
			}
		case '\'':
			if !doubleQuoted {
				if singleQuoted {
					got = argQuoted
				}
				singleQuoted = !singleQuoted
				continue
			}
		}

		got = argSingle
		buf += string(r)
	}

	if escaped {
		buf += "\\"
		bufRaw += "\\"
	}

	if got != argNo {
		args = append(args, buf)
		argsRaw = append(argsRaw, bufRaw)
	}
	return args, argsRaw
}

func UnquoteWild(s string) string {
	var buf string
	var esc bool
	for _, r := range s {
		if esc {
			if !isWild(r) {
				buf += "\\"
			}
			buf += string(r)
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		buf += string(r)
	}
	if esc {
		buf += "\\"
	}
	return buf
}
