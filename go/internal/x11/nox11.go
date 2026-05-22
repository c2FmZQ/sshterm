//go:build !x11

package x11

import (
	"golang.org/x/crypto/ssh"
)

func Enabled() bool {
	return false
}

func HandleX11Forwarding(any, *ssh.Client, string, []byte) {
}
