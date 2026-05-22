//go:build x11 && debug

package wire

import (
	"log"
)

func debugf(format string, v ...interface{}) {
	log.Printf(format, v...)
}
