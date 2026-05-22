//go:build x11 && debug

package x11

import (
	"log"
)

func debugf(format string, v ...interface{}) {
	log.Printf(format, v...)
}
