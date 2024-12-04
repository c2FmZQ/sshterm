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

package app

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

func checkCertificate(cert *ssh.Certificate, certType uint32) error {
	var errs []error
	if cert.CertType != certType {
		errs = append(errs, fmt.Errorf("certificate has wrong type: %d", cert.CertType))
	}
	now := uint64(time.Now().Unix())
	if cert.ValidAfter > now {
		errs = append(errs, fmt.Errorf("certificate is not yet valid"))
	}
	if cert.ValidBefore > 0 && now > cert.ValidBefore {
		errs = append(errs, fmt.Errorf("certificate is expired"))
	}
	if certType == ssh.HostCert && len(cert.CriticalOptions) > 0 {
		errs = append(errs, fmt.Errorf("certificate has critical options: %v", cert.CriticalOptions))
	}
	c2 := *cert
	c2.Signature = nil
	signBytes := c2.Marshal()
	if err := cert.SignatureKey.Verify(signBytes[:len(signBytes)-4], cert.Signature); err != nil {
		errs = append(errs, fmt.Errorf("certificate signature is invalid"))
	}
	return errors.Join(errs...)
}
