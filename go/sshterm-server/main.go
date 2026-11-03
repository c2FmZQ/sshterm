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

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/c2FmZQ/sshterm/sshterm-server/internal"
)

var Version = "dev"

type endpointFlags []internal.Endpoint

func (f *endpointFlags) String() string {
	parts := make([]string, 0, len(*f))
	for _, ep := range *f {
		parts = append(parts, fmt.Sprintf("%s=%s", ep.Name, ep.Address))
	}
	return strings.Join(parts, ",")
}

func (f *endpointFlags) Set(value string) error {
	ep, err := internal.ParseEndpoint(value)
	if err != nil {
		return err
	}
	*f = append(*f, ep)
	return nil
}

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return fmt.Errorf("invalid trusted proxy %q", value)
		}
		*f = append(*f, part)
	}
	return nil
}

func main() {
	var (
		addr           = flag.String("addr", "127.0.0.1:8080", "The TCP address to listen on.")
		cfgFile        = flag.String("config", "", "Optional path to a base config.json file.")
		tlsCert        = flag.String("tls-cert", "", "Path to a TLS certificate file (requires --tls-key).")
		tlsKey         = flag.String("tls-key", "", "Path to a TLS private key file (requires --tls-cert).")
		authorizedKeys = flag.String("authorized-keys", "", "Path to an authorized_keys file to enable the built-in jump host.")
		hostKey        = flag.String("host-key", "", "Optional path to a private key file for the built-in jump host (generated dynamically if unset).")
		versionFlag    = flag.Bool("v", false, "Show the version.")
		endpoints      endpointFlags
		trustedProxies stringListFlag
	)
	flag.Var(&endpoints, "ep", "SSH endpoint in the form name=host[:port] (repeatable).")
	flag.Var(&endpoints, "endpoint", "Alias for -ep.")
	flag.Var(&trustedProxies, "trusted-proxies", "Comma-separated list of trusted proxy IPs or CIDRs for X-Forwarded-For (repeatable).")
	flag.Parse()

	if *versionFlag {
		os.Stdout.WriteString(Version + " " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH + "\n")
		return
	}

	log.Printf("sshterm-server %s %s %s/%s", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	srv, err := internal.New(internal.Options{
		Addr:               *addr,
		ConfigFile:         *cfgFile,
		TLSCertFile:        *tlsCert,
		TLSKeyFile:         *tlsKey,
		AuthorizedKeysFile: *authorizedKeys,
		HostKeyFile:        *hostKey,
		TrustedProxies:     trustedProxies,
		Endpoints:          endpoints,
	})
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
