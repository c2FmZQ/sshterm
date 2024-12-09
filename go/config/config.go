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

package config

// Config is SSH Term configuration. This data structure is typically read from
// the config.json file in the same directory as the SSH app.
type Config struct {
	// DBName is the name of the IndexedDB database to use. It defaults to
	// "sshterm".
	DBName string `json:"dbName,omitempty"`

	// Persist, if set, forces database persistence to be on or off and
	// cannot be changed from the app.
	Persist *bool `json:"persist,omitempty"`

	// Authorities is a list of Certificate Authorities used to verify host
	// certificates.
	Authorities []struct {
		Name      string   `json:"name"`
		PublicKey string   `json:"publicKey"`
		Hostnames []string `json:"hostnames,omitempty"`
	} `json:"certificateAuthorities,omitempty"`

	// Endpoints is a list of WebSocket endpoints that the app can use to
	// connect to SSH servers.
	Endpoints []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"endpoints,omitempty"`

	// Hosts is a list of known hosts and their host keys. It is used for
	// host key authentication. For hosts that use certificates, use
	// Authorities instead.
	Hosts []struct {
		Name string `json:"name"`
		Key  string `json:"key,omitempty"`
	} `json:"hosts,omitempty"`

	// GenerateKeys instructs the app to generate SSH keys when it starts.
	// These keys are passwordless and are intended to be used with an
	// Identity Provider.
	GenerateKeys []struct {
		Name             string `json:"name"`
		Type             string `json:"type,omitempty"`
		Bits             int    `json:"bits,omitempty"`
		IdentityProvider string `json:"identityProvider,omitempty"`
		AddToAgent       bool   `json:"addToAgent,omitempty"`
	} `json:"generateKeys,omitempty"`

	// AutoConnect, if set, instructs the app to open an SSH connection
	// immediately after it starts. All normal interactive commands are
	// disabled.
	// If Username is unset, the user will be prompted to enter it.
	// If Command is unset, the app will request an interactive shell.
	AutoConnect *struct {
		Username     string `json:"username,omitempty"`
		Endpoint     string `json:"endpoint"`
		Identity     string `json:"identity,omitempty"`
		Command      string `json:"command,omitempty"`
		ForwardAgent bool   `json:"forwardAgent,omitempty"`
	} `json:"autoConnect,omitempty"`
}
