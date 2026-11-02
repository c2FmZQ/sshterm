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

package internal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// DefaultJumpEndpointName is the endpoint and host name used in config.json
// when the built-in jump host is enabled.
const DefaultJumpEndpointName = "jump"

const (
	maxJumpChannelsPerConn = 32
	maxWSMessageSize       = 64 * 1024
)

var jumpPubKeyAuthAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoSKECDSA256,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA256,
	ssh.KeyAlgoRSASHA512,
}

type ipMatcher struct {
	ip   net.IP
	cidr *net.IPNet
}

func (m ipMatcher) matches(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if m.cidr != nil {
		return cidrContainsIP(m.cidr, ip)
	}
	return m.ip != nil && m.ip.Equal(ip)
}

func parseTrustedProxies(specs []string) ([]ipMatcher, error) {
	var matchers []ipMatcher
	for _, spec := range specs {
		for _, entry := range strings.Split(spec, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				return nil, fmt.Errorf("invalid trusted proxy %q", spec)
			}
			if strings.Contains(entry, "/") {
				_, cidr, err := net.ParseCIDR(entry)
				if err != nil {
					return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", entry, err)
				}
				matchers = append(matchers, ipMatcher{cidr: cidr})
				continue
			}
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted proxy IP %q", entry)
			}
			matchers = append(matchers, ipMatcher{ip: ip})
		}
	}
	return matchers, nil
}

type jumpHost struct {
	signer             ssh.Signer
	authorizedKeysFile string
	trustedProxies     []ipMatcher
	dialContext        func(ctx context.Context, network, address string) (net.Conn, error)
	lookupIP           func(ctx context.Context, host string) ([]net.IPAddr, error)
	logger             *log.Logger

	mu        sync.Mutex
	lastBytes []byte
	rules     []authRule
}

type authRule struct {
	isCA       bool
	pubKey     ssh.PublicKey
	keyBytes   []byte
	principals []string
	permitOpen []permitOpenRule
}

type permitOpenRule struct {
	hostPattern string
	ip          net.IP
	cidr        *net.IPNet
	port        int // 0 means wildcard '*'
}

func newJumpHost(authorizedKeysFile, hostKeyFile string, trustedProxies []ipMatcher, dialContext func(ctx context.Context, network, address string) (net.Conn, error), logger *log.Logger) (*jumpHost, error) {
	akBytes, err := os.ReadFile(authorizedKeysFile)
	if err != nil {
		return nil, fmt.Errorf("reading authorized_keys file: %w", err)
	}
	rules, err := parseAuthorizedKeys(akBytes)
	if err != nil {
		return nil, err
	}

	var signer ssh.Signer
	if hostKeyFile != "" {
		hkBytes, err := os.ReadFile(hostKeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading host key file: %w", err)
		}
		signer, err = ssh.ParsePrivateKey(hkBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing host key file: %w", err)
		}
		if signer.PublicKey().Type() == ssh.KeyAlgoDSA {
			return nil, errors.New("DSA host keys are not supported")
		}
		if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
			if mas, ok := signer.(ssh.MultiAlgorithmSigner); ok {
				signer, err = ssh.NewSignerWithAlgorithms(mas, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})
				if err != nil {
					return nil, fmt.Errorf("restricting RSA host key algorithms: %w", err)
				}
			}
		}
	} else {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating jump host key: %w", err)
		}
		signer, err = ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, fmt.Errorf("creating jump host signer: %w", err)
		}
		if logger != nil {
			logger.Printf("warning: --host-key not specified; generated ephemeral jump host key (%s)", ssh.FingerprintSHA256(signer.PublicKey()))
		}
	}

	return &jumpHost{
		signer:             signer,
		authorizedKeysFile: authorizedKeysFile,
		trustedProxies:     trustedProxies,
		dialContext:        dialContext,
		lookupIP:           net.DefaultResolver.LookupIPAddr,
		logger:             logger,
		lastBytes:          akBytes,
		rules:              rules,
	}, nil
}

func (j *jumpHost) getRules() []authRule {
	j.mu.Lock()
	defer j.mu.Unlock()

	akBytes, err := os.ReadFile(j.authorizedKeysFile)
	if err != nil {
		if j.logger != nil {
			j.logger.Printf("error reading authorized_keys file %q: %v", j.authorizedKeysFile, err)
		}
		return j.rules
	}
	if bytes.Equal(akBytes, j.lastBytes) {
		return j.rules
	}
	j.lastBytes = akBytes
	rules, err := parseAuthorizedKeys(akBytes)
	if err != nil {
		if j.logger != nil {
			j.logger.Printf("error reloading authorized_keys file %q: %v", j.authorizedKeysFile, err)
		}
		return j.rules
	}
	j.rules = rules
	if j.logger != nil {
		j.logger.Printf("reloaded authorized_keys file %q (%d rules)", j.authorizedKeysFile, len(rules))
	}
	return j.rules
}

func (j *jumpHost) publicKeyAuthorizedFormat() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(j.signer.PublicKey())))
}

func parseAuthorizedKeys(content []byte) ([]authRule, error) {
	var rules []authRule
	lines := bytes.Split(content, []byte("\n"))
	for i, rawLine := range lines {
		lineNum := i + 1
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pubKey, _, opts, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("authorized_keys line %d: %w", lineNum, err)
		}
		rule, err := parseAuthRule(lineNum, pubKey, opts)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseAuthRule(lineNum int, pubKey ssh.PublicKey, opts []string) (authRule, error) {
	if _, isCert := pubKey.(*ssh.Certificate); isCert {
		return authRule{}, fmt.Errorf("authorized_keys line %d: certificate cannot be used as an authorized key; use cert-authority with a CA public key", lineNum)
	}
	if pubKey.Type() == ssh.KeyAlgoDSA {
		return authRule{}, fmt.Errorf("authorized_keys line %d: DSA keys are not supported", lineNum)
	}

	var (
		isCA             bool
		noPortForwarding bool
		principals       []string
		permitOpen       []permitOpenRule
	)

	for _, opt := range opts {
		k, v, hasVal := strings.Cut(opt, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		if hasVal {
			var err error
			v, err = unquoteOptValue(v)
			if err != nil {
				return authRule{}, fmt.Errorf("authorized_keys line %d: option %q: %w", lineNum, k, err)
			}
		}

		switch k {
		case "cert-authority":
			if hasVal {
				return authRule{}, fmt.Errorf("authorized_keys line %d: option %q does not take a value", lineNum, k)
			}
			isCA = true

		case "principals":
			if !hasVal {
				return authRule{}, fmt.Errorf("authorized_keys line %d: option %q requires a value", lineNum, k)
			}
			var count int
			for _, p := range strings.Split(v, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					return authRule{}, fmt.Errorf("authorized_keys line %d: empty principal in principals option", lineNum)
				}
				if _, err := path.Match(p, "test"); err != nil {
					return authRule{}, fmt.Errorf("authorized_keys line %d: invalid principal pattern %q: %w", lineNum, p, err)
				}
				principals = append(principals, p)
				count++
			}
			if count == 0 {
				return authRule{}, fmt.Errorf("authorized_keys line %d: empty principals option", lineNum)
			}

		case "permitopen":
			if !hasVal {
				return authRule{}, fmt.Errorf("authorized_keys line %d: option %q requires a value", lineNum, k)
			}
			parts := strings.Split(v, ",")
			if len(parts) == 1 && strings.EqualFold(strings.TrimSpace(parts[0]), "none") {
				permitOpen = nil
				break
			}
			var count int
			for _, entry := range parts {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					return authRule{}, fmt.Errorf("authorized_keys line %d: empty permitopen specification", lineNum)
				}
				if strings.EqualFold(entry, "none") {
					return authRule{}, fmt.Errorf("authorized_keys line %d: permitopen=\"none\" cannot be combined with other entries in the same option", lineNum)
				}
				po, err := parsePermitOpen(entry)
				if err != nil {
					return authRule{}, fmt.Errorf("authorized_keys line %d: %w", lineNum, err)
				}
				permitOpen = append(permitOpen, po)
				count++
			}
			if count == 0 {
				return authRule{}, fmt.Errorf("authorized_keys line %d: empty permitopen option", lineNum)
			}

		case "no-port-forwarding", "restrict":
			if hasVal {
				return authRule{}, fmt.Errorf("authorized_keys line %d: option %q does not take a value", lineNum, k)
			}
			noPortForwarding = true
			if k == "restrict" {
				permitOpen = nil
			}

		case "port-forwarding":
			if hasVal {
				return authRule{}, fmt.Errorf("authorized_keys line %d: option %q does not take a value", lineNum, k)
			}
			noPortForwarding = false

		default:
			return authRule{}, fmt.Errorf("authorized_keys line %d: unsupported option %q", lineNum, k)
		}
	}

	if !isCA && len(principals) > 0 {
		return authRule{}, fmt.Errorf("authorized_keys line %d: \"principals\" option requires \"cert-authority\"", lineNum)
	}
	if isCA && len(principals) == 0 {
		return authRule{}, fmt.Errorf("authorized_keys line %d: \"cert-authority\" requires \"principals\" option", lineNum)
	}
	if noPortForwarding {
		permitOpen = nil
	}

	return authRule{
		isCA:       isCA,
		pubKey:     pubKey,
		keyBytes:   pubKey.Marshal(),
		principals: principals,
		permitOpen: permitOpen,
	}, nil
}

func unquoteOptValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", errors.New("option value must be enclosed in double quotes")
	}
	raw := v[1 : len(v)-1]
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' {
			if i+1 >= len(raw) {
				return "", errors.New("unterminated escape sequence in option value")
			}
			i++
			if raw[i] != '\\' && raw[i] != '"' {
				return "", fmt.Errorf("invalid escape sequence \\%c in option value", raw[i])
			}
			b.WriteByte(raw[i])
			continue
		}
		if raw[i] == '"' {
			return "", errors.New("unescaped quote in option value")
		}
		b.WriteByte(raw[i])
	}
	return b.String(), nil
}

func parsePermitOpen(spec string) (permitOpenRule, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return permitOpenRule{}, errors.New("empty permitopen specification")
	}

	var hostPart, portPart string
	bracketed := false
	if strings.HasPrefix(spec, "[") {
		bracketed = true
		idx := strings.IndexByte(spec, ']')
		if idx == -1 {
			return permitOpenRule{}, fmt.Errorf("invalid permitopen %q: missing closing bracket", spec)
		}
		hostPart = spec[1:idx]
		rest := spec[idx+1:]
		if rest == "" {
			portPart = "22"
		} else if strings.HasPrefix(rest, ":") {
			portPart = rest[1:]
		} else {
			return permitOpenRule{}, fmt.Errorf("invalid permitopen %q", spec)
		}
	} else {
		switch strings.Count(spec, ":") {
		case 0:
			hostPart = spec
			portPart = "22"
		case 1:
			hostPart, portPart, _ = strings.Cut(spec, ":")
		default:
			if net.ParseIP(spec) != nil {
				hostPart = spec
				portPart = "22"
			} else if _, _, err := net.ParseCIDR(spec); err == nil {
				hostPart = spec
				portPart = "22"
			} else {
				return permitOpenRule{}, fmt.Errorf("invalid permitopen %q: use [ipv6]:port for IPv6 with port", spec)
			}
		}
	}

	hostPart = strings.TrimSpace(hostPart)
	portPart = strings.TrimSpace(portPart)
	if hostPart == "" {
		return permitOpenRule{}, fmt.Errorf("invalid permitopen %q: host cannot be empty", spec)
	}
	if portPart == "" {
		return permitOpenRule{}, fmt.Errorf("invalid permitopen %q: port cannot be empty", spec)
	}

	var port int
	if portPart == "*" {
		port = 0
	} else {
		p, err := strconv.Atoi(portPart)
		if err != nil || p < 1 || p > 65535 {
			return permitOpenRule{}, fmt.Errorf("invalid permitopen %q: invalid port %q", spec, portPart)
		}
		port = p
	}

	rule := permitOpenRule{port: port}
	if strings.Contains(hostPart, "/") {
		_, ipNet, err := net.ParseCIDR(hostPart)
		if err != nil {
			return permitOpenRule{}, fmt.Errorf("invalid permitopen %q: %w", spec, err)
		}
		if bracketed && !strings.Contains(hostPart, ":") {
			return permitOpenRule{}, fmt.Errorf("invalid permitopen %q: brackets are only valid for IPv6", spec)
		}
		rule.cidr = ipNet
	} else if ip := net.ParseIP(hostPart); ip != nil {
		if bracketed && !strings.Contains(hostPart, ":") {
			return permitOpenRule{}, fmt.Errorf("invalid permitopen %q: brackets are only valid for IPv6", spec)
		}
		rule.ip = ip
	} else {
		if bracketed {
			return permitOpenRule{}, fmt.Errorf("invalid permitopen %q: bracketed host must be a valid IPv6 address or CIDR", spec)
		}
		pat := strings.ToLower(hostPart)
		if err := validateHostPattern(pat); err != nil {
			return permitOpenRule{}, fmt.Errorf("invalid permitopen %q: %w", spec, err)
		}
		rule.hostPattern = pat
	}

	return rule, nil
}

func validateHostPattern(pat string) error {
	if pat == "*" {
		return nil
	}
	if len(pat) > 253 {
		return errors.New("host pattern too long")
	}
	if _, err := path.Match(pat, "test"); err != nil {
		return err
	}
	labels := strings.Split(pat, ".")
	allNumericOrWildcard := true
	for _, label := range labels {
		if label == "" {
			return errors.New("empty label in host pattern")
		}
		labelHasAlpha := false
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z':
				labelHasAlpha = true
				allNumericOrWildcard = false
			case c >= '0' && c <= '9', c == '-', c == '_':
			case c == '*', c == '?':
			default:
				return fmt.Errorf("invalid character %q in host pattern", c)
			}
		}
		_ = labelHasAlpha
	}
	if allNumericOrWildcard && len(labels) > 1 {
		return errors.New("IP wildcards are not supported; use CIDR notation")
	}
	lastLabel := labels[len(labels)-1]
	c0 := lastLabel[0]
	if !((c0 >= 'a' && c0 <= 'z') || c0 == '*' || c0 == '?') {
		return errors.New("top-level label must start with a letter or wildcard")
	}
	return nil
}

func isValidDestHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		}
	}
	lastLabel := labels[len(labels)-1]
	return lastLabel[0] >= 'a' && lastLabel[0] <= 'z'
}

func (j *jumpHost) authenticate(conn ssh.ConnMetadata, pubKey ssh.PublicKey, rules []authRule) ([]permitOpenRule, string, error) {
	if cert, ok := pubKey.(*ssh.Certificate); ok {
		if cert.SignatureKey == nil {
			return nil, "", errors.New("certificate missing signature key")
		}
		caBytes := cert.SignatureKey.Marshal()
		var allowedRules []permitOpenRule
		for _, rule := range rules {
			if !rule.isCA || !bytes.Equal(rule.keyBytes, caBytes) {
				continue
			}
			if !matchPrincipals(rule.principals, cert.ValidPrincipals) {
				continue
			}
			if len(rule.permitOpen) == 0 {
				continue
			}
			allowedRules = append(allowedRules, rule.permitOpen...)
		}
		if len(allowedRules) == 0 {
			return nil, "", errors.New("certificate not authorized")
		}
		if err := validateUserCert(cert, conn.RemoteAddr()); err != nil {
			return nil, "", err
		}
		return allowedRules, fmt.Sprintf("cert:%s", cert.KeyId), nil
	}

	if pubKey.Type() == ssh.KeyAlgoDSA {
		return nil, "", errors.New("DSA keys are not supported")
	}
	keyBytes := pubKey.Marshal()
	var allowedRules []permitOpenRule
	for _, rule := range rules {
		if rule.isCA || !bytes.Equal(rule.keyBytes, keyBytes) {
			continue
		}
		if len(rule.permitOpen) == 0 {
			continue
		}
		allowedRules = append(allowedRules, rule.permitOpen...)
	}
	if len(allowedRules) == 0 {
		return nil, "", errors.New("public key not authorized")
	}
	return allowedRules, fmt.Sprintf("key:%s", ssh.FingerprintSHA256(pubKey)), nil
}

func matchPrincipals(patterns, certPrincipals []string) bool {
	if len(patterns) == 0 || len(certPrincipals) == 0 {
		return false
	}
	for _, pat := range patterns {
		for _, p := range certPrincipals {
			if p == "" {
				continue
			}
			if matched, err := path.Match(pat, p); err == nil && matched {
				return true
			}
		}
	}
	return false
}

func validateUserCert(cert *ssh.Certificate, remoteAddr net.Addr) error {
	if cert.CertType != ssh.UserCert {
		return fmt.Errorf("certificate has wrong type: %d", cert.CertType)
	}
	if cert.Key == nil || cert.Key.Type() == ssh.KeyAlgoDSA {
		return errors.New("certificate key algorithm is not supported")
	}
	now := uint64(time.Now().Unix())
	if cert.ValidAfter > now {
		return errors.New("certificate is not yet valid")
	}
	if cert.ValidBefore != ssh.CertTimeInfinity && (now >= cert.ValidBefore || cert.ValidBefore < cert.ValidAfter) {
		return errors.New("certificate is expired")
	}
	for k, v := range cert.CriticalOptions {
		if k == "source-address" {
			if !checkSourceAddress(v, remoteAddr) {
				return errors.New("certificate source-address mismatch")
			}
			continue
		}
		return fmt.Errorf("certificate has unsupported critical option %q", k)
	}
	if v, ok := cert.Extensions["permit-port-forwarding"]; !ok || v != "" {
		return errors.New("certificate does not permit port forwarding")
	}
	if cert.Signature == nil || cert.SignatureKey == nil || cert.Signature.Format == ssh.KeyAlgoRSA || cert.Signature.Format == ssh.KeyAlgoDSA {
		return errors.New("certificate signature algorithm is not supported")
	}
	c2 := *cert
	c2.Signature = nil
	signBytes := c2.Marshal()
	if len(signBytes) < 4 {
		return errors.New("certificate is malformed")
	}
	if err := cert.SignatureKey.Verify(signBytes[:len(signBytes)-4], cert.Signature); err != nil {
		return errors.New("certificate signature is invalid")
	}
	return nil
}

func cidrContainsIP(cidr *net.IPNet, ip net.IP) bool {
	if cidr == nil || ip == nil {
		return false
	}
	return cidr.Contains(ip)
}

func parseIPString(s string) net.IP {
	if h, _, ok := strings.Cut(s, "%"); ok {
		s = h
	}
	return net.ParseIP(s)
}

func extractAddrIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		if tcpAddr == nil {
			return nil
		}
		return tcpAddr.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return parseIPString(host)
}

func (j *jumpHost) isTrustedProxy(ip net.IP) bool {
	for _, m := range j.trustedProxies {
		if m.matches(ip) {
			return true
		}
	}
	return false
}

func (j *jumpHost) resolveClientAddr(req *http.Request, peerAddr net.Addr) net.Addr {
	if len(j.trustedProxies) == 0 || req == nil {
		return peerAddr
	}
	peerIP := extractAddrIP(peerAddr)
	if !j.isTrustedProxy(peerIP) {
		return peerAddr
	}
	xffValues := req.Header.Values("X-Forwarded-For")
	if len(xffValues) == 0 {
		return peerAddr
	}
	var parts []string
	for _, hdr := range xffValues {
		for _, p := range strings.Split(hdr, ",") {
			parts = append(parts, strings.TrimSpace(p))
		}
	}
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "" {
			return &net.TCPAddr{}
		}
		ip := parseIPString(parts[i])
		if ip == nil {
			return &net.TCPAddr{}
		}
		if !j.isTrustedProxy(ip) || i == 0 {
			return &net.TCPAddr{IP: ip}
		}
	}
	return &net.TCPAddr{}
}

func checkSourceAddress(sourceAddrs string, remoteAddr net.Addr) bool {
	if remoteAddr == nil || strings.TrimSpace(sourceAddrs) == "" {
		return false
	}
	remoteIP := extractAddrIP(remoteAddr)
	if remoteIP == nil {
		return false
	}
	matched := false
	for _, entry := range strings.Split(sourceAddrs, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return false
		}
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			if cidrContainsIP(cidr, remoteIP) {
				matched = true
			}
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return false
		}
		if ip.Equal(remoteIP) {
			matched = true
		}
	}
	return matched
}

func (j *jumpHost) authorizeDestination(ctx context.Context, rules []permitOpenRule, destHost string, destPort uint32) (string, bool) {
	if destPort < 1 || destPort > 65535 {
		return "", false
	}
	rawHost := strings.TrimSpace(destHost)
	if rawHost == "" {
		return "", false
	}
	h := rawHost
	if strings.HasPrefix(rawHost, "[") && strings.HasSuffix(rawHost, "]") {
		inner := rawHost[1 : len(rawHost)-1]
		if ip := net.ParseIP(inner); ip != nil && strings.Contains(inner, ":") {
			h = inner
		} else {
			return "", false
		}
	}

	port := int(destPort)
	portStr := strconv.Itoa(port)

	if destIP := net.ParseIP(h); destIP != nil {
		for _, r := range rules {
			if r.port != 0 && r.port != port {
				continue
			}
			if r.hostPattern == "*" {
				return net.JoinHostPort(destIP.String(), portStr), true
			}
			if r.ip != nil && r.ip.Equal(destIP) {
				return net.JoinHostPort(destIP.String(), portStr), true
			}
			if r.cidr != nil && cidrContainsIP(r.cidr, destIP) {
				return net.JoinHostPort(destIP.String(), portStr), true
			}
		}
		return "", false
	}

	lowerHost := strings.ToLower(h)
	if !isValidDestHostname(lowerHost) {
		return "", false
	}
	hasIPRule := false
	for _, r := range rules {
		if r.port != 0 && r.port != port {
			continue
		}
		if r.hostPattern == "*" {
			return net.JoinHostPort(lowerHost, portStr), true
		}
		if r.hostPattern != "" {
			if matched, err := path.Match(r.hostPattern, lowerHost); err == nil && matched {
				return net.JoinHostPort(lowerHost, portStr), true
			}
		}
		if r.ip != nil || r.cidr != nil {
			hasIPRule = true
		}
	}
	if !hasIPRule || j.lookupIP == nil {
		return "", false
	}
	lookupCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	addrs, err := j.lookupIP(lookupCtx, lowerHost)
	cancel()
	if err != nil {
		return "", false
	}
	for _, addr := range addrs {
		if addr.IP == nil {
			continue
		}
		for _, r := range rules {
			if r.port != 0 && r.port != port {
				continue
			}
			if r.ip != nil && r.ip.Equal(addr.IP) {
				return net.JoinHostPort(addr.IP.String(), portStr), true
			}
			if r.cidr != nil && cidrContainsIP(r.cidr, addr.IP) {
				return net.JoinHostPort(addr.IP.String(), portStr), true
			}
		}
	}
	return "", false
}

func (j *jumpHost) serveWebSocket(reqCtx context.Context, wsConn *websocket.Conn, remoteAddr net.Addr) {
	conn := newJumpWSConn(wsConn, remoteAddr)
	defer conn.Close()

	rules := j.getRules()
	var (
		allowedRules []permitOpenRule
		authID       string
	)
	sshCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			_, _, err := j.authenticate(conn, pubKey, rules)
			return nil, err
		},
		VerifiedPublicKeyCallback: func(conn ssh.ConnMetadata, pubKey ssh.PublicKey, _ *ssh.Permissions, sigFormat string) (*ssh.Permissions, error) {
			if sigFormat == ssh.KeyAlgoRSA || sigFormat == ssh.KeyAlgoDSA {
				return nil, fmt.Errorf("signature algorithm %q is not supported", sigFormat)
			}
			var err error
			allowedRules, authID, err = j.authenticate(conn, pubKey, rules)
			return nil, err
		},
		PublicKeyAuthAlgorithms: jumpPubKeyAuthAlgorithms,
	}
	sshCfg.AddHostKey(j.signer)

	handshakeTimer := time.AfterFunc(dialTimeout, func() {
		_ = conn.Close()
	})
	sconn, chans, reqs, err := ssh.NewServerConn(conn, sshCfg)
	handshakeTimer.Stop()
	if err != nil {
		return
	}
	defer sconn.Close()

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range reqs {
			if req.WantReply {
				_ = req.Reply(req.Type == "keepalive@openssh.com", nil)
			}
		}
	}()

	sem := make(chan struct{}, maxJumpChannelsPerConn)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(ssh.Prohibited, "only direct-tcpip is permitted")
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = newChan.Reject(ssh.ResourceShortage, "too many concurrent channels")
			continue
		}
		wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer wg.Done()
			defer func() { <-sem }()
			j.handleDirectTCPIP(reqCtx, sconn, nc, allowedRules, authID)
		}(newChan)
	}
}

type sshChanDeadlineWriter struct {
	ch        ssh.Channel
	onTimeout func()
}

func (w *sshChanDeadlineWriter) Write(p []byte) (int, error) {
	timer := time.AfterFunc(writeWait, w.onTimeout)
	defer timer.Stop()
	return w.ch.Write(p)
}

func (j *jumpHost) handleDirectTCPIP(ctx context.Context, sconn ssh.Conn, newChan ssh.NewChannel, allowedRules []permitOpenRule, authID string) {
	var payload struct {
		DestHost   string
		DestPort   uint32
		OriginHost string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
		_ = newChan.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
		return
	}

	targetAddr, ok := j.authorizeDestination(ctx, allowedRules, payload.DestHost, payload.DestPort)
	if !ok {
		j.logger.Printf("jump host denied %q -> %q:%d", authID, payload.DestHost, payload.DestPort)
		_ = newChan.Reject(ssh.Prohibited, "destination not permitted")
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	tcpConn, err := j.dialContext(dialCtx, "tcp", targetAddr)
	cancel()
	if err != nil {
		j.logger.Printf("jump host dial %q:%d (%s) failed: %v", payload.DestHost, payload.DestPort, targetAddr, err)
		_ = newChan.Reject(ssh.ConnectionFailed, "upstream connection failed")
		return
	}
	defer tcpConn.Close()

	ch, chReqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(chReqs)

	var wg sync.WaitGroup
	wg.Add(2)
	var closeOnce sync.Once
	var teardownTimer *time.Timer
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = ch.Close()
			_ = tcpConn.Close()
			teardownTimer = time.AfterFunc(writeWait, func() {
				_ = sconn.Close()
			})
		})
	}

	go func() {
		defer wg.Done()
		defer closeBoth()
		_, _ = io.Copy(&tcpDeadlineWriter{conn: tcpConn}, ch)
	}()

	go func() {
		defer wg.Done()
		defer closeBoth()
		_, _ = io.Copy(&sshChanDeadlineWriter{
			ch: ch,
			onTimeout: func() {
				closeBoth()
				_ = sconn.Close()
			},
		}, tcpConn)
	}()

	wg.Wait()
	if teardownTimer != nil {
		teardownTimer.Stop()
	}
}

type jumpWSConn struct {
	ws         *websocket.Conn
	remoteAddr net.Addr
	reader     io.Reader
	writeMu    sync.Mutex
	done       chan struct{}
	closeOnce  sync.Once
}

func newJumpWSConn(ws *websocket.Conn, remoteAddr net.Addr) *jumpWSConn {
	if remoteAddr == nil {
		remoteAddr = ws.RemoteAddr()
	}
	c := &jumpWSConn{
		ws:         ws,
		remoteAddr: remoteAddr,
		done:       make(chan struct{}),
	}
	ws.SetReadLimit(maxWSMessageSize)
	_ = ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		return ws.SetReadDeadline(time.Now().Add(pongWait))
	})
	go func() {
		ticker := time.NewTicker(pingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-c.done:
				return
			case <-ticker.C:
				if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait)); err != nil {
					_ = c.Close()
					return
				}
			}
		}
	}()
	return c
}

func (c *jumpWSConn) Read(b []byte) (int, error) {
	for {
		if c.reader == nil {
			msgType, r, err := c.ws.NextReader()
			if err != nil {
				return 0, err
			}
			_ = c.ws.SetReadDeadline(time.Now().Add(pongWait))
			if msgType != websocket.BinaryMessage {
				_ = c.ws.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseUnsupportedData, "binary messages only"),
					time.Now().Add(writeWait),
				)
				_ = c.Close()
				return 0, errors.New("unexpected non-binary websocket message")
			}
			c.reader = r
		}
		n, err := c.reader.Read(b)
		if err == io.EOF {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *jumpWSConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *jumpWSConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.ws.Close()
	})
	return err
}

func (c *jumpWSConn) LocalAddr() net.Addr  { return c.ws.LocalAddr() }
func (c *jumpWSConn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *jumpWSConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *jumpWSConn) SetReadDeadline(t time.Time) error { return c.ws.SetReadDeadline(t) }
func (c *jumpWSConn) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.SetWriteDeadline(t)
}

func (s *Server) handleJumpWebSocket(w http.ResponseWriter, req *http.Request) {
	wsConn, err := s.upgrader.Upgrade(w, req, nil)
	if err != nil {
		s.logger.Printf("websocket upgrade failed for jump host: %v", err)
		return
	}
	defer wsConn.Close()
	remoteAddr := s.jumpHost.resolveClientAddr(req, wsConn.RemoteAddr())
	s.jumpHost.serveWebSocket(req.Context(), wsConn, remoteAddr)
}
