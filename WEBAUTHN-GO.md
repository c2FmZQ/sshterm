# `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` Support in `golang.org/x/crypto/ssh`

## Background: OpenSSH Specification

OpenSSH defines FIDO2/U2F security key support in [`PROTOCOL.u2f`](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.u2f?annotate=HEAD) and certificate formats in [`PROTOCOL.certkeys`](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD).

For ECDSA P-256 security keys, OpenSSH uses three wire identifiers with distinct roles in its `keytypes` table (`sshkey.c`):

| Role | Wire Identifier | OpenSSH `sshkey_types` | `cert` | `sigonly` |
| :--- | :--- | :--- | :---: | :---: |
| **Plain Public Key** (`ssh -Q key-plain`) | `sk-ecdsa-sha2-nistp256@openssh.com` | `KEY_ECDSA_SK` | `0` | `0` |
| **Certificate** (`ssh -Q key-cert`) | `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` | `KEY_ECDSA_SK_CERT` | `1` | `0` |
| **WebAuthn Signature** (`ssh -Q key-sig`) | `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` | `KEY_ECDSA_SK` | `0` | `1` |

Key protocol properties:

1. **`webauthn-sk-ecdsa-sha2-nistp256@openssh.com` is a signature-only algorithm (`sigonly = 1`)**, analogous to how `rsa-sha2-256` and `rsa-sha2-512` are signature algorithms for `ssh-rsa` (`KEY_RSA`) keys.
2. **Public keys and certificates always use `sk-ecdsa-sha2-nistp256@openssh.com` and `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com`**. There is no `webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` certificate type. (If OpenSSH's `sshkey` parser is given a public key labeled `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`, it maps it to `KEY_ECDSA_SK` and canonicalizes the public key type to `sk-ecdsa-sha2-nistp256@openssh.com`.)
3. **Both signature formats are valid for `KEY_ECDSA_SK` and `KEY_ECDSA_SK_CERT` keys**:
   - Standard CTAP2/U2F signature (`sk-ecdsa-sha2-nistp256@openssh.com`):
     ```text
     string    "sk-ecdsa-sha2-nistp256@openssh.com"
     string    ecdsa_signature (mpint r, mpint s)
     byte      flags
     uint32    counter
     ```
     where the ECDSA P-256 signature is computed over:
     $$\text{SHA-256}\big(\text{SHA-256}(\text{application}) \parallel \text{flags} \parallel \text{counter} \parallel \text{SHA-256}(\text{message})\big)$$
   - Browser WebAuthn signature (`webauthn-sk-ecdsa-sha2-nistp256@openssh.com`):
     ```text
     string    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
     string    ecdsa_signature (mpint r, mpint s)
     byte      flags
     uint32    counter
     string    origin
     string    clientData
     string    extensions
     ```
     where `clientData` is the WebAuthn `clientDataJSON` string containing `"type":"webauthn.get"`, `"challenge":"<base64url(message)>"`, and `"origin":"<origin>"`, and the ECDSA P-256 signature is computed over:
     $$\text{SHA-256}\big(\text{SHA-256}(\text{application}) \parallel \text{flags} \parallel \text{counter} \parallel \text{extensions} \parallel \text{SHA-256}(\text{clientData})\big)$$

---

## Current Limitations in `golang.org/x/crypto/ssh`

As of `golang.org/x/crypto v0.58.0`, the `ssh` package defines `KeyAlgoSKECDSA256 = "sk-ecdsa-sha2-nistp256@openssh.com"` and `CertAlgoSKECDSA256v01 = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"`, but has **no awareness of `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`**.

This causes four distinct failures in `golang.org/x/crypto/ssh`:

### 1. Signature Wire Unmarshaling Fails (`ssh/certs.go`: `parseSignatureBody`)

`parseSignatureBody` parses an SSH wire signature into an `*ssh.Signature{Format, Blob, Rest}` and checks that no trailing bytes remain unless the format is specifically known to carry `Rest` data:

```go
	switch out.Format {
	case KeyAlgoSKECDSA256, KeyAlgoSKED25519:
		out.Rest = in
		return out, nil, true
	}

	if len(in) > 0 {
		return nil, nil, false
	}
```

Because `"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"` is missing from the `switch`, `parseSignatureBody` sees the trailing `flags || counter || origin || clientData || extensions` bytes in `in` and fails (`return nil, nil, false`).

As a result:
- `ssh.Server` cannot parse `SSH_MSG_USERAUTH_REQUEST` packets containing a `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signature.
- `ssh/agent` client (`agentClient.Sign`) cannot parse `SSH_AGENT_SIGN_RESPONSE` packets containing a `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signature.
- `ssh.ParsePublicKey` / `ssh.ParseAuthorizedKey` cannot parse a certificate whose CA signature (`cert.Signature`) uses `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`.

### 2. Signature Verification Fails (`ssh/keys.go`: `(*skECDSAPublicKey).Verify`)

`(*skECDSAPublicKey).Verify` rejects any signature whose `Format` is not literally `KeyAlgoSKECDSA256` (`"sk-ecdsa-sha2-nistp256@openssh.com"`), and only implements the non-WebAuthn digest calculation:

```go
func (k *skECDSAPublicKey) Verify(data []byte, sig *Signature) error {
	if sig.Format != k.Type() {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}
	...
	var skSig struct {
		Flags   byte
		Counter uint32
	}
	if err := Unmarshal(sig.Rest, &skSig); err != nil {
		return err
	}
```

Even if `parseSignatureBody` allowed the signature through, `(*skECDSAPublicKey).Verify` would fail on both `sig.Format != k.Type()` and `Unmarshal(sig.Rest, &skSig)`.

### 3. Server Algorithm Compatibility Checks Reject WebAuthn Signatures (`ssh/common.go` & `ssh/server.go`)

In `ssh/server.go`, `ServerConn.userAuth` validates the algorithm name in `SSH_MSG_USERAUTH_REQUEST` and compares the key algorithm to the signature format via `isAlgoCompatible`:

```go
func isAlgoCompatible(keyAlgo, sigAlgo string) bool {
	if keyAlgo == sigAlgo {
		return true
	}
	if underlyingAlgo(keyAlgo) == KeyAlgoRSA && isRSASigAlgo(sigAlgo) {
		return true
	}
	if certKeyAlgo, ok := certKeyAlgoNames[keyAlgo]; ok {
		return isAlgoCompatible(certKeyAlgo, sigAlgo)
	}
	return false
}
```

When a client authenticates with an `sk-ecdsa-sha2-nistp256@openssh.com` public key or an `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` certificate and produces a signature with `sig.Format == "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"`, `isAlgoCompatible(pubKey.Type(), sig.Format)` returns `false`, causing `ssh.Server` to reject the authentication attempt with:

```text
ssh:avas: key type "sk-ecdsa-sha2-nistp256@openssh.com" not compatible with signature type "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
```

Additionally, if an OpenSSH client sends `Algoname: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"` in `SSH_MSG_USERAUTH_REQUEST`, `ServerConn` rejects it unless `"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"` is included in `supportedPubKeyAuthAlgos` (`ssh/common.go`).

### 4. Public Key Parsing Rejects the `webauthn-sk-*` Alias (`ssh/keys.go`: `parsePubKey`)

OpenSSH's `sshkey_from_blob` accepts `"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"` in public key blobs and authorized_keys files as an alias for `KEY_ECDSA_SK` (`"sk-ecdsa-sha2-nistp256@openssh.com"`). In contrast, `parsePubKey` in `golang.org/x/crypto/ssh/keys.go` only matches `KeyAlgoSKECDSA256` and returns `ssh: unknown key algorithm: webauthn-sk-ecdsa-sha2-nistp256@openssh.com`.

---

## Recommended Upstream Solution for `golang.org/x/crypto/ssh`

### 1. Define the Signature Algorithm Constant and Register It (`ssh/common.go`)

Add the algorithm constant:

```go
const SigAlgoWebAuthnSKECDSA256 = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
```

Include `SigAlgoWebAuthnSKECDSA256` in `supportedPubKeyAuthAlgos` and map it to `KeyAlgoSKECDSA256` in `underlyingAlgo`:

```go
func underlyingAlgo(algo string) string {
	if caAlgo, ok := certKeyAlgoNames[algo]; ok {
		algo = caAlgo
	}
	switch algo {
	case KeyAlgoRSASHA256, KeyAlgoRSASHA512:
		return KeyAlgoRSA
	case SigAlgoWebAuthnSKECDSA256:
		return KeyAlgoSKECDSA256
	default:
		return algo
	}
}
```

### 2. Preserve `sig.Rest` When Unmarshaling WebAuthn Signatures (`ssh/certs.go`)

In `parseSignatureBody`:

```go
	switch out.Format {
	case KeyAlgoSKECDSA256, SigAlgoWebAuthnSKECDSA256, KeyAlgoSKED25519:
		out.Rest = in
		return out, nil, true
	}
```

### 3. Allow `SigAlgoWebAuthnSKECDSA256` for `KeyAlgoSKECDSA256` Keys and Certificates (`ssh/server.go`)

In `isAlgoCompatible`:

```go
func isAlgoCompatible(keyAlgo, sigAlgo string) bool {
	if keyAlgo == sigAlgo {
		return true
	}
	if underlyingAlgo(keyAlgo) == KeyAlgoRSA && isRSASigAlgo(sigAlgo) {
		return true
	}
	if underlyingAlgo(keyAlgo) == KeyAlgoSKECDSA256 &&
		(sigAlgo == KeyAlgoSKECDSA256 || sigAlgo == SigAlgoWebAuthnSKECDSA256) {
		return true
	}
	if certKeyAlgo, ok := certKeyAlgoNames[keyAlgo]; ok {
		return isAlgoCompatible(certKeyAlgo, sigAlgo)
	}
	return false
}
```

### 4. Support WebAuthn Verification in `(*skECDSAPublicKey).Verify` (`ssh/keys.go`)

Update `(*skECDSAPublicKey).Verify` to handle `sig.Format == SigAlgoWebAuthnSKECDSA256` per OpenSSH's `PROTOCOL.u2f` and `ssh-ecdsa-sk.c` (`webauthn_check_prepare_hash`):

```go
func (k *skECDSAPublicKey) Verify(data []byte, sig *Signature) error {
	if sig.Format != KeyAlgoSKECDSA256 && sig.Format != SigAlgoWebAuthnSKECDSA256 {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}

	var ecSig struct {
		R *big.Int
		S *big.Int
	}
	if err := Unmarshal(sig.Blob, &ecSig); err != nil {
		return err
	}

	h := ecHash(k.Curve)
	n := h.New()
	n.Write([]byte(k.application))
	appDigest := n.Sum(nil)

	blob := h.New()
	blob.Write(appDigest)

	switch sig.Format {
	case KeyAlgoSKECDSA256:
		var skSig struct {
			Flags   byte
			Counter uint32
		}
		if err := Unmarshal(sig.Rest, &skSig); err != nil {
			return err
		}
		n.Reset()
		n.Write(data)
		dataDigest := n.Sum(nil)

		var buf [5]byte
		buf[0] = skSig.Flags
		binary.BigEndian.PutUint32(buf[1:], skSig.Counter)
		blob.Write(buf[:])
		blob.Write(dataDigest)

	case SigAlgoWebAuthnSKECDSA256:
		var waSig struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}
		if err := Unmarshal(sig.Rest, &waSig); err != nil {
			return err
		}
		if err := verifyWebAuthnClientData(waSig.Flags, waSig.Origin, waSig.ClientData, waSig.Extensions, data); err != nil {
			return err
		}
		n.Reset()
		n.Write([]byte(waSig.ClientData))
		clientDataDigest := n.Sum(nil)

		var buf [5]byte
		buf[0] = waSig.Flags
		binary.BigEndian.PutUint32(buf[1:], waSig.Counter)
		blob.Write(buf[:])
		blob.Write([]byte(waSig.Extensions))
		blob.Write(clientDataDigest)
	}

	if ecdsa.Verify(&k.PublicKey, blob.Sum(nil), ecSig.R, ecSig.S) {
		return nil
	}
	return errors.New("ssh: signature did not verify")
}
```

Where `verifyWebAuthnClientData` validates (matching OpenSSH's `webauthn_check_prepare_hash`):
1. `(flags & 0x40) == 0` (the WebAuthn `AT` / AttestedCredentialData flag must not be set in an assertion).
2. `((flags & 0x80) != 0) == (len(extensions) != 0)` (the WebAuthn `ED` / ExtensionData flag must match whether `extensions` is non-empty).
3. `clientData` is a valid WebAuthn `clientDataJSON` object with:
   - `"type": "webauthn.get"`
   - `"challenge"` equal to `base64.RawURLEncoding.EncodeToString(data)`
   - `"origin"` non-empty and equal to `origin`.

### 5. (Optional) Accept `SigAlgoWebAuthnSKECDSA256` in `parsePubKey` (`ssh/keys.go`)

For compatibility with keys exported with the `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` key type prefix (matching `ssh-keygen`), allow `SigAlgoWebAuthnSKECDSA256` in `parsePubKey` as an alias for `parseSKECDSAPubKey`:

```go
	case KeyAlgoSKECDSA256, SigAlgoWebAuthnSKECDSA256:
		return parseSKECDSAPubKey(in)
```

---

## How `sshterm` Handles This Today

In `sshterm` (`internal/webauthnsk`), `Key` separates the public key type from the signature format:

1. **`(*Key).Type()` and `(*Key).Marshal()`** use `ssh.KeyAlgoSKECDSA256` (`"sk-ecdsa-sha2-nistp256@openssh.com"`).
2. **`(*Key).Sign()`** returns `&ssh.Signature{Format: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com", ...}`.
3. **`UnmarshalPublic()`** accepts both `"sk-ecdsa-sha2-nistp256@openssh.com"` and legacy `"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"` public key blobs and normalizes `Key.Type()` to `"sk-ecdsa-sha2-nistp256@openssh.com"`.

With this separation:
- **Certificate Issuance Works**: Any CA using `golang.org/x/crypto/ssh` (such as `tlsproxy`) or OpenSSH `ssh-keygen -s` can parse the public key with `ssh.ParseAuthorizedKey` and sign an `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` certificate with `(*ssh.Certificate).SignCert`.
- **Certificate Import & Validation Work**: `cert.Key.Marshal()` matches `pub.Marshal()` byte-for-byte.
- **Authentication to OpenSSH `sshd` Works**: Both plain `sk-ecdsa-sha2-nistp256@openssh.com` keys and `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` certificates authenticate against OpenSSH `sshd` using `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signatures.
- **SSH Agent Forwarding (`ssh -A`) Works**: `golang.org/x/crypto/ssh/agent` can parse the public key in `SSH_AGENTC_SIGN_REQUEST` messages.

The only remaining scenario that requires the upstream `golang.org/x/crypto/ssh` changes above is **verifying** a `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signature inside a Go SSH server (`ssh.NewServerConn` / `ssh.CertChecker`).
