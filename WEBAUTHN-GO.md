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
	case KeyAlgoSKECDSA256, CertAlgoSKECDSA256v01, KeyAlgoSKED25519, CertAlgoSKED25519v01:
		out.Rest = in
		return out, nil, ok
	}

	return out, in, ok
```

Because `"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"` is missing from the `switch`, `parseSignatureBody` returns the trailing `flags || counter || origin || clientData || extensions` bytes as `trailing` to `parseSignature`, which rejects the signature (`if !ok || len(trailing) > 0`).

As a result:
- `ssh.Server` cannot parse `SSH_MSG_USERAUTH_REQUEST` packets containing a `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signature.
- `ssh.ParsePublicKey` / `ssh.ParseAuthorizedKey` cannot parse a certificate whose CA signature (`cert.Signature`) uses `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`.

### 2. Signature Verification Fails (`ssh/keys.go`: `(*skECDSAPublicKey).Verify`)

`(*skECDSAPublicKey).Verify` rejects any signature whose `Format` is not literally `KeyAlgoSKECDSA256` (`"sk-ecdsa-sha2-nistp256@openssh.com"`), and only implements the non-WebAuthn digest calculation:

```go
func (k *skECDSAPublicKey) Verify(data []byte, sig *Signature) error {
	if sig.Format != k.Type() {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}
	...
	var skf skFields
	if err := Unmarshal(sig.Rest, &skf); err != nil {
		return err
	}
```

Even if `parseSignatureBody` allowed the signature through, `(*skECDSAPublicKey).Verify` would fail on both `sig.Format != k.Type()` and `Unmarshal(sig.Rest, &skf)`.

### 3. Server Algorithm Compatibility Checks Reject WebAuthn Signatures (`ssh/common.go` & `ssh/server.go`)

In `ssh/server.go`, `connection.serverAuthenticate` validates the algorithm name in `SSH_MSG_USERAUTH_REQUEST` and compares the selected algorithm to the signature format via `isAlgoCompatible`:

```go
func isAlgoCompatible(algo, sigFormat string) bool {
	if isRSA(algo) && isRSA(sigFormat) {
		return true
	}
	// Standard case: the underlying algorithm must match the signature format.
	return underlyingAlgo(algo) == sigFormat
}
```

When a client authenticates with an `sk-ecdsa-sha2-nistp256@openssh.com` public key or an `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` certificate and produces a signature with `sig.Format == "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"`, `serverAuthenticate` rejects the authentication attempt in three places:

1. `!slices.Contains(config.PublicKeyAuthAlgorithms, sig.Format)` fails because `SigAlgoWebAuthnSKECDSA256` is not in `supportedPubKeyAuthAlgos` / `defaultPubKeyAuthAlgos`.
2. `isAlgoCompatible(algo, sig.Format)` returns `false` because `underlyingAlgo(algo)` is `KeyAlgoSKECDSA256` while `sig.Format` is `"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"`.
3. If a client sets `algo = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"` in `SSH_MSG_USERAUTH_REQUEST` for a plain `sk-ecdsa-sha2-nistp256@openssh.com` public key, `!slices.Contains(algorithmsForKeyFormat(pubKey.Type()), algo)` also fails.

### 4. Public Key Parsing Rejects the `webauthn-sk-*` Alias (`ssh/keys.go`: `parsePubKey`)

OpenSSH's `sshkey_from_blob` accepts `"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"` in public key blobs and authorized_keys files as an alias for `KEY_ECDSA_SK` (`"sk-ecdsa-sha2-nistp256@openssh.com"`). In contrast, `parsePubKey` in `golang.org/x/crypto/ssh/keys.go` only matches `KeyAlgoSKECDSA256` and returns `ssh: unknown key algorithm: webauthn-sk-ecdsa-sha2-nistp256@openssh.com`.

---

## Recommended Upstream Solution for `golang.org/x/crypto/ssh`

### 1. Define the Signature Algorithm Constant and Register It (`ssh/common.go`)

Add the algorithm constant:

```go
const SigAlgoWebAuthnSKECDSA256 = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
```

Include `SigAlgoWebAuthnSKECDSA256` in `supportedPubKeyAuthAlgos`, `defaultPubKeyAuthAlgos`, `hashFunc`, `algorithmsForKeyFormat`, and `keyFormatForAlgorithm`:

```go
	supportedPubKeyAuthAlgos = []string{
		KeyAlgoED25519,
		KeyAlgoSKED25519,
		KeyAlgoSKECDSA256,
		SigAlgoWebAuthnSKECDSA256,
		KeyAlgoECDSA256,
		KeyAlgoECDSA384,
		KeyAlgoECDSA521,
		KeyAlgoRSASHA256,
		KeyAlgoRSASHA512,
	}

	defaultPubKeyAuthAlgos = []string{
		KeyAlgoED25519,
		KeyAlgoSKED25519,
		KeyAlgoSKECDSA256,
		SigAlgoWebAuthnSKECDSA256,
		KeyAlgoECDSA256,
		KeyAlgoECDSA384,
		KeyAlgoECDSA521,
		KeyAlgoRSASHA256,
		KeyAlgoRSASHA512,
		KeyAlgoRSA,
		InsecureKeyAlgoDSA,
	}
```

```go
func hashFunc(format string) (crypto.Hash, error) {
	switch format {
	case KeyAlgoRSASHA256, KeyAlgoECDSA256, KeyAlgoSKED25519, KeyAlgoSKECDSA256, SigAlgoWebAuthnSKECDSA256:
		return crypto.SHA256, nil
	...
```

```go
func algorithmsForKeyFormat(keyFormat string) []string {
	switch keyFormat {
	case KeyAlgoRSA:
		return []string{KeyAlgoRSASHA256, KeyAlgoRSASHA512, KeyAlgoRSA}
	case CertAlgoRSAv01:
		return []string{CertAlgoRSASHA256v01, CertAlgoRSASHA512v01, CertAlgoRSAv01}
	case KeyAlgoSKECDSA256:
		return []string{KeyAlgoSKECDSA256, SigAlgoWebAuthnSKECDSA256}
	default:
		return []string{keyFormat}
	}
}

func keyFormatForAlgorithm(sigAlgo string) string {
	switch sigAlgo {
	case KeyAlgoRSA, KeyAlgoRSASHA256, KeyAlgoRSASHA512:
		return KeyAlgoRSA
	case CertAlgoRSAv01, CertAlgoRSASHA256v01, CertAlgoRSASHA512v01:
		return CertAlgoRSAv01
	case KeyAlgoSKECDSA256, SigAlgoWebAuthnSKECDSA256:
		return KeyAlgoSKECDSA256
	...
```

### 2. Preserve `sig.Rest` When Unmarshaling WebAuthn Signatures (`ssh/certs.go`)

In `parseSignatureBody`:

```go
	switch out.Format {
	case KeyAlgoSKECDSA256, SigAlgoWebAuthnSKECDSA256, CertAlgoSKECDSA256v01, KeyAlgoSKED25519, CertAlgoSKED25519v01:
		out.Rest = in
		return out, nil, ok
	}
```

### 3. Allow `SigAlgoWebAuthnSKECDSA256` for `KeyAlgoSKECDSA256` Keys and Certificates (`ssh/server.go`)

In `isAlgoCompatible`:

```go
func isAlgoCompatible(algo, sigFormat string) bool {
	if isRSA(algo) && isRSA(sigFormat) {
		return true
	}
	if (underlyingAlgo(algo) == KeyAlgoSKECDSA256 || algo == SigAlgoWebAuthnSKECDSA256) &&
		(sigFormat == KeyAlgoSKECDSA256 || sigFormat == SigAlgoWebAuthnSKECDSA256) {
		return true
	}
	// Standard case: the underlying algorithm must match the signature format.
	return underlyingAlgo(algo) == sigFormat
}
```

### 4. Support WebAuthn Verification in `(*skECDSAPublicKey).Verify` (`ssh/keys.go`)

Update `(*skECDSAPublicKey).Verify` to handle `sig.Format == SigAlgoWebAuthnSKECDSA256` per OpenSSH's `PROTOCOL.u2f` and `ssh-ecdsa-sk.c` (`webauthn_check_prepare_hash`), while preserving `flagUserPresence` enforcement:

```go
func (k *skECDSAPublicKey) Verify(data []byte, sig *Signature) error {
	if sig.Format != KeyAlgoSKECDSA256 && sig.Format != SigAlgoWebAuthnSKECDSA256 {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}
	hash, err := hashFunc(sig.Format)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write([]byte(k.application))
	appDigest := h.Sum(nil)

	var ecSig struct {
		R *big.Int
		S *big.Int
	}
	if err := Unmarshal(sig.Blob, &ecSig); err != nil {
		return err
	}

	var flags byte
	var counter uint32
	var extensions []byte
	var messageDigest []byte

	switch sig.Format {
	case KeyAlgoSKECDSA256:
		var skf skFields
		if err := Unmarshal(sig.Rest, &skf); err != nil {
			return err
		}
		flags = skf.Flags
		counter = skf.Counter
		h.Reset()
		h.Write(data)
		messageDigest = h.Sum(nil)

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
		flags = waSig.Flags
		counter = waSig.Counter
		extensions = []byte(waSig.Extensions)
		h.Reset()
		h.Write([]byte(waSig.ClientData))
		messageDigest = h.Sum(nil)
	}

	if flags&flagUserPresence == 0 && !k.noTouchRequired {
		return errSKMissingUserPresence
	}

	blob := struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		Extensions        []byte `ssh:"rest"`
		MessageDigest     []byte `ssh:"rest"`
	}{
		appDigest,
		flags,
		counter,
		extensions,
		messageDigest,
	}

	original := Marshal(blob)

	h.Reset()
	h.Write(original)
	digest := h.Sum(nil)

	if ecdsa.Verify((*ecdsa.PublicKey)(&k.PublicKey), digest, ecSig.R, ecSig.S) {
		return nil
	}
	return errors.New("ssh: signature did not verify")
}
```

Where `verifyWebAuthnClientData` validates (matching OpenSSH's `webauthn_check_prepare_hash`):
1. `(flags & 0x40) == 0` (the WebAuthn `AT` / AttestedCredentialData flag must not be set in an assertion).
2. `((flags & 0x80) != 0) == (len(extensions) != 0)` (the WebAuthn `ED` / ExtensionData flag must match whether `extensions` is non-empty).
3. `origin` starts with `"https://"` or `"http://"` and contains no `"` characters.
4. `clientData` begins with `{"type":"webauthn.get","challenge":"<base64url(data)>","origin":"<origin>"` followed immediately by `}` or `,`, and is a valid JSON object in which `"crossOrigin"` is not `true`.

### 5. (Optional) Accept `SigAlgoWebAuthnSKECDSA256` in `parsePubKey` (`ssh/keys.go`)

With Section 1's `keyFormatForAlgorithm` change in place, [`parsePubKey`](file:///home/robin/go/pkg/mod/golang.org/x/crypto@v0.58.0/ssh/keys.go#L102-L105) already returns a clear diagnostic error if handed a legacy public key blob labeled `"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"`:

```text
ssh: signature algorithm "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" isn't a key format; key is malformed and should be re-encoded with type "sk-ecdsa-sha2-nistp256@openssh.com"
```

If compatibility with legacy keys exported with the `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` key type prefix is also desired (matching `ssh-keygen`), `parsePubKey` can accept `SigAlgoWebAuthnSKECDSA256` as an alias for `parseSKECDSA`:

```go
	case KeyAlgoSKECDSA256, SigAlgoWebAuthnSKECDSA256:
		return parseSKECDSA(in)
```

(If `ParseAuthorizedKey` and `ParseKnownHosts` should also accept text lines whose first field is `"webauthn-sk-ecdsa-sha2-nistp256@openssh.com"`, their `pubKey.Type() != algo` check can additionally allow `algo == SigAlgoWebAuthnSKECDSA256 && pubKey.Type() == KeyAlgoSKECDSA256`.)

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
