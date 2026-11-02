# `sshterm-server` Jump Host `authorized_keys` Guide

When `sshterm-server` is started with `--authorized-keys <file>`, it enables a built-in SSH jump host exposed over WebSocket at `/_ws/jump`, adds the `jump` endpoint and its host public key to `/config.json`, and sets `"jumpHosts": "jump"` in `/config.json` (unless `jumpHosts` is already set in a base `--config` file). The endpoint name `jump` is reserved when `--authorized-keys` is set.

This document explains how `sshterm-server` evaluates `authorized_keys` and provides practical examples for configuring access control by key, certificate, and destination.

---

## Context & Design Model

1. **Forwarding-Only (`direct-tcpip` Only)**
   The built-in jump host does not allocate PTYs, run shells or commands, or serve SFTP. It only accepts SSH `direct-tcpip` channel requests (`ssh -J jump ...` or default `jumpHosts`, up to 32 concurrent channels per SSH connection) to tunnel SSH connections to downstream target hosts.

2. **Default-Deny Destination Policy (`permitopen` Required)**
   Every active line in `authorized_keys` must explicitly declare which `host[:port]` destinations it may reach via `permitopen="..."`. Any line without an effective `permitopen` grants access to **no destinations** and is skipped during authentication (if a key or certificate matches only such lines, SSH authentication to the jump host fails).

3. **SSH Username Is Ignored on the Jump Host**
   When a user runs `ssh root@db.prod.internal` in `sshterm` using the default jump host `jump`, the SSH connection to `jump` uses `root` as the SSH transport username (`c.User()`). Meanwhile, SSH Certificate Authorities (such as [`tlsproxy`](https://github.com/c2FmZQ/tlsproxy)) issue user certificates whose principals are user identities—typically email addresses like `alice@example.com`.
   Because `authorized_keys` on `sshterm-server` is a single global access-control file rather than a per-OS-user `~/.ssh/authorized_keys` file:
   - The SSH login username on the jump host is ignored.
   - Public keys are matched directly against non-CA lines in `authorized_keys`.
   - User certificates are matched against `cert-authority` lines by CA key **and** by matching the certificate's `ValidPrincipals` against the mandatory `principals="..."` option on the line.

4. **Additive Multi-Rule Matching**
   If a user's public key or certificate matches multiple lines in `authorized_keys`, the user is granted the **union** of all `permitopen` rules from every matching line. This lets you layer role-based or group-based access rules cleanly across multiple lines.

5. **Literal Destination Matching (No Implicit DNS Lookups)**
   `permitopen` rules are matched directly against the literal destination hostname or IP address requested by the client (case-insensitively for hostnames):
   - Hostname and hostname-wildcard rules (e.g., `db.internal:22`, `*.dev.example.com:22`) match requested hostnames.
   - IP address and CIDR rules (e.g., `10.0.0.0/8:22`, `[2001:db8::/32]:22`) match requested IP literals.
   - The universal wildcard `*` (e.g., `*:22`, `*:*`) matches both hostnames and IP addresses.

6. **Strict Startup Validation**
   `sshterm-server` loads and validates the entire `authorized_keys` file once at startup. Any syntax error, unknown option, unsupported key type (`ssh-dss` or an SSH certificate used directly in place of a public/CA key), `cert-authority` without `principals`, or invalid `permitopen` pattern causes `sshterm-server` to fail startup immediately with an error message identifying the line number.

---

## Supported Options Reference

All option values (`principals="..."`, `permitopen="..."`) must be enclosed in double quotes (`"`). Inside double quotes, only `\"` and `\\` are valid escape sequences. Unknown options cause `sshterm-server` to fail startup with an error.

| Option | Syntax | Description |
| :--- | :--- | :--- |
| `permitopen` | `permitopen="<spec>[,<spec>...]"` | Grants forwarding access to one or more `host[:port]` destinations. May be specified multiple times on a line or comma-separated inside quotes. |
| `cert-authority` | `cert-authority` | Marks the key on the line as an SSH Certificate Authority (CA) public key used to verify SSH user certificates. Requires `principals="..."`. |
| `principals` | `principals="<pat>[,<pat>...]"` | Required with `cert-authority`. Comma-separated list of principal patterns (supports `*`, `?`, and `[...]` globs via Go's `path.Match`) matched against the certificate's `ValidPrincipals`. |

> **OpenSSH Compatibility / No-Op Options:**
> For compatibility with existing OpenSSH `authorized_keys` entries, `sshterm-server` also parses `port-forwarding`, `no-port-forwarding`, `restrict`, and `permitopen="none"` left-to-right on a line:
> - `port-forwarding` is a no-op (unless re-enabling forwarding after an earlier `restrict` or `no-port-forwarding` on the same line).
> - `restrict` clears any earlier `permitopen` entries on the same line and marks port forwarding as disabled (until a subsequent `port-forwarding` option appears on the same line).
> - `no-port-forwarding` (without a subsequent `port-forwarding` on the same line), or a standalone `permitopen="none"` (without a subsequent `permitopen="..."` on the same line), clears the line's `permitopen` list so the line grants no destinations.

### `permitopen` Target Formats

| Format | Example | Port Behavior | Matches |
| :--- | :--- | :--- | :--- |
| Exact hostname | `permitopen="bastion.example.com:22"` | Explicit port `22` | `bastion.example.com` port `22` |
| Hostname (default port) | `permitopen="bastion.example.com"` | Defaults to `22` | `bastion.example.com` port `22` |
| Hostname wildcard | `permitopen="*.dev.example.com:2222"` | Explicit port `2222` | Any hostname matching `*.dev.example.com` on port `2222` (`*` also matches across `.`) |
| Hostname with any port | `permitopen="app-?.staging.internal:*"` | Any port (`1`–`65535`) | `app-1.staging.internal`, `app-a.staging.internal`, etc. on any port |
| Any host on port 22 | `permitopen="*:22"` or `permitopen="*"` | Port `22` | Any hostname, IPv4, or IPv6 address on port `22` |
| Any host, any port | `permitopen="*:*"` | Any port (`1`–`65535`) | Any hostname, IPv4, or IPv6 address on any port |
| IPv4 address | `permitopen="192.168.1.10:22"` or `permitopen="192.168.1.10"` | Port `22` | Literal IPv4 `192.168.1.10` on port `22` |
| IPv4 CIDR | `permitopen="10.0.0.0/8:22"` or `permitopen="10.0.0.0/8"` | Port `22` | Any literal IPv4 in `10.0.0.0/8` on port `22` |
| IPv6 address | `permitopen="[2001:db8::1]:2222"`, `permitopen="[2001:db8::1]"`, or `permitopen="2001:db8::1"` | `2222` / default `22` | Literal IPv6 `2001:db8::1` |
| IPv6 CIDR | `permitopen="[2001:db8::/32]:*"`, `permitopen="[2001:db8::/32]"`, or `permitopen="2001:db8::/32"` | Any port / default `22` | Any literal IPv6 in `2001:db8::/32` |

> **Notes on Hostnames, Wildcards, and Certificates:**
> - **No IP Wildcards:** IP wildcard patterns such as `10.0.0.*:22` are rejected at startup. Always use CIDR notation (e.g., `10.0.0.0/24:22`) for IP address ranges.
> - **Hostname Rules:** Hostname labels may contain `a-z`, `0-9`, `-`, and `_` (plus `*` and `?` wildcards in patterns), and the top-level label must begin with an ASCII letter (or `*`/`?` wildcard in patterns). Brackets `[...]` are only valid around IPv6 addresses and IPv6 CIDRs.
> - **User Certificate Validation:** Certificates must be SSH user certificates (`ssh.UserCert`) within their `ValidAfter`/`ValidBefore` window, signed with a supported algorithm (`ssh-ed25519`, `ecdsa-sha2-*`, `rsa-sha2-256`, or `rsa-sha2-512`; `ssh-dss` and SHA-1 `ssh-rsa` are rejected).
>   - **Critical Options:** `source-address` is verified against the direct TCP peer of `sshterm-server` (note that behind a reverse proxy, the TCP peer is the proxy's IP). Any other critical option (such as `force-command`) is rejected.
>   - **Extensions:** If a user certificate specifies a non-empty `extensions` map (such as certificates generated by `ssh-keygen`), it must include `permit-port-forwarding`. Certificates with an empty `extensions` map (such as default `tlsproxy` certificates) are treated as permitting port forwarding.
> - **Security Keys (`sk-ecdsa-sha2-nistp256@openssh.com` / `sk-ssh-ed25519@openssh.com`):** Native FIDO2/CTAP2 signatures (`sk-ecdsa-sha2-nistp256@openssh.com` and `sk-ssh-ed25519@openssh.com`) are supported. Browser-generated WebAuthn (`ecdsa-sk`) signatures use `webauthn-sk-ecdsa-sha2-nistp256@openssh.com`, which is not yet supported by `golang.org/x/crypto/ssh` on the server side (see [WEBAUTHN-GO.md](WEBAUTHN-GO.md)).

---

## Examples

### 1. Individual User Public Keys with Specific Hosts and Ports

You can authorize individual SSH public keys (`ssh-ed25519`, `ecdsa-sha2-*`, `sk-ecdsa-sha2-nistp256@openssh.com`, `sk-ssh-ed25519@openssh.com`, `ssh-rsa` with SHA-2 signatures) and restrict each key to specific hosts and ports.

Multiple destinations can be specified either by repeating `permitopen="..."` or by separating targets with commas inside a single `permitopen="..."` option:

```text
# Alice's key: can connect to host1.example.com (default port 22) and host2.example.com on port 2222
permitopen="host1.example.com",permitopen="host2.example.com:2222" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB alice@laptop

# Bob's key: equivalent comma-separated syntax inside a single permitopen option
permitopen="web.internal.example.com:22,db.internal.example.com:2222" ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU= bob@workstation
```

---

### 2. IPv4 and IPv6 Addresses and CIDR Subnets

When users connect to target hosts by IP address (e.g., `ssh admin@10.10.1.50` or `ssh admin@[2001:db8::dead:beef]`), use IP or CIDR `permitopen` rules. Both unbracketed (`2001:db8::1`, `2001:db8::/32`) and bracketed (`[2001:db8::1]`, `[2001:db8::/32]`) IPv6 forms without a port default to port `22`; use brackets (`[ipv6]:port` or `[ipv6/prefix]:port`) when specifying an explicit port or port wildcard `*`:

```text
# Allow port 22 across the 10.0.0.0/8 private network and any port on 192.168.50.10
permitopen="10.0.0.0/8:22,192.168.50.10:*" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC netadmin@ops

# IPv6 examples:
# - [2001:db8:1::/48]:2222 allows port 2222 across the 2001:db8:1::/48 subnet
# - 2001:db8:2::/48 (unbracketed) defaults to port 22
# - [::1]:* allows any port on IPv6 loopback
# - 2001:db8::10 (unbracketed) allows port 22 on a single IPv6 host
permitopen="[2001:db8:1::/48]:2222,2001:db8:2::/48,[::1]:*,2001:db8::10" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD ipv6-admin@ops
```

---

### 3. SSH Certificate Authority (`cert-authority`) with `tlsproxy` Email Principals

When using an SSH CA (such as `tlsproxy`) that issues user certificates with the user's email address as principal, use `cert-authority` together with `principals="..."`.

Because `sshterm-server` evaluates all matching rules additively, you can reuse the **same CA key across multiple lines** to define tiered access by user or domain:

```text
# Tier 1: All @example.com users can reach *.dev.internal on port 22
cert-authority,principals="*@example.com",permitopen="*.dev.internal:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE tlsproxy-user-ca

# Tier 2: Members of the QA team can also reach *.staging.internal on port 22 or 2222
cert-authority,principals="*@qa.example.com,qa-*@example.com",permitopen="*.staging.internal:22,*.staging.internal:2222" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE tlsproxy-user-ca

# Tier 3: Named SREs can reach *.prod.internal on port 22 and the 10.20.0.0/16 prod subnet
cert-authority,principals="alice@example.com,sre-oncall@example.com",permitopen="*.prod.internal:22,10.20.0.0/16:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE tlsproxy-user-ca

# Tier 4: Break-glass administrator can reach any host and port
cert-authority,principals="breakglass-admin@example.com",permitopen="*:*" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE tlsproxy-user-ca
```

In this configuration:
- `bob@example.com` matches **Tier 1** only (`*.dev.internal:22`).
- `qa-lead@example.com` matches **Tier 1** and **Tier 2** (`*.dev.internal:22`, `*.staging.internal:22`, `*.staging.internal:2222`).
- `alice@example.com` matches **Tier 1** and **Tier 3** (`*.dev.internal:22`, `*.prod.internal:22`, `10.20.0.0/16:22`).
- `contractor@external.org` matches no rules and is rejected during SSH authentication.

---

### 4. Complete Production Example

Below is a complete `authorized_keys` file combining a corporate `tlsproxy` CA, a partner CA, and static emergency/automation keys:

```text
# =============================================================================
# Corporate User CA (issued by tlsproxy with user email addresses as principals)
# =============================================================================

# All corporate engineers: access to development hosts on port 22
cert-authority,principals="*@corp.example.com",permitopen="*.dev.corp.example.com:22,dev-bastion.corp.example.com:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE corp-ca

# Database administrators: access to production and staging database clusters
cert-authority,principals="dba-*@corp.example.com,alice@corp.example.com",permitopen="db-*.prod.corp.example.com:22,db-*.staging.corp.example.com:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE corp-ca

# Network & Infrastructure SREs: access to all prod hosts and private IPv4/IPv6 subnets
cert-authority,principals="sre-*@corp.example.com,alice@corp.example.com",permitopen="*.prod.corp.example.com:22,10.0.0.0/8:22,172.16.0.0/12:22,[2001:db8:cafe::/48]:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE corp-ca

# =============================================================================
# Vendor / Partner CA (restricted to a dedicated sandbox environment)
# =============================================================================

cert-authority,principals="*@partner.example.org",permitopen="sandbox-?.partner.corp.example.com:2222" ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfU= partner-ca

# =============================================================================
# Static Public Keys (Emergency & Automation)
# =============================================================================

# Emergency on-call hardware key (FIDO2/CTAP2): unrestricted destination access
permitopen="*:*" sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUAAAAEc3NoOg== oncall-yubikey

# CI/CD deployment key: restricted to staging web servers on port 22
permitopen="web-*.staging.corp.example.com:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF cicd-deploy
```

### Starting `sshterm-server` with This File

```bash
./sshterm-server \
  --addr 127.0.0.1:8080 \
  --authorized-keys /etc/sshterm/authorized_keys \
  --host-key /etc/sshterm/jump_host_ed25519_key
```
