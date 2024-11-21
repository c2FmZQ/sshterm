# SSH Term

SSH Term is an SSH client written in GO, compiled to WASM, that runs entirely in your web browser.

It uses [xterm.js](https://xtermjs.org/) as terminal, and [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh) for the SSH client functionality.

The connection between the client and the server uses [WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket) and [tlsproxy](https://github.com/c2FmZQ/tlsproxy).

![screenshot](https://github.com/c2FmZQ/sshterm/blob/main/images/sshterm.png "SSH Term")

Supported features:

* [x] Connect to any WebSocket endpoints configured in tlsproxy.
* [x] Generate and use SSH keys.
* [x] Keyboard interactive authentication.
* [x] In-memory SSH agent and agent forwarding.

Not implemented:

* [ ] File transfers.
* [ ] Port forwarding.
* [ ] Certificates.
* [ ] Security keys.

## How to install

Check out the repo and build everything:

```bash
git clone https://github.com/c2FmZQ/sshterm.git
cd sshterm
./build.sh
```

If all goes well, all the needed files will be in the `docroot` directory.

```
$ ls docroot/
index.html  ssh.js  ssh.wasm  wasm_exec.js  xterm.css  xterm.js
```

## Configure tlsproxy

The simplest tlsproxy config looks like this:

```yaml
backends:
  - serverNames:
      - ssh.EXAMPLE.COM
    mode: local
    documentRoot: /path/to/docroot/

webSockets:
  - endpoint: wss://ssh.EXAMPLE.COM/myserver
    address: 192.168.0.100:22
```

## Open the app

Open `https://ssh.EXAMPLE.COM/` in a browser. It should open a terminal.

The first time you connect, the server endpoint must be configured when the `ep` command:

```bash
ep add myserver wss://ssh.EXAMPLE.COM/myserver
```

Then, you can SSH to your server with:

```bash
ssh username@myserver
```

:warning: Replace _ssh.EXAMPLE.COM_, _myserver_, _/path/to/docroot/_, ... with something appropriate for your environment.

