# SSH Term

SSH Term is a full-featured SSH client that runs entirely in your web browser.

The core client is written in Go and compiled to WebAssembly (WASM), allowing it to run client-side. It uses [xterm.js](https://xtermjs.org/) for the terminal interface and connects to standard SSH servers through a [tlsproxy](https://github.com/c2FmZQ/tlsproxy) WebSocket proxy.

![screenshot](https://github.com/c2FmZQ/sshterm/blob/main/images/sshterm.png "SSH Term")

## Features

*   Connect to any SSH server, including via jump hosts.
*   SFTP client with streaming uploads and downloads.
*   In-memory SSH agent and agent forwarding.
*   Public key authentication with certificates.
*   WebAuthn support for security keys and passkeys.
*   Generate, import, and export SSH keys (rsa, ecdsa, ecdsa-sk, ed25519).
*   Backup and restore configuration and keys.
*   Keyboard-interactive authentication.
*   Persistence of data to browser local storage.

## Getting Started

You can get started by either downloading a pre-built release or by building the project from source.

### Installation

**Option 1: Download a Release**

You can find pre-packaged releases on the [releases page](https://github.com/c2FmZQ/sshterm/releases). Download the `sshterm-docroot-${VERSION}.tar.gz` file, which contains all the necessary files ready to be deployed.

**Option 2: Build from Source**

If you have Go and Node.js installed, you can build the project yourself:

```bash
git clone https://github.com/c2FmZQ/sshterm.git
cd sshterm
./build.sh
```

After the build completes, the `docroot/` directory will contain all the required application files.

### Configuration

SSH Term connects to SSH servers via a WebSocket proxy. You will need to configure `tlsproxy` to forward connections.

1.  **Configure `tlsproxy`**

    Create a `tlsproxy` configuration file. Here is a minimal example:

    ```yaml
    backends:
      - serverNames:
          - ssh.example.com
        mode: local
        documentRoot: /path/to/your/docroot/

    webSockets:
      - endpoint: wss://ssh.example.com/myserver
        address: 192.168.0.100:22
    ```
    *Update the `serverNames`, `documentRoot`, `endpoint`, and `address` to match your environment.*

2.  **Configure the Endpoint in the App**

    Open the SSH Term URL in your browser (e.g., `https://ssh.example.com`). The first time you use it, you must configure the server endpoint with the `ep` command:

    ```console
    ep add myserver wss://ssh.example.com/myserver
    ```
    The URL can also be a relative path, e.g. `./myserver`.
    Alternatively, you can provide this configuration in a `config.json` file in the `docroot` directory.

### Using `config.json`

As an alternative to configuring endpoints manually with the `ep` command, you can create a `config.json` file in the `docroot/` directory to pre-configure the application. This is useful for deploying SSH Term with a default set of connections and settings.

Copy `config.json.example` to `config.json` and modify it to fit your needs.

Here is an example with explanations of the fields:

```json
{
	"persist": false,
	"theme": "dark",
	"certificateAuthorities": [{
		"name": "my_ca_example_com",
		"publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOO4jC9AcVsCOfapTGboTKOuMbil0Z8jKnt3pb3M8eqi",
		"hostnames": [ "*.example.com" ]
	}],
	"endpoints": [{
		"name": "myserver.example.com",
		"url": "./websocket"
	}],
	"hosts": [{
		"name": "myserver.example.com",
		"key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINqyuT/sFvC37z1qMY0may2TMKqg2nxdjxBxyfXeieot"
	}],
	"generateKeys": [{
		"name": "default",
		"type": "ed25519",
		"identityProvider": "./cert",
		"addToAgent": true
	}],
	"autoConnect": {
		"username": "username",
		"hostname": "myserver.example.com",
		"identity": "default",
		"command": "uname -a",
		"forwardAgent": false
	}
}
```

*   `endpoints`: Pre-defines WebSocket endpoints. This is the same as using the `ep add` command.
*   `hosts`: Pre-defines known host keys to trust.
*   `certificateAuthorities`: Specifies trusted CAs for host certificates.
*   `generateKeys`: Can be used to generate a new SSH key on first use.
*   `autoConnect`: Automatically connect to a specified host on startup.
*   `persist`: Controls whether settings are saved to the browser's local storage.
*   `theme`: Sets the visual theme (e.g., "dark", "light").

## Usage

This section explains how to use the SSH Term application, from initial setup to a complete command reference.

### Quick Start

Follow these steps to get connected for the first time.

1.  **Configure the Server Endpoint**

    Before you can connect, you must tell SSH Term how to reach your SSH server via its WebSocket proxy. Use the `ep add` command to add a new endpoint.

    ```console
    ep add my-server wss://ssh.example.com/my-server
    ```
    Replace `my-server` with a name of your choice and the URL with the one provided by your `tlsproxy` configuration. The URL can be absolute or relative.

2.  **Generate an SSH Key**

    Next, generate a new SSH key to use for authentication. The `keys generate` command creates a new key and adds it to the local keystore.

    ```console
    keys generate -t ed25519 my-key
    ```
    This creates a new `ed25519` key named `my-key`. You can see your new key by running `keys list`. Don't forget to add the public key to your server's `~/.ssh/authorized_keys` file.

3.  **Connect to Your Server**

    Now you can connect to your server using the `ssh` command.

    ```console
    ssh user@my-server
    ```
    SSH Term will use the endpoint you configured to establish the connection.

### Command Reference

Here is a list of all available commands. Most commands follow a `command <sub-command> [arguments]` pattern.

#### Connection Commands

*   `ssh [options] [user@]hostname [command]` - Starts an SSH connection.
    *   `-i, --identity <keyname>`: The key to use for authentication.
    *   `-J, --jump-hosts <jump-hosts>`: Connect by going through jump hosts.
    *   `-A, --forward-agent`: Forwards access to the local SSH agent.
*   `sftp [options] [user@]hostname` - Starts an interactive SFTP session.
    *   (Options are the same as `ssh`)

#### Key Management (`keys`)

*   `keys list` - Lists all keys.
*   `keys generate [options] <name>` - Generates a new key.
    *   `-t, --type <type>`: The type of key to generate (`ecdsa`, `ecdsa-sk`, `ed25519`, `rsa`).
    *   `-b, --bits <bits>`: The key size in bits.
    *   `--idp <url>`: The URL of the identity provider to use.
*   `keys delete <name>` - Deletes a key.
*   `keys show <name>` - Shows a key's public part and certificate details.
*   `keys change-pass <name>` - Changes a key's passphrase.
*   `keys import <name>` - Imports a private key from a file.
*   `keys export [-p] <name>` - Exports a key. With `-p` or `--private`, exports the private key.
*   `keys import-cert <key-name>` - Imports a certificate for an existing key.

#### Endpoint Management (`ep`)

*   `ep list` - Lists all configured server endpoints.
*   `ep add <name> <url>` - Adds a new server endpoint.
*   `ep delete <name>` - Deletes a server endpoint.

#### SSH Agent Management (`agent`)

*   `agent list` - Lists keys in the SSH agent.
*   `agent add <key-name>` - Adds a key to the agent.
*   `agent remove [-all] [<name>]` - Removes a key (or all keys with `--all`) from the agent.
*   `agent lock` - Locks the agent with a passphrase.
*   `agent unlock` - Unlocks the agent.

#### Known Hosts Management (`hosts`)

*   `hosts list` - Lists all known hosts.
*   `hosts delete <name>` - Deletes a known host.

#### Certificate Authority Management (`ca`)

*   `ca list` - Lists all certificate authorities.
*   `ca import <name> [hostname...]` - Imports a CA public key.
*   `ca delete <name>` - Deletes a certificate authority.
*   `ca add-hostname <name> <hostname>...` - Adds trusted hostnames to a CA.
*   `ca remove-hostname <name> <hostname>...` - Removes hostnames from a CA.

#### Database Management (`db`)

*   `db persist [on|off|toggle]` - Manages whether the database is persisted to local storage.
*   `db wipe` - Deletes everything from the database.
*   `db backup` - Creates an encrypted backup of the database.
*   `db restore` - Restores the database from a backup.

#### SFTP Commands (for use within an `sftp` session)

*   `cd [dir]` - Changes the remote directory.
*   `pwd` - Shows the current remote directory.
*   `ls [-l] [path...]` - Lists remote files.
*   `get <remote-file>...` - Downloads one or more files.
*   `put` - Uploads one or more files.
*   `mkdir [-p] <directory>...` - Creates a remote directory.
*   `rm [-R] <path>...` - Removes a remote file or directory.
*   `rmdir <directory>...` - Removes a remote directory.
*   `mv <old> <new>` - Renames a remote file or directory.
*   `chmod <mode> <path>...` - Changes file permissions.
*   `ln [-s] <target> <link>` - Creates a hard or symbolic link.
*   `help` or `?` - Shows available SFTP commands.
*   `exit` or `quit` - Exits the SFTP session.

#### Terminal and Application

*   `set theme <light|dark|green>` - Sets the color theme.
*   `clear` - Clears the terminal screen.
*   `reload` - Reloads the application page.
*   `help` - Shows a list of available commands.
*   `exit` - Exits the application.

## Contributing

Contributions are welcome! We appreciate help with bug fixes, feature development, and documentation.

### Development Setup

1.  **Clone the repository:**
    ```console
    git clone https://github.com/c2FmZQ/sshterm.git
    cd sshterm
    ```

### Code Structure

For a detailed explanation of the project's architecture and design, please see [DESIGN.md](DESIGN.md).

The codebase is organized into the following main directories:

*   `go/`: Contains all the Go source code for the SSH client. This code is compiled into a WebAssembly (`.wasm`) module.
    *   `go/internal/app/`: Defines all the application's commands (`ssh`, `keys`, `ep`, etc.).
    *   `go/internal/indexeddb/`: A Go wrapper for the browser's IndexedDB API for local storage.
    *   `go/internal/jsutil/`: Utilities for Go-to-JavaScript interoperability.
    *   `go/internal/terminal/`: A Go wrapper for the `xterm.js` terminal to handle I/O.
    *   `go/internal/shellwords/`: Handles shell-style command-line parsing.
    *   `go/internal/websocket/`: Implements a `net.Conn` interface over a browser WebSocket.
    *   `go/internal/webauthnsk/`: Implements the `ecdsa-sk` (WebAuthn) key type.
    *   `go/internal/tests/`: Contains internal end-to-end tests for the Go application, which are also compiled to WASM and run in a browser.
    *   `go/internal/testserver/`: A backend server used for running the internal Go tests, providing a mock SSH server and other endpoints.
*   `docroot/`: The web root for the application. It contains the main `index.html`, the compiled `ssh.wasm` binary, and the necessary JavaScript and CSS assets. This is the directory you would serve to users.
*   `xterm/`: Contains the `xterm.js` frontend component and its dependencies, which provides the terminal UI.
*   `tests/`: Contains scripts and Docker configurations for running the end-to-end browser tests.
*   `build.sh`: The main build script that compiles the Go code into WASM and moves all necessary assets into the `docroot/` directory.

2.  **Run the tests:**
    You can run the test suite to verify your changes.

    *   **Headless Mode:** To run the tests in a headless browser, execute:
        ```console
        ./tests/run-headless-tests.sh
        ```

    *   **Interactive Mode:** To run the tests in your own browser for debugging, start the test server:
        ```console
        ./tests/run-test-server.sh
        ```
        Then, open `http://<hostname>:8443/tests.html` in your browser.

    [Watch the video](https://www.youtube.com/watch?v=wwoTMb_pqw8)

### Submitting Changes

We follow a standard GitHub pull request workflow.

1.  **Fork** the repository on GitHub.
2.  **Create a new branch** for your changes.
3.  **Make your changes** and commit them with a clear message.
4.  **Push** your branch to your fork.
5.  **Open a pull request** against the `main` branch of the original repository.

#### Tests and Documentation

*   **Tests**: Please ensure that your changes are covered by new or existing tests. You can run the test suite locally using the instructions in the "Development Setup" section. All pull requests must pass the automated CI checks.
*   **Documentation**: If you introduce a new command, option, or user-facing feature, please update the relevant sections of this `README.md` file.