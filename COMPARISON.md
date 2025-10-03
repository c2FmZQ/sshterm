# Comparison with Other Solutions

This document compares the architecture and security model of SSH Term with other common "SSH in a browser" solutions.

## The Two Main Architectures

Web-based SSH solutions generally fall into two architectural categories:

1.  **Server-Side Gateway Model:** The web server runs the actual `ssh` client process. The browser acts as a thin client, rendering a terminal UI (like xterm.js) and relaying keystrokes to the server. The server pipes the I/O of the `ssh` process back and forth to the browser, usually over a WebSocket.
    **Examples:**

*   [Shell In A Box](https://github.com/shellinabox/shellinabox) (Server-side web terminal)
*   [Wetty](https://github.com/butlerx/wetty) (Server-side web terminal)
*   [Gate One](https://github.com/liftoff/GateOne) (Server-side web terminal)
*   [Apache Guacamole](https://guacamole.apache.org/) (Clientless remote desktop gateway)
*   [WebSSH (Python)](https://github.com/huashengdun/webssh) (Server-side web terminal)
*   [GoTTY](https://github.com/yudai/gotty) (Server-side web terminal)
*   [Bastillion](https://bastillion.io/) (Web-based SSH bastion host)

2.  **Client-Side WASM Model:** The entire SSH client is compiled to WebAssembly (WASM) and runs directly inside the user's browser. The browser is the SSH client. A lightweight, stateless WebSocket-to-TCP proxy is still required on the server-side, but it does not run the `ssh` process or handle any credentials.
**Examples:**

*   [sshterm](https://github.com/c2FmZQ/sshterm) (WebAssembly-based client)
*   [ssheasy](https://github.com/hullarb/ssheasy) (WebAssembly-based client)
*   [piping-ssh](https://github.com/nwtgck/piping-ssh-web) (WebAssembly-based client)
*   [Tailscale SSH Console](https://tailscale.com/blog/ssh-console/) (WebAssembly-based client)
*   [SSHy](https://github.com/stuicey/SSHy) (HTML5/JavaScript-based client)

SSH Term is a prime example of the Client-Side WASM model, which gives it a fundamentally different security posture and operational profile compared to the more traditional Server-Side Gateway model.

## Key Differences

| Feature | Server-Side Gateway Model (e.g., Wetty, Guacamole) | Client-Side WASM Model (SSH Term) |
| :--- | :--- | :--- |
| **SSH Client Location** | Runs on the web application server. | Runs inside the user's browser (as WebAssembly). |
| **Credential Handling** | Private keys and credentials must be stored on, or accessible by, the web server. The server authenticates to the target SSH host. | Private keys never leave the browser. They are stored (encrypted) in the browser's IndexedDB. The browser authenticates directly to the target SSH host (via the proxy). |
| **Security Boundary** | The primary security boundary is the web server. A compromise of the web server could expose user credentials and active sessions for all users. | The primary security boundary is the browser's sandbox. A compromise of the web server would only serve malicious code, but it would not expose existing user keys stored in their browsers. Each session is isolated within its own browser context. |
| **Resource Usage** | The web server must spawn and manage an `ssh` process for every active user session, consuming CPU and memory on the server. | The computational load of the SSH session (encryption, etc.) is offloaded to the user's machine. The server only runs a lightweight, stateless WebSocket proxy. |
| **Scalability** | Scaling requires adding more web server instances, which can be stateful if they are managing active SSH processes. | Scales more easily. The WebSocket proxy is stateless and can be scaled horizontally behind a load balancer. The resource-intensive work is distributed among the clients. |
| **Features** | Features like SFTP or agent forwarding require specific server-side implementation to manage file staging or agent sockets on the server. | Features like SFTP and agent forwarding are implemented entirely in the client-side Go code. File transfers happen directly between the browser and the SSH connection, and the agent is an in-memory component in the WASM module. |
| **Attack Surface** | The attack surface includes the web application, its dependencies (e.g., Node.js, Python), and the `ssh` binary itself, all running on a publicly accessible server. | The attack surface is primarily the browser and the WASM module's interaction with it. The server-side component is minimal (just a proxy), significantly reducing the server's attack surface. |

## Summary

The **Server-Side Gateway** model is conceptually simpler and has been the traditional approach. However, it centralizes risk and resource consumption on the server. The server becomes a high-value target, as it holds the keys to the kingdom (user credentials and sessions).

Conversely, the **Client-Side WASM** model, used by **SSH Term**, represents a more modern, "zero-trust" approach. It treats the server as an untrusted, simple pipe (the WebSocket proxy) and moves the sensitive cryptographic operations and session management into the client's sandboxed browser environment. This enhances security by decentralizing risk and improves scalability by distributing the workload.

While both models can provide a functional SSH client in the browser, SSH Term's architecture is fundamentally more secure and scalable for most use cases.
