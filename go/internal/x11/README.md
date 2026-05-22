# X11 Forwarding Implementation

This directory contains the implementation of the server-side X11 forwarding protocol for sshterm. The code is structured to support two different architectures: a WebAssembly (wasm) target that runs in the browser, and a standard non-wasm target used for testing.

## Target Architecture Overview

The core X11 server logic is designed to be platform-independent. It communicates with a frontend via the `X11FrontendAPI` interface. The actual implementation of this frontend is the only part of the code that is architecture-dependent.

- The core server logic resides in `x11.go`.
- The `X11FrontendAPI` interface is defined in `x11.go`.
- The `newX11Frontend` function, which returns an `X11FrontendAPI` implementation, is architecture-dependent.
- For the **wasm** build (in-browser), the frontend implementation in `x11_frontend_wasm.go` communicates with JavaScript to handle rendering. This is further split into `x11_frontend_wasm_debug.go` and `x11_frontend_wasm_nodebug.go` to manage debug logging.
- For **non-wasm** builds (used for tests), a mock frontend in `x11_frontend_mock.go` is used to simulate the frontend behavior.

### Build Tags

Go build tags are used to manage the different build configurations.

- `//go:build x11`: This is the main build tag for the package. Most files have this tag, so the X11 forwarding code is only enabled when this tag is used.
- `//go:build !x11`: The `nox11.go` file uses this tag to provide a stub implementation when X11 support is disabled.
- `//go:build wasm` and `//go:build !wasm`: These tags are used to separate the wasm and non-wasm (mock) implementations of the `X11FrontendAPI`. They are always used in combination with the `x11` tag.
- `//go:build debug` and `//go:build !debug`: These tags control the inclusion of debugging-related code.

## File Structure

- **`x11.go`**: Contains the core, architecture-independent data structures (`x11Server`, `window`, request/setup structs), the `X11FrontendAPI` interface, the `HandleX11Forwarding` function (which sets up the channel handling), and the `x11Server` methods (`serve`, `handshake`, `handleRequest`).

- **`client.go`**: Manages the state of a single connected X11 client, including their windows, resources, and message queue.

- **`wire/`**: A sub-package containing Go representations of the X11 wire protocol. It defines structs for requests, replies, events, and errors, and handles the low-level parsing and serialization of binary X11 messages.

- **`request_handlers.go`**: Contains the handler functions for the various X11 requests (e.g., `handleCreateWindow`, `handlePutImage`). These functions are called by the main server loop in `x11.go` to process incoming client requests.

- **`xinput.go`**: Implements support for the XInput extension, which allows for more advanced handling of input devices beyond the core keyboard and pointer.

- **`fonts.go`**, **`keymap.go`**, **`colorname.go`**: These files provide helper functionality for managing X11 fonts, keyboard mappings, and named colors.

- **`x11_frontend_wasm.go`**: (`//go:build wasm`) The `wasm` implementation of the `X11FrontendAPI` and the `newX11Frontend` function for wasm builds. It acts as a bridge to the browser's JavaScript environment to perform rendering tasks.

- **`x11_frontend_mock.go`**: (`//go:build !wasm`) A mock implementation of the `X11FrontendAPI` and the `newX11Frontend` function for non-wasm builds. It records calls made to its methods, allowing tests to verify server behavior without a graphical environment.

- **`*_test.go`**: Various test files for the package.
- **`testing_helpers_test.go`**: Provides common testing utilities, such as mock loggers and network connections, used across the test files.
