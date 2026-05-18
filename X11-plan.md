# X11 Forwarding Implementation Plan for SSHTERM

This document outlines the plan for implementing X11 forwarding in SSHTERM. The goal is to allow users to run graphical applications on a remote server and have their GUIs displayed in the browser.

## High-Level Goal

Implement an X11 server within the SSHTERM Go application (compiled to WASM). This server will receive X11 drawing commands, translate them into JavaScript calls, and directly invoke functions in the frontend to be rendered on HTML5 canvas elements.

## Architecture

The implementation will consist of three main components:

1.  **X11 Server (Go/WASM):** The existing X11 server in Go will be compiled to WASM and run in the browser. It will parse the X11 protocol and manage X11 windows and resources. Instead of sending messages over a WebSocket, it will make direct JavaScript calls to the frontend renderer.
2.  **Frontend Renderer (JS/Canvas):** The frontend will expose JavaScript functions that the Go/WASM X11 server can call. These functions will receive rendering commands and window management events directly from the Go/WASM module and render the X11 windows using one or more `<canvas>` elements. It will also capture user input (mouse, keyboard) and send it back to the Go/WASM X11 server via JavaScript calls.

## Implementation Milestones

The implementation is broken down into the following milestones. Each task can be worked on incrementally.

### Milestone 1: Basic X11 Server & SSH Integration

- [x] **Task 1.1:** Create a new package `go/internal/x11` for the X11 server.
- [x] **Task 1.2:** Handle incoming X11 channels from the SSH client. *(Note: A TCP server is not needed as we get channels directly from the SSH client.)*
- [x] **Task 1.3:** Modify the SSH client to request X11 forwarding. *(Note: Added `-X` flag and `x11-req` request.)*
- [x] **Task 1.4:** Implement the initial X11 handshake. The server now parses the client's handshake message.

### Milestone 2: X11 Protocol Parsing

- [x] **Task 2.1:** Implement the server-side of the X11 handshake. This involves sending the server's setup information back to the client.
- [x] **Task 2.2:** Begin manual parsing of X11 requests. *(Note: Started parsing request headers (opcode, data, length) and logging them.)*
- [x] **Task 2.3:** Implement handlers for core X11 requests:
    - [x] `CreateWindow`
    - [x] `MapWindow`
    - [x] `UnmapWindow`
    - [x] `DestroyWindow`
    - [x] `CreateGC`
    - [x] `ChangeProperty` (for window titles)
- [x] **Task 2.4:** Maintain a server-side representation of windows and their properties.

### Milestone 3: Backend-Frontend Communication (Direct WASM-JS Calls)

- [x] **Task 3.1:** Define a clear JavaScript API for X11 rendering. This API will expose functions that the Go/WASM module can call (e.g., `x11.createWindow(id, x, y, width, height)`).
- [x] **Task 3.2:** Implement the Go-side of the WASM-JS bridge. This involves using `syscall/js` to call the JavaScript API functions from the Go X11 server.
- [x] **Task 3.3:** When the X11 server processes requests (e.g., `CreateWindow`, `MapWindow`, `ChangeProperty`), it should make corresponding JavaScript calls to the frontend renderer.

### Milestone 4: Frontend Rendering (JS/Canvas)

- [x] **Task 4.1:** Create a new JavaScript module on the frontend that implements the X11 rendering API defined in Task 3.1.
- [x] **Task 4.2:** On receiving a `createWindow` call, dynamically create a new `<canvas>` element for the window. The window should be movable and resizable.
- [x] **Task 4.3:** Implement handlers for other rendering commands (e.g., `draw_image` for `PutImage` requests, `setTitle`, `showWindow`, `hideWindow`, `destroyWindow`).
- [x] **Task 4.4:** Implement `PutImage` rendering on the canvas. This is the core of displaying GUI content.

### Milestone 5: User Input (JS-WASM Calls)

- [x] **Task 5.1:** Capture mouse events (click, move, scroll) on the canvas windows in JavaScript.
- [x] **Task 5.2:** Capture keyboard events when a window is focused in JavaScript.
- [x] **Task 5.3:** Expose Go/WASM functions that JavaScript can call to send input events back to the Go X11 server.
- [x] **Task 5.4:** The Go X11 server will translate these events into X11 events and send them to the X11 client.

### Milestone 6: Advanced Features & Refinements

- [x] **Task 6.1:** Clipboard integration.
    - [x] **Task 6.1.1:** Implement `GetProperty` and `SetProperty` handlers in the Go X11 server to manage clipboard data.
    - [x] **Task 6.1.2:** Use X11 atoms like `CLIPBOARD`, `TARGETS`, and `UTF8_STRING` to handle clipboard requests.
    - [x] **Task 6.1.3:** Implement JavaScript functions to interact with the browser's clipboard API (`navigator.clipboard`).
    - [x] **Task 6.1.4:** Bridge the Go X11 server and the JavaScript clipboard functions to allow copy and paste between the remote application and the local browser.
- [x] **Task 6.2:** Support for multiple X11 visuals and color depths.
- [x] **Task 6.3:** Performance optimizations, such as optimizing WASM-JS calls and canvas rendering.
- [x] **Task 6.4:** Support for more X11 drawing primitives.
- [x] **Task 6.5:** Advanced Drawing Primitives (Arcs) [Text]
- [x] **Task 6.6:** Implement Graphics Context (GC) creation in `X11Frontend.createGC`.
- [x] **Task 6.7:** Implement actual image rendering on canvas in `X11Frontend.putImage`.
- [x] **Task 6.8:** Integrate Graphics Context (GC) for drawing primitives (`polyLine`, `polyFillRectangle`, `fillPoly`, `polySegment`, `polyPoint`, `polyRectangle`).
- [x] **Task 6.9:** Implement all missing X11 core protocol opcodes as defined in `Xproto.h`.
    - [x] **Task 6.9.1:** Identify the opcodes that must be handled by the X11 server for compatibility, and prioritize. Add subtasks below for each one with details.
    - [x] **Task 6.9.1.1:** Implement `X_GetWindowAttributes` (3): Essential for applications to query window properties like size, position, and visibility.
    - [x] **Task 6.9.1.2:** Implement `X_ConfigureWindow` (12): Allows applications to resize, move, and stack windows, crucial for window management.
    - [x] **Task 6.9.1.3:** Implement `X_GetGeometry` (14): Retrieves a window's geometry (position, size, border width).
    - [x] **Task 6.9.1.4:** Implement `X_QueryPointer` (38): Enables applications to get the current mouse pointer position and button state.
    - [x] **Task 6.9.1.5:** Implement `X_SendEvent` (25): Fundamental for inter-client communication and event propagation.
    - [x] **Task 6.9.1.6:** Implement `X_ClearArea` (61): Used to clear a rectangular area of a window or pixmap, important for redrawing.
    - [x] **Task 6.9.1.7:** Implement `X_CopyArea` (62): Copies a rectangular area from one drawable to another, essential for efficient redrawing and scrolling.
    - [x] **Task 6.9.1.8:** Implement `X_GetImage` (73): Allows clients to retrieve image data from a drawable.
    - [x] **Task 6.9.1.9:** Implement `X_GetAtomName` (17): Retrieves the string name of an atom.
    - [x] **Task 6.9.1.10:** Implement `X_ListProperties` (21): Lists properties set on a window.
- [x] **Task 6.10:** Add basic X11 window decorations: Title bar, Close button.
- [x] **Task 6.11:** Make X11 windows resizable and draggable.
- [x] **Task 6.11.1:** Implement a basic window manager to handle window decorations, dragging, and resizing for top-level windows.
- [x] **Task 6.12:** Explore option to display X11 canvas in a separate HTML5 window to avoid overlap with the xterm terminal.
- [x] **Task 6.13:** Throttle and/or sample high frequency events like mouse movement.
    - [x] **Subtask 6.13.1:** Implement Throttling for `mousemove` Events in `x11_frontend_wasm.go`
    - [x] **Subtask 6.13.2:** Determine Optimal Frontend Throttle Delay
    - [x] **Subtask 6.13.3:** Assess Need for Server-Side Sampling/Aggregation
    - [x] **Subtask 6.13.4:** Conduct Performance Testing
    - [x] **Subtask 6.13.5:** Refine Throttling Implementation
- [x] **Task 6.14:** Harden input validation in the WASM code that receives X11 data from the remote SSH server / remote X11 client.
    - [x] **Subtask 6.14.1:** Implement Comprehensive Length Checks in `requests.go`
    - [x] **Subtask 6.14.2:** Verify Padding and Alignment
    - [x] **Subtask 6.14.3:** Validate Numeric Ranges and Enum Values
    - [x] **Subtask 6.14.4:** Validate Resource IDs
    - [x] **Subtask 6.14.5:** Standardize X11 Error Replies for Validation Failures
    - [x] **Subtask 6.14.6:** Review Frontend Data Sent to Go Backend
    - [x] **Subtask 6.14.7:** Implement Fuzz Testing for X11 Request Parsing
- [x] **Task 6.15:** Implement X11 Text Rendering
    - [x] **Task 6.15.1:** Implement `ImageText8`
    - [x] **Task 6.15.2:** Implement `ImageText16`
    - [x] **Task 6.15.3:** Implement `PolyText8`
    - [x] **Task 6.15.4:** Implement `PolyText16`
- [x] **Task 6.16:** Achieve 100% compatibility with `xeyes`.
    - [x] **Task 6.16.1:** Implement the `Bell` request.
    - [x] **Task 6.16.2:** Implement `ChangeGC` for all GC attributes.
    - [x] **Task 6.16.3:** Implement `CreatePixmap` and `PutImage` for bitmap data.
    - [x] **Task 6.16.4:** Implement the `WarpPointer` request.
    - [x] **Task 6.16.5:** Implement `CreateGlyphCursor` and `ChangeWindowAttributes` for cursor management.
    - [x] **Task 6.16.6:** Implement `CopyGC` and `FreeGC` requests.
    - [x] **Task 6.16.7:** Implement the `TranslateCoordinates` request.
    - [x] **Task 6.16.8:** Implement `ChangeWindowAttributes` for event selection (`CWEventMask`).
    - [x] **Task 6.16.9:** Implement server-side event sending (e.g., `Expose`, `KeyPress`, `ButtonPress`).
    - [x] **Task 6.16.10:** Implement synchronization via round-trip requests (e.g., `GetInputFocus`).
    - [x] **Task 6.16.11:** Implement window stacking via `ConfigureWindow`.
    - [x] **Task 6.16.12:** Implement `GetSelectionOwner`, `SetSelectionOwner`, and `ConvertSelection` requests.
    - [x] **Task 6.16.13:** Implement `GrabPointer`, `UngrabPointer`, `GrabKeyboard`, and `UngrabKeyboard` requests.
    - [x] **Task 6.16.14:** Implement the `QueryBestSize` request.
    - [x] **Task 6.16.15:** Implement Visual/Colormap Information functions.
    - [x] **Task 6.16.16:** Implement Window Manager Hints/Properties functions.
    - [x] **Task 6.16.17:** Implement Text Properties/Input Methods functions.
    - [x] **Task 6.16.18:** Implement Display/Screen Information functions.
- [x] **Task 6.17:** Implement comprehensive X11 Color Management and Colormaps.
    - [x] **Task 6.17.1:** Implement `CreateColormap` and `FreeColormap`.
    - [x] **Task 6.17.2:** Implement a Color Name Database.
    - [x] **Task 6.17.3:** Implement `LookupColor` and `AllocNamedColor`.
    - [x] **Task 6.17.4:** Implement `AllocColor` and `FreeColors`.
    - [x] **Task 6.17.5:** Implement `StoreColors` and `StoreNamedColor`.
    - [x] **Task 6.17.6:** Enhance Frontend to be Colormap-Aware.
    - [x] **Task 6.17.7:** Fully Implement `QueryColors`.
    - [x] **Task 6.17.8:** Implement Colormap Installation and Notification.
    - [x] **Task 6.17.9:** Implement `ListInstalledColormaps`.
- [x] **Task 6.18:** Implement X11 Font System support (Basic API)
    - [x] **Task 6.18.1:** Map X11 Font Names to CSS Fonts
    - [x] **Task 6.18.2:** Implement `OpenFont` (Simplified)
    - [x] **Task 6.18.3:** Integrate GC Font into Text Rendering
    - [x] **Task 6.18.4:** Implement `QueryFont` (Simplified)
    - [x] **Task 6.18.5:** Implement `CloseFont`
    - [x] **Task 6.18.6:** Implement `ListFonts` (Simplified)
    - [x] **Task 6.18.7:** Implement full 2-byte font metric generation
- [x] **Task 6.19:** Implement complete X11 Pixmap and GContext Manipulation.
    - [x] **Task 6.19.1:** Implement `CopyPlane` Request
    - [x] **Task 6.19.2:** Improve `PutImage` for Multi-plane XYPixmap
    - [x] **Task 6.19.3:** Implement `SetDashes` Request
    - [x] **Task 6.19.4:** Implement `SetClipRectangles` Request
- [x] **Task 6.20:** Implement X11 Cursor Management.
    - [x] **Subtask 6.20.1:** Implement `CreateCursor` Request
    - [x] **Subtask 6.20.2:** Implement `FreeCursor` Request
    - [x] **Subtask 6.20.3:** Implement `RecolorCursor` Request
    - [x] **Subtask 6.20.4:** Enhance `CreateGlyphCursor` for Custom Font Data
- [x] **Task 6.21:** Implement more granular X11 Event Handling.
    - [x] **Subtask 6.21.1:** Implement `KeyPress` and `KeyRelease` Events
    - [x] **Subtask 6.21.2:** Implement `ButtonPress` and `ButtonRelease` Events
    - [x] **Subtask 6.21.3:** Implement `MotionNotify` Events
    - [x] **Subtask 6.21.4:** Implement `EnterNotify` and `LeaveNotify` Events
    - [x] **Subtask 6.21.5:** Implement `FocusIn` and `FocusOut` Events
    - [x] **Subtask 6.21.6:** Implement `VisibilityNotify` Events
    - [x] **Subtask 6.21.7:** Implement Proper Input Grabbing Logic
    - [x] **Subtask 6.21.8:** Implement `AllowEvents` Request
    - [x] **Subtask 6.21.9:** Implement Event Propagation and Masking
- [x] **Task 6.22:** Implement general X11 Resource Management and Server Control requests.
    - [x] **Subtask 6.22.1:** Implement `DestroySubwindows` Request
    - [x] **Subtask 6.22.2:** Implement `ReparentWindow` Request
    - [x] **Subtask 6.22.3:** Implement `QueryTree` Request
    - [x] **Subtask 6.22.4:** Implement `DeleteProperty` Request
    - [x] **Subtask 6.22.5:** Implement `SetInputFocus` Request
    - [x] **Subtask 6.22.6:** Implement `QueryKeymap` Request
    - [x] **Subtask 6.22.7:** Implement Keyboard Control Requests (`ChangeKeyboardControl`, `GetKeyboardControl`)
    - [x] **Subtask 6.22.8:** Implement Pointer Control Requests (`ChangePointerControl`, `GetPointerControl`)
    - [x] **Subtask 6.22.9:** Implement Server Grabbing (`GrabServer`, `UngrabServer`)
    - [x] **Subtask 6.22.10:** Implement `KillClient` Request
    - [x] **Subtask 6.22.11:** Implement `NoOperation` Request
- [x] **Task 6.23:** Implement support for common X11 Extensions.
    - [x] **Subtask 6.23.1:** Implement `ListExtensions` Request
    - [x] **Subtask 6.23.2:** Refine `QueryExtension` to Report Actual Support

## Testing Strategy

A robust testing strategy is crucial for this complex feature.

### Unit Tests

-   **Go:**
    -   [x] Unit tests for the X11 request parsing and handling logic have been implemented and are passing in the `go/internal/x11` package. These tests mock the frontend API to verify that the correct rendering commands are generated.
    -   [x] Existing unit tests for the `go/internal/app` package are passing, ensuring no regressions were introduced during the X11 refactoring.
    -   [x] Unit tests for the `go/internal/x11` package to cover the `x11Server`'s interaction with the `X11FrontendAPI` and `Logger` interface.
-   **JS:**
    -   [x] Basic setup for JavaScript unit tests using Vitest is complete.
    -   [x] Unit tests for the frontend rendering logic have been implemented and are passing. These tests mock the Go/WASM calls to simulate incoming commands and assert the state of the canvas.

### Integration Tests

- [x] Update `go/internal/testserver` to simulate an X11 application when X11 forwarding is requested. This simulated application should exercise as many primitives as possible.
- [x] Write automated tests (using chromedp) that:
    1.  Open an SSH session with the test server, requesting X11 forwarding.
    2.  Verify that the simulated X11 application exercises the primitives correctly.
    3.  Take a screenshot for manual inspection.
- [ ] Implement a test against The official X Test Suite (XTS).
- [ ] Create a new Docker-based test environment for X11 testing.
- [ ] The test environment should include an SSH server and some simple X11 applications (e.g., `xeyes`, `xclock`, `xterm`).
- [ ] Write automated tests (e.g., using Playwright or Selenium) that:
    1.  Start SSHTERM.
    2.  Connect to the test SSH server with X11 forwarding enabled.
    3.  Run an X11 application.
    4.  Take a screenshot of the browser and compare it to a baseline image to verify rendering.
    5.  Simulate user input and verify that the X11 application responds correctly.

### Shortcuts and Future Work

This section lists the shortcuts that have been taken so far and that will need to be revisited later to complete the implementation.

**Protocol Implementation:**

*   **Missing Opcodes:** Many opcodes listed in `const.go` are not handled in the `handleRequest` switch statement in `x11.go`. These are currently no-ops and will cause applications using them to fail or behave incorrectly.
*   **`PolyText8` and `PolyText16`:** The parsing logic for these requests in `requests.go` does not handle font changes within the text items.
*   **`GetImage`:** The implementation is basic and may not handle all formats and depths correctly.
*   **Events:** The server does not yet send all events to the client (e.g., `KeyPress`, `ButtonPress`). The `SendKeyboardEvent` functions are placeholders.
*   **Input Grabbing:** The `GrabPointer`, `UngrabPointer`, `GrabKeyboard`, and `UngrabKeyboard` requests are implemented, but the frontend returns a hardcoded `Success` status. A full implementation would require significant changes to how input is handled.
*   **`QueryBestSize`:** The `QueryBestSize` request is implemented to return a fixed size (1024x768) as a placeholder. A full implementation would need to consider the actual constraints of the browser and the frontend.
*   **Text Properties/Input Methods:** These functions are currently implemented as no-ops. A full implementation would require handling complex text properties and input method extensions.
*   **Display/Screen Information:** Only basic screen information is provided during the handshake. A full implementation would need to support querying more detailed display and screen information.
*   **MIT-SHM (Shared Memory Extension):** The `QueryExtension` request is handled by reporting that extensions are not present. This will cause clients to fall back to non-shared memory methods. Full MIT-SHM support is not yet implemented.
*   **PutImage (XYPixmap):** Basic support for `PutImage` with `XYPixmap` format (format 1) has been added. It currently assumes a depth of 1 (monochrome) and uses the foreground and background colors from the Graphics Context. Multi-plane XYPixmap is not fully supported.
*   **Non-moving Eyes:** `QueryPointer` and `WarpPointer` are implemented, but the frontend's mouse event handling and server's processing of these events might still be incomplete or incorrect, leading to non-moving eyes.

**Frontend and Rendering:**

*   **`CreateGlyphCursor`:** The implementation in `x11_frontend_wasm.go` uses a simplified mapping of a few hardcoded glyph IDs to CSS cursor names. It does not support custom cursors from font data.
*   **`CreateCursor`:** The implementation for creating cursors from pixmaps (which would allow for custom cursors) is missing.
*   **Fonts:** The `ImageText` and `PolyText` functions use a hardcoded font ("12px monospace"). A proper implementation would need to handle `OpenFont`, `QueryFont`, and use the font specified in the Graphics Context.
*   **Error Handling:** The frontend does not have robust error handling for canvas operations.

### Manual Testing

- Manually test with a wider range of X11 applications (e.g., a simple window manager, a text editor, a browser) to identify compatibility issues.
- Test on different browsers and operating systems.

## Progress Tracking

This file will be the single source of truth for the project's progress. When a task is completed, update the checkbox from `[ ]` to `[x]`.
