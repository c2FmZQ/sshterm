# X11 Implementation Completion Plan

This document outlines the detailed steps required to bring the X11 server implementation in `sshterm` to a high-fidelity, performant, and fully functional state.

## Current State Analysis

The current implementation provides a basic X11 server capable of rendering simple clients. However, it lacks critical features for interactive applications (menus, popups), suffers from performance bottlenecks in rendering (software emulation), and has incomplete protocol support.

**Critical Gaps:**
1.  **Event Handling:** Pointer grabs (`GrabPointer`) are stubbed, rendering menus and dropdowns unusable. Mouse events are not throttled, leading to performance degradation.
2.  **Rendering Performance:** Logical operations (`GXxor`, `GXor`, etc.) use a slow read-modify-write software path. `PutImage` is unoptimized. `ComposeWindow` redraws the entire window tree on every update.
3.  **Fidelity:** Font rendering is rudimentary. complex GC attributes (dashes, line styles) are missing. Cursor support is basic.

## Phase 1: Critical Interaction & Event Handling

**Goal:** Enable functional usage of standard X11 applications (menus, popups, dragging) and prevent browser freezing.

### 1.1 Implement Pointer Grabs (Priority: High)
Menus and popups rely on `GrabPointer` to capture input outside their window.
-   **Frontend (`x11_frontend_wasm.go`):**
    -   Implement `GrabPointer`: Use `element.setPointerCapture(pointerId)` on the canvas to redirect all mouse input to the grabbing window.
    -   Implement `UngrabPointer`: Use `element.releasePointerCapture(pointerId)`.
    -   Update `mouseEventHandler` to handle `gotpointercapture` and `lostpointercapture` events if necessary to sync state.

### 1.2 Mouse Event Throttling (Priority: High)
High-frequency `mousemove` events flood the Go-WASM bridge.
-   **Frontend (`x11_frontend_wasm.go`):**
    -   Modify `mouseEventHandler` to use a standard throttling mechanism (e.g., 60FPS limit using `requestAnimationFrame` or timestamp deltas).
    -   Accumulate deltas for relative motion if necessary, or just drop intermediate absolute positions.

### 1.3 Keyboard Input Refinement
-   **Frontend:** Ensure `keydown`/`keyup` listeners are correctly attached/detached on focus changes (`FocusIn`/`FocusOut`).
-   **Keymap:** Verify `keymap.go` covers all standard US layout keys, including modifiers, to support shortcuts (e.g., `Alt+Tab`, `Ctrl+C`).

## Phase 2: Rendering Performance Optimization

**Goal:** Achieve 60FPS rendering for typical desktop operations (window dragging, scrolling).

### 2.1 Native Logical Operations (Priority: High)
Software emulation of GC logical functions (`GXxor`, `GXinvert`, etc.) is extremely slow in WASM/JS.
-   **Frontend (`x11_frontend_wasm.go`):**
    -   Map X11 GC functions to HTML5 Canvas `globalCompositeOperation` where possible:
        -   `GXcopy` -> `source-over`
        -   `GXxor` -> `xor` (if supported) or emulate efficiently.
        -   `GXclear` -> `destination-out`
    -   For unsupported ops, optimize the software path:
        -   Use `Uint32Array` views on `ImageData` for faster pixel manipulation.
        -   Minimize `getImageData`/`putImageData` calls by caching read-back data if unchanged.

### 2.2 Dirty Region Tracking (Priority: Medium)
`ComposeWindow` currently clears and redraws the entire window.
-   **Server (`x11.go`):**
    -   Implement a "damage region" (union of rectangles) for each window.
    -   Only send `PutImage` or draw commands for the damaged area.
-   **Frontend:**
    -   Update `ComposeWindow` to accept a clipping rectangle.

### 2.3 Optimize `PutImage` (Priority: Medium)
-   **Frontend:**
    -   Avoid per-pixel loops in Go for standard formats (ZPixmap / TrueColor).
    -   Pass raw byte slices to JS and use `Uint8ClampedArray.set()` for bulk memory copy.

## Phase 3: Rendering Fidelity & Protocol Completeness

**Goal:** Ensure visual correctness for diverse applications.

### 3.1 Advanced Graphics Context Features
-   **Dashes & Line Styles:** Implement `setLineDash` in `applyGCState` for `LineOnOffDash` and `LineDoubleDash`.
-   **Fill Rules:** Ensure `FillPolygon` respects `EvenOdd` vs `Winding` rules.
-   **Tile/Stipple:** Optimize pattern generation. Cache `CanvasPattern` objects instead of recreating them on every draw call.

### 3.2 Font Rendering Improvements
-   **Metrics:** Improve `QueryFont` to support non-ASCII characters and more accurate bounds.
-   **Font Matching:** Enhance `MapX11FontToCSS` to better approximate X11 logical font descriptions (XLFD) to available web fonts.

### 3.3 Cursor Enhancements
-   **Custom Cursors:** Optimize `CreateCursor` to cache the generated DataURL. Avoid repeatedly generating base64 strings for the same cursor data.
-   **RecolorCursor:** Implement dynamic recoloring of client-side cursors (update CSS or regenerate DataURL).

### 3.4 Missing Protocol Requests
Implement the following stubbed or missing handlers in `request_handlers.go`:
-   `AllowEvents`: Crucial for `ReplayPointer`/`ReplayKeyboard` in modal interactions.
-   `WarpPointer`: Ensure it updates the server-side pointer position correctly even if the browser doesn't support moving the physical cursor.
-   `SetInputFocus`: Ensure focus models (ClickToFocus vs FocusFollowsMouse) work as expected.

## Phase 4: fully Automated High-Fidelity Testing Strategy

This strategy leverages the existing `chromedp` and `testserver` infrastructure to ensure high fidelity and correctness without manual intervention.

### 4.1 Architecture
The testing pipeline consists of three components:
1.  **Headless Browser (Chromedp):** Runs the `sshterm` WASM frontend. It injects user input (mouse/keyboard) and captures the rendering state (screenshots + operation logs).
2.  **Test Server (Mock X11 Client):** A Go-based SSH server that acts as an X11 client. It sends specific X11 protocol sequences ("Scenes") and records the expected X11 events it receives.
3.  **Comparator (Go Test):** Orchestrates the test. It verifies that:
    -   **Visuals:** Canvas screenshots match Golden Images.
    -   **Logic:** The sequence of X11 operations sent by the server matches the Canvas operations executed by the frontend.
    -   **Events:** Browser input events result in the correct X11 events received by the Test Server.

### 4.2 Enhanced Operation Comparison (Translation Verification)
The current `compareOperations` function verifies that X11 drawing commands result in corresponding Canvas calls. We will expand this:
-   **Instrumentation:** Ensure all new frontend functions (`GrabPointer`, `PolyLine` with dashes, `PutImage`) record their execution to the global `window.canvasOperations` log.
-   **Verification:** The `testserver` will emit a "manifest" of expected Canvas operations for each scene. The test runner will assert equality.
    -   *Example:* `X_PolyLine(dashed)` -> `ctx.setLineDash(...)`, `ctx.stroke()`.

### 4.3 Automated Event & Interaction Testing
To test Grabs and Input without a user:
1.  **Inject Input:** Use `chromedp.MouseClickXY`, `chromedp.MouseMoveTo`, and `chromedp.SendKeys` to simulate user interaction on the canvas.
2.  **Assert X11 Events:** The `testserver` will have a channel to report received X11 events.
    -   *Scenario:* "Menu Grab"
        1.  `testserver` creates a window and calls `GrabPointer`.
        2.  `chromedp` clicks at (10, 10) *outside* the window.
        3.  `testserver` asserts it received a `ButtonPress` event (because of the grab).
        4.  Failure if the event is missing or sent to the wrong window.

### 4.4 Golden Image Visual Regression
1.  **Baseline Creation:** Run the test suite once with a flag (e.g., `-update-golden`) to generate PNGs in `tests/testdata/golden/`.
2.  **Automated Check:**
    -   Capture screenshot via `chromedp.CaptureScreenshot`.
    -   Compare pixel-by-pixel with the Golden Image.
    -   Fail the test if the diff exceeds a small threshold (to account for minor browser rendering differences).

### 4.5 Performance Benchmarking
-   **FPS Counter:** Add a hidden FPS counter in the frontend.
-   **Stress Test:** Create a test scene with 1000 lines or large `PutImage` updates.
-   **Assertion:** `chromedp` reads the FPS counter; fail if it drops below 30 FPS during the stress test.

## Step-by-Step Execution Plan

1.  **Stopgap Fixes:**
    -   [x] Fix initialization of default colormap visual (fixes xterm/xeyes startup).
    -   [x] Implement `GrabPointer`/`UngrabPointer` in WASM frontend.
    -   [x] Add `mousemove` throttling.
    -   [x] **Test:** Add `TestX11_Grab` to `main_test.go` using `chromedp` click injection.
2.  **Performance Core:**
    -   [x] Optimize `PutImage` (bulk copy).
    -   [x] Implement native `globalCompositeOperation` mappings.
    -   [x] **Test:** Add `TestX11_Benchmark` to assert rendering speed.
3.  **Visuals:**
    -   [x] Implement Dashed Lines & Stipples.
    -   [x] Improve Font Mapping.
    -   [x] **Test:** Add `TestX11_Visuals` with Golden Image comparison for dashes/stipples.
4.  **Protocol Completion:**
    -   [x] Implement `AllowEvents`.
    -   [x] Implement `GetWindowAttributes` (WASM side).
    -   [x] **Test:** Verify `AllowEvents` unblocks input queue in `TestX11_Grab`.
5.  **Final Polish:**
    -   [x] Dirty region optimization.
    -   [x] Full regression testing suite run.
