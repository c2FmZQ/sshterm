# X11 Real-World Application Testing Strategy

This document defines the strategy for verifying the X11 server implementation in `sshterm` using actual X11 applications running in a controlled environment.

## 1. Objectives
- Verify protocol correctness with diverse toolkits (Xlib, Xt, Motif, GTK).
- Ensure interactive stability (grabs, focus, events) under real-world traffic.
- Assert visual fidelity using automated regression against known application states.
- Performance validation with non-synthetic workloads.

## 2. Infrastructure

### 2.1 The "Real App" Container (`x11-apps`)
A new Docker service will be added to provide a standard Linux environment with:
- **Base OS:** Debian/Ubuntu (slim).
- **SSH Server:** `openssh-server` configured with `X11Forwarding yes`.
- **Applications:**
  - `xeyes`: Tests QueryPointer, WarpPointer, and basic window mapping.
  - `xclock`: Tests periodic rendering and Arcs/Lines.
  - `xterm`: Tests complex font rendering and keyboard input.
  - `xmessage`: Tests basic window management and button interactions.
  - `xcalc`: Tests complex layout and multiple window events.

### 2.2 Test Orchestrator
The existing `chromedp` logic in `main_test.go` will be extended to:
1.  Initiate an SSH session from `sshterm` to the `x11-apps` container.
2.  Launch target applications via the terminal.
3.  Inject DOM events (Click, Move) into the canvas.
4.  Capture screenshots and compare with "Real-World Golden Images".

## 3. Automated Test Scenarios

### Scenario A: The Tracking Test (`xeyes`)
- **Action:** Launch `xeyes`. Move the browser cursor across the canvas in a circular pattern.
- **Verification:** Capture multiple screenshots; verify that the "pupils" of the eyes are following the cursor (non-static rendering).
- **Goal:** Verify `QueryPointer` and `MotionNotify` delivery.

### Scenario B: The Input Test (`xterm`)
- **Action:** Launch `xterm`. Inject keyboard events for a string (e.g., `ls -l\n`).
- **Verification:** Capture canvas; use OCR or pixel matching to verify the string appeared in the rendered terminal.
- **Goal:** Verify keyboard mapping and complex `PutImage` sequences.

### Scenario C: The Modal Test (`xmessage`)
- **Action:** Launch `xmessage "Test"`. Inject a click on the "OK" button.
- **Verification:** Verify that the X11 window is destroyed in the browser DOM.
- **Goal:** Verify `GrabPointer`, `ButtonPress`, and window lifecycle protocol.

### Scenario D: The Visual Consistency Test (`xclock`)
- **Action:** Launch `xclock`. Wait 5 seconds.
- **Verification:** Verify that the hands have moved. Compare with a baseline image of a standard X server's `xclock` output.
- **Goal:** Verify high-fidelity drawing primitives (Arcs, Polygons).

## 4. Implementation Steps

1.  **Environment Setup:**
    - Create `tests/Dockerfile.x11apps`.
    - Update `tests/docker-compose-browser-tests.yaml` to include the `x11-apps` service.
2.  **Test Development:**
    - Add `TestX11_RealApps` to `go/internal/tests/app_test.go` (or a dedicated integration test file).
    - Implement a `CaptureCanvas` helper to grab PNGs from the WASM frontend via `chromedp`.
3.  **Baseline Generation:**
    - Add a `-update-real-golden` flag to the test suite to capture initial screenshots from the real apps.
4.  **CI Integration:**
    - Update `run-headless-tests.sh` to build and start the new container.

## 5. Success Criteria
- All automated scenarios pass consistently without flakiness.
- Zero "BadProtocol" or "BadWindow" errors in the server logs during real app usage.
- Performance remains >= 30 FPS during `xeyes` tracking.
