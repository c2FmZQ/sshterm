package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

type domRect struct {
	Left   float64 `json:"left"`
	Top    float64 `json:"top"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

var (
	withChromedp = flag.String("with-chromedp", "", "URL of remote chromedp instance")
	targetURL    = flag.String("target-url", "https://tester:8443/tests.html?x11", "URL of the sshterm application")
	testTimeout  = flag.Duration("timeout", 2*time.Minute, "Timeout for the test execution")
)

func main() {
	flag.Parse()

	if *withChromedp == "" {
		log.Fatal("--with-chromedp is required")
	}

	// Wait for tlsproxy to be ready
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	log.Printf("Waiting for %s to be ready...", *targetURL)
	ready := false
	for i := 0; i < 30; i++ {
		resp, err := client.Get(*targetURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				log.Printf("Target is ready!")
				ready = true
				break
			}
		}
		time.Sleep(1 * time.Second)
	}
	if !ready {
		log.Fatalf("Timed out waiting for %s to become ready", *targetURL)
	}

	allocCtx, allocCancel := chromedp.NewRemoteAllocator(context.Background(), *withChromedp)
	defer allocCancel()

	sessionCtx, sessionCancel := chromedp.NewContext(allocCtx)
	defer sessionCancel()

	chromedp.ListenTarget(sessionCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			var args []string
			for _, arg := range e.Args {
				val := arg.Value.String()
				if s, err := strconv.Unquote(val); err == nil {
					val = s
				}
				args = append(args, val)
			}
			log.Printf("CONSOLE.%s: %s", e.Type, strings.Join(args, " "))
		case *runtime.EventExceptionThrown:
			log.Printf("EXCEPTION: %s", e.ExceptionDetails.Text)
			if e.ExceptionDetails.Exception != nil {
				log.Printf("EXCEPTION DETAIL: %s", e.ExceptionDetails.Exception.Description)
			}
		}
	})

	if err := chromedp.Run(sessionCtx); err != nil {
		log.Fatalf("Failed to initialize chromedp session: %v", err)
	}

	testCtx, testCancel := context.WithTimeout(sessionCtx, *testTimeout)
	defer testCancel()

	var beforeBuf, afterBuf []byte
	log.Println("Starting chromedp actions...")
	err := chromedp.Run(testCtx,
		chromedp.EmulateViewport(1280, 1024),
		chromedp.Navigate(*targetURL),
		chromedp.WaitVisible(".xterm-rows", chromedp.ByQuery),
		// Disable clipboard to avoid NotAllowedError in headless env
		chromedp.Evaluate(`Object.defineProperty(navigator, 'clipboard', { value: null });`, nil),

		// Initial wait for terminal to settle
		chromedp.Sleep(5*time.Second),

		// Wait for initial prompt
		waitForTerminalText("sshterm>"),

		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Sending 'ep add' command...")
			return nil
		}),
		chromedp.Click(".xterm-rows", chromedp.ByQuery),
		insertText("ep add x11-apps wss://tester:8443/websocket"),
		pressEnter(),
		chromedp.Sleep(500*time.Millisecond),

		// Wait for next prompt
		waitForTerminalText("sshterm>"),

		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Sending 'ssh -X' command...")
			return nil
		}),
		insertText("ssh -X testuser@x11-apps"),
		pressEnter(),

		waitForTerminalText("password:"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Found password prompt. Sending 'sshterm'...")
			return nil
		}),
		insertText("sshterm"),
		pressEnter(),

		waitForTerminalText("testuser@x11-apps:~$"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Connected! Launching multiple X11 applications with distinct positioning...")
			return nil
		}),

		// Launch xterm at top-left
		insertText("xterm -geometry 80x24+0+0 &"),
		pressEnter(),
		chromedp.Sleep(1*time.Second),

		// Launch test_ui.py with output redirected to a log file
		insertText("python3 /home/testuser/test_ui.py > /tmp/tkinter_ui.log 2>&1 &"),
		pressEnter(),

		logAction("Waiting for multiple X11 windows (canvases)..."),
		waitForCanvases(9),

		chromedp.ActionFunc(func(ctx context.Context) error {
			var canvasPositions string
			err := chromedp.Evaluate(`
				Array.from(document.querySelectorAll('canvas')).map(c => {
					const r = c.getBoundingClientRect();
					return c.id + ': left=' + r.left + ', top=' + r.top + ', width=' + r.width + ', height=' + r.height;
				}).join('\n')
			`, &canvasPositions).Do(ctx)
			if err != nil {
				return err
			}
			log.Printf("All Canvas positions in DOM:\n%s", canvasPositions)
			return nil
		}),

		chromedp.Sleep(2*time.Second),

		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Locating Tkinter Test UI window XID...")
			var tkXID string
			err := chromedp.Evaluate(`
				(function() {
					const span = Array.from(document.querySelectorAll('span[id^="x11-window-title-"]'))
						.find(s => s.textContent.toLowerCase().includes("tkinter") && s.closest('div[id^="x11-window-"]').style.display !== "none");
					return span ? span.id.replace("x11-window-title-", "") : "";
				})()
			`, &tkXID).Do(ctx)
			if err != nil || tkXID == "" {
				return fmt.Errorf("failed to find Tkinter window XID: %v", err)
			}
			log.Printf("Found Tkinter XID: %s", tkXID)

			canvasID := "#x11-canvas-" + tkXID
			windowID := "#x11-window-" + tkXID

			var tkRect domRect
			err = chromedp.Evaluate(fmt.Sprintf(`
				(function() {
					const c = document.querySelector(%q);
					if (!c) return {left: 0, top: 0, width: 0, height: 0};
					const r = c.getBoundingClientRect();
					return {left: r.left, top: r.top, width: r.width, height: r.height};
				})()
			`, canvasID), &tkRect).Do(ctx)
			if err != nil || tkRect.Width == 0 || tkRect.Height == 0 {
				return fmt.Errorf("failed to get Tkinter canvas bounding rect: %v (%+v)", err, tkRect)
			}
			log.Printf("Tkinter canvas bounding rect: %+v", tkRect)

			log.Println("Capturing initial screenshot before GUI interactions...")
			if err := chromedp.CaptureScreenshot(&beforeBuf).Do(ctx); err != nil {
				return fmt.Errorf("failed to capture initial screenshot: %v", err)
			}

			// Helper functions in Javascript to inject mouse events using deterministic pointer routing
			setupJS := `
				window.clickCanvasAt = function(canvasSelector, x, y) {
					const canvas = document.querySelector(canvasSelector);
					if (!canvas) return false;
					
					const parentWindow = canvas.parentNode;
					
					function findTargetWindow(win, rx, ry) {
						const children = Array.from(win.childNodes).filter(n => n.id && n.id.startsWith("x11-window-") && n.style.display !== "none");
						for (const child of children) {
							const left = parseInt(child.style.left) || 0;
							const top = parseInt(child.style.top) || 0;
							const width = parseInt(child.style.width) || 0;
							const height = parseInt(child.style.height) || 0;
							
							if (rx >= left && rx < left + width && ry >= top && ry < top + height) {
								return findTargetWindow(child, rx - left, ry - top);
							}
						}
						return win;
					}
					
					const isTopLevel = parentWindow.id.startsWith("x11-window-") && parentWindow.querySelector('div[id^="x11-titlebar-"]');
					const titleBarHeight = isTopLevel ? 20 : 0;
					const winX = x;
					const winY = y + titleBarHeight;
					
					const targetWindow = findTargetWindow(parentWindow, winX, winY);
					const targetCanvas = targetWindow.querySelector("canvas");
					if (!targetCanvas) return false;
					
					let offsetX = winX;
					let offsetY = winY;
					let curr = targetWindow;
					while (curr && curr !== parentWindow) {
						offsetX -= parseInt(curr.style.left) || 0;
						offsetY -= parseInt(curr.style.top) || 0;
						curr = curr.parentNode;
					}
					
					const targetRect = targetCanvas.getBoundingClientRect();
					const clientX = targetRect.left + offsetX;
					const clientY = targetRect.top + offsetY;
					
					if (window.lastEnteredCanvas && window.lastEnteredCanvas !== targetCanvas) {
						window.lastEnteredCanvas.dispatchEvent(new MouseEvent('mouseleave', {
							bubbles: true, cancelable: true,
							clientX: clientX, clientY: clientY
						}));
					}
					window.lastEnteredCanvas = targetCanvas;
					
					targetCanvas.dispatchEvent(new MouseEvent('mouseenter', {
						bubbles: true, cancelable: true,
						clientX: clientX, clientY: clientY
					}));
					targetCanvas.dispatchEvent(new MouseEvent('mousemove', {
						bubbles: true, cancelable: true,
						clientX: clientX, clientY: clientY
					}));
					
					targetCanvas.dispatchEvent(new MouseEvent('mousedown', {
						bubbles: true, cancelable: true,
						clientX: clientX, clientY: clientY, buttons: 1
					}));
					targetCanvas.dispatchEvent(new MouseEvent('mouseup', {
						bubbles: true, cancelable: true,
						clientX: clientX, clientY: clientY, buttons: 0
					}));
					return true;
				};
			`
			err = chromedp.Evaluate(setupJS, nil).Do(ctx)
			if err != nil {
				return fmt.Errorf("failed to inject JS click helper: %v", err)
			}

			log.Println("1. Clicking the Entry textbox to set focus...")
			var ok bool
			err = chromedp.Evaluate(fmt.Sprintf(`window.clickCanvasAt(%q, 200, 45)`, canvasID), &ok).Do(ctx)
			if err != nil || !ok {
				return fmt.Errorf("failed to click entry textbox: %v (ok=%t)", err, ok)
			}
			// Focus the window element
			err = chromedp.Evaluate(fmt.Sprintf(`document.querySelector(%q).focus()`, windowID), nil).Do(ctx)
			if err != nil {
				return fmt.Errorf("failed to focus window element: %v", err)
			}
			err = chromedp.Sleep(200 * time.Millisecond).Do(ctx)
			if err != nil {
				return err
			}

			log.Println("Typing text into the Entry textbox...")
			err = chromedp.SendKeys(windowID, "WASM X11 test text").Do(ctx)
			if err != nil {
				return fmt.Errorf("failed to type text: %v", err)
			}
			err = chromedp.Sleep(500 * time.Millisecond).Do(ctx)
			if err != nil {
				return err
			}

			log.Println("2. Clicking the Checkbutton...")
			err = chromedp.Evaluate(fmt.Sprintf(`window.clickCanvasAt(%q, 60, 90)`, canvasID), &ok).Do(ctx)
			if err != nil || !ok {
				return fmt.Errorf("failed to click Checkbutton: %v", err)
			}
			err = chromedp.Sleep(500 * time.Millisecond).Do(ctx)
			if err != nil {
				return err
			}

			log.Println("3. Clicking the Option B Radiobutton...")
			err = chromedp.Evaluate(fmt.Sprintf(`window.clickCanvasAt(%q, 190, 140)`, canvasID), &ok).Do(ctx)
			if err != nil || !ok {
				return fmt.Errorf("failed to click Radiobutton: %v", err)
			}
			err = chromedp.Sleep(500 * time.Millisecond).Do(ctx)
			if err != nil {
				return err
			}

			log.Println("4. Clicking the Scale (slider) to change its value...")
			err = chromedp.Evaluate(fmt.Sprintf(`window.clickCanvasAt(%q, 250, 205)`, canvasID), &ok).Do(ctx)
			if err != nil || !ok {
				return fmt.Errorf("failed to click Scale: %v", err)
			}
			err = chromedp.Sleep(500 * time.Millisecond).Do(ctx)
			if err != nil {
				return err
			}

			log.Println("5. Clicking the 'Cherry' item in the Listbox...")
			err = chromedp.Evaluate(fmt.Sprintf(`window.clickCanvasAt(%q, 150, 277)`, canvasID), &ok).Do(ctx)
			if err != nil || !ok {
				return fmt.Errorf("failed to click Listbox: %v", err)
			}
			err = chromedp.Sleep(1 * time.Second).Do(ctx)
			if err != nil {
				return err
			}

			log.Println("Capturing post-interaction screenshot while Tkinter UI is visible...")
			if err := chromedp.CaptureScreenshot(&afterBuf).Do(ctx); err != nil {
				return fmt.Errorf("failed to capture post-interaction screenshot: %v", err)
			}
			if err := os.WriteFile("x11-standalone-screenshot.png", afterBuf, 0644); err != nil {
				return fmt.Errorf("failed to save screenshot: %v", err)
			}

			log.Println("Inspecting screenshots to verify GUI elements are rendered correctly...")
			if err := verifyScreenshots(beforeBuf, afterBuf, tkRect); err != nil {
				return fmt.Errorf("screenshot visual verification failed: %v", err)
			}

			log.Println("6. Clicking the Submit button...")
			err = chromedp.Evaluate(fmt.Sprintf(`window.clickCanvasAt(%q, 200, 380)`, canvasID), &ok).Do(ctx)
			if err != nil || !ok {
				return fmt.Errorf("failed to click Submit button: %v", err)
			}
			err = chromedp.Sleep(2 * time.Second).Do(ctx)
			if err != nil {
				return err
			}

			return nil
		}),

		logAction("Verifying Tkinter state result from file..."),
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Click the primary xterm rows to focus back to the SSH session
			err := chromedp.Click(".xterm-rows", chromedp.ByQuery).Do(ctx)
			if err != nil {
				return err
			}
			// Focus the helper textarea explicitly to make text insertion reliable
			err = chromedp.Evaluate(`
				const el = document.querySelector('.xterm-helper-textarea');
				if (el) el.focus();
			`, nil).Do(ctx)
			if err != nil {
				return err
			}
			return nil
		}),
		insertText("cat /tmp/tkinter_state.json"),
		pressEnter(),
		waitForTerminalText(`"success": true`),
		waitForTerminalText(`"text": "WASM X11 test text"`),
		waitForTerminalText(`"checked": true`),
		waitForTerminalText(`"radio": 2`),
		waitForTerminalText(`"scale": 80.0`),
		waitForTerminalText(`"listbox": ["Cherry"]`),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var termText string
			err := chromedp.Run(ctx,
				chromedp.Evaluate(`
					(function() {
						try {
							if (window.sshApp && window.sshApp.term) {
								const term = window.sshApp.term;
								let s = "";
								const active = term.buffer.active;
								for (let i = 0; i < active.length; i++) {
									const line = active.getLine(i);
									if (line) s += line.translateToString() + "\n";
								}
								return s;
							}
							return "sshApp.term not found";
						} catch (e) {
							return "Error: " + e.message;
						}
					})()
				`, &termText),
			)
			if err == nil {
				log.Printf("Final terminal text:\n%s", termText)
			}
			return err
		}),
	)

	if err != nil {
		log.Printf("Test failed: %v", err)

		// Create a separate timeout context for failure diagnostic actions (recovery)
		// so they can't hang the test process forever if the browser is unresponsive.
		diagCtx, diagCancel := context.WithTimeout(sessionCtx, 15*time.Second)
		defer diagCancel()

		var termText string
		_ = chromedp.Run(diagCtx,
			chromedp.Evaluate(`
				(function() {
					try {
						if (window.sshApp && window.sshApp.term) {
							const term = window.sshApp.term;
							let s = "Buffer length: " + term.buffer.active.length + "\n";
							for (let i = 0; i < term.buffer.active.length; i++) {
								const line = term.buffer.active.getLine(i);
								if (line) s += line.translateToString() + "\n";
							}
							return s;
						}
						return "sshApp.term not found";
					} catch (e) {
						return "Error: " + e.message;
					}
				})()
			`, &termText),
		)
		log.Printf("Terminal text at failure:\n%s", termText)

		// Capture failure screenshot
		var errBuf []byte
		if screenshotErr := chromedp.Run(diagCtx, chromedp.CaptureScreenshot(&errBuf)); screenshotErr == nil {
			if writeErr := os.WriteFile("x11-standalone-screenshot-failed.png", errBuf, 0644); writeErr == nil {
				log.Println("Failure screenshot saved to x11-standalone-screenshot-failed.png")
			} else {
				log.Printf("Failed to write failure screenshot: %v", writeErr)
			}
		} else {
			log.Printf("Failed to capture screenshot on failure: %v", screenshotErr)
		}

		// Attempt to print /tmp/tkinter_ui.log to see Python trace
		log.Println("Attempting to dump /tmp/tkinter_ui.log on failure...")
		var logText string
		_ = chromedp.Run(diagCtx,
			chromedp.Click(".xterm-rows", chromedp.ByQuery),
			insertText("cat /tmp/tkinter_ui.log"),
			pressEnter(),
			chromedp.Sleep(1*time.Second),
			chromedp.Evaluate(`
				(function() {
					try {
						if (window.sshApp && window.sshApp.term) {
							const term = window.sshApp.term;
							let s = "";
							const active = term.buffer.active;
							for (let i = 0; i < active.length; i++) {
								const line = active.getLine(i);
								if (line) s += line.translateToString() + "\n";
							}
							return s;
						}
					} catch (e) {}
					return "failed to read terminal";
				})()
			`, &logText),
		)
		log.Printf("Terminal text after cat /tmp/tkinter_ui.log:\n%s", logText)

		log.Fatal("Stopping due to failure")
	}

	log.Println("Test passed! Screenshot saved to x11-standalone-screenshot.png")
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func pixelRGBA(img image.Image, x, y int) color.RGBA {
	r, g, b, a := img.At(x, y).RGBA()
	return color.RGBA{
		R: uint8(r >> 8),
		G: uint8(g >> 8),
		B: uint8(b >> 8),
		A: uint8(a >> 8),
	}
}

func colorMatches(c, target color.RGBA, tolerance int) bool {
	return absInt(int(c.R)-int(target.R)) <= tolerance &&
		absInt(int(c.G)-int(target.G)) <= tolerance &&
		absInt(int(c.B)-int(target.B)) <= tolerance
}

func countColorInRect(img image.Image, rect image.Rectangle, target color.RGBA, tolerance int) (matched int, total int) {
	b := rect.Intersect(img.Bounds())
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			total++
			if colorMatches(pixelRGBA(img, x, y), target, tolerance) {
				matched++
			}
		}
	}
	return matched, total
}

func verifyScreenshots(beforeBuf, afterBuf []byte, tkRect domRect) error {
	beforeImg, err := png.Decode(bytes.NewReader(beforeBuf))
	if err != nil {
		return fmt.Errorf("failed to decode before screenshot: %w", err)
	}
	afterImg, err := png.Decode(bytes.NewReader(afterBuf))
	if err != nil {
		return fmt.Errorf("failed to decode after screenshot: %w", err)
	}

	ox := int(math.Round(tkRect.Left))
	oy := int(math.Round(tkRect.Top))
	relRect := func(x0, y0, x1, y1 int) image.Rectangle {
		return image.Rect(ox+x0, oy+y0, ox+x1, oy+y1)
	}

	const tol = 18
	var (
		colWhite     = color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
		colBlack     = color.RGBA{R: 0x00, G: 0x00, B: 0x00, A: 0xff}
		colRootGray  = color.RGBA{R: 0xe0, G: 0xe0, B: 0xe0, A: 0xff}
		colTitleBar  = color.RGBA{R: 0x33, G: 0x33, B: 0x33, A: 0xff}
		colRed       = color.RGBA{R: 0xff, G: 0x00, B: 0x00, A: 0xff}
		colGreen     = color.RGBA{R: 0x00, G: 0x80, B: 0x00, A: 0xff}
		colBlue      = color.RGBA{R: 0x00, G: 0x00, B: 0xff, A: 0xff}
		colScaleBlue = color.RGBA{R: 0x00, G: 0x55, B: 0xaa, A: 0xff}
		colYellow    = color.RGBA{R: 0xff, G: 0xff, B: 0x00, A: 0xff}
		colMagenta   = color.RGBA{R: 0xff, G: 0x00, B: 0xff, A: 0xff}
		colCyan      = color.RGBA{R: 0x00, G: 0xff, B: 0xff, A: 0xff}
		colOrange    = color.RGBA{R: 0xff, G: 0x80, B: 0x00, A: 0xff}
	)

	// 1. Verify Window Manager Title Bar and Close Button (above canvas at y: -20..0)
	titleBarRect := relRect(5, -18, 370, -2)
	tbDark, tbTotal := countColorInRect(afterImg, titleBarRect, colTitleBar, tol)
	tbWhite, _ := countColorInRect(afterImg, titleBarRect, colWhite, 40)
	closeBtnRect := relRect(380, -18, 399, -2)
	closeRed, closeTotal := countColorInRect(afterImg, closeBtnRect, colRed, tol)
	log.Printf("Visual check [TitleBar]: dark=%d/%d, titleTextWhite=%d, closeBtnRed=%d/%d", tbDark, tbTotal, tbWhite, closeRed, closeTotal)
	if tbDark < tbTotal/2 {
		return fmt.Errorf("title bar background not rendered: got %d/%d #333333 pixels", tbDark, tbTotal)
	}
	if tbWhite < 20 {
		return fmt.Errorf("title bar text 'Tkinter Test UI' not rendered: got %d white pixels", tbWhite)
	}
	if closeRed < closeTotal/3 {
		return fmt.Errorf("title bar close button not rendered: got %d/%d red pixels", closeRed, closeTotal)
	}

	// 2. Verify Root Window Background (#e0e0e0)
	rootBgRect := relRect(5, 30, 45, 400)
	rootGray, rootTotal := countColorInRect(afterImg, rootBgRect, colRootGray, tol)
	log.Printf("Visual check [RootBackground]: gray=%d/%d", rootGray, rootTotal)
	if rootGray < rootTotal*8/10 {
		return fmt.Errorf("root window background (#e0e0e0) not rendered: got %d/%d pixels", rootGray, rootTotal)
	}

	// 3. Verify Entry Widget (x=50, y=30, w=300, h=30) before & after typing text
	entryRect := relRect(65, 35, 340, 55)
	entryWhiteBefore, entryTotal := countColorInRect(beforeImg, entryRect, colWhite, tol)
	entryBlackBefore, _ := countColorInRect(beforeImg, entryRect, colBlack, 60)
	entryWhiteAfter, _ := countColorInRect(afterImg, entryRect, colWhite, tol)
	entryBlackAfter, _ := countColorInRect(afterImg, entryRect, colBlack, 60)
	log.Printf("Visual check [Entry]: before(white=%d/%d, black=%d), after(white=%d/%d, black=%d)",
		entryWhiteBefore, entryTotal, entryBlackBefore, entryWhiteAfter, entryTotal, entryBlackAfter)
	if entryWhiteBefore < entryTotal*9/10 {
		return fmt.Errorf("entry widget white background not rendered before typing: got %d/%d white pixels", entryWhiteBefore, entryTotal)
	}
	if entryBlackBefore != 0 {
		return fmt.Errorf("expected empty entry widget before typing, got %d dark pixels", entryBlackBefore)
	}
	if entryBlackAfter < 50 {
		return fmt.Errorf("typed text in entry widget not rendered: got only %d dark pixels after typing", entryBlackAfter)
	}

	// 4. Verify Checkbutton (x=50, y=80) indicator & label text
	// In Tk 8.6, selectcolor="#ff0000" fills the indicator box with red (81px when unchecked),
	// and checking it draws a black checkmark inside the red box (reducing red pixels to ~60px).
	checkIndRect := relRect(50, 80, 80, 110)
	checkLabelRect := relRect(75, 80, 260, 110)
	checkRedBefore, _ := countColorInRect(beforeImg, checkIndRect, colRed, tol)
	checkRedAfter, _ := countColorInRect(afterImg, checkIndRect, colRed, tol)
	checkTextBlack, _ := countColorInRect(afterImg, checkLabelRect, colBlack, 60)
	log.Printf("Visual check [Checkbutton]: redBefore=%d, redAfter=%d, labelBlack=%d", checkRedBefore, checkRedAfter, checkTextBlack)
	if checkRedBefore < 60 {
		return fmt.Errorf("checkbutton red indicator box not rendered before clicking: got %d red pixels", checkRedBefore)
	}
	if checkRedAfter < 40 || checkRedBefore-checkRedAfter < 10 {
		return fmt.Errorf("checkbutton checkmark not drawn inside indicator after clicking: redBefore=%d, redAfter=%d", checkRedBefore, checkRedAfter)
	}
	if checkTextBlack < 40 {
		return fmt.Errorf("checkbutton label 'Enable Feature' not rendered: got %d dark pixels", checkTextBlack)
	}

	// 5. Verify Radiobuttons (Option A at x=50, y=130; Option B at x=180, y=130)
	// Both indicators have red background (#ff0000); the selected one has a black center dot
	// (so fewer red pixels when selected, and more red pixels when unselected).
	radioAIndRect := relRect(50, 130, 80, 160)
	radioBIndRect := relRect(180, 130, 210, 160)
	radioALabelRect := relRect(75, 130, 175, 160)
	radioBLabelRect := relRect(205, 130, 310, 160)
	radioARedBefore, _ := countColorInRect(beforeImg, radioAIndRect, colRed, tol)
	radioARedAfter, _ := countColorInRect(afterImg, radioAIndRect, colRed, tol)
	radioBRedBefore, _ := countColorInRect(beforeImg, radioBIndRect, colRed, tol)
	radioBRedAfter, _ := countColorInRect(afterImg, radioBIndRect, colRed, tol)
	radioATextBlack, _ := countColorInRect(afterImg, radioALabelRect, colBlack, 60)
	radioBTextBlack, _ := countColorInRect(afterImg, radioBLabelRect, colBlack, 60)
	log.Printf("Visual check [Radiobuttons]: A(redBefore=%d, redAfter=%d, text=%d), B(redBefore=%d, redAfter=%d, text=%d)",
		radioARedBefore, radioARedAfter, radioATextBlack, radioBRedBefore, radioBRedAfter, radioBTextBlack)
	if radioARedBefore < 20 || radioBRedBefore < 30 || radioBRedBefore-radioARedBefore < 8 {
		return fmt.Errorf("initial radiobutton indicators wrong: Option A red=%d (selected with dot), Option B red=%d (unselected solid)", radioARedBefore, radioBRedBefore)
	}
	if radioARedAfter-radioARedBefore < 8 || radioBRedBefore-radioBRedAfter < 8 {
		return fmt.Errorf("post-click radiobutton indicators did not swap selection dot: A(%d->%d), B(%d->%d)",
			radioARedBefore, radioARedAfter, radioBRedBefore, radioBRedAfter)
	}
	if radioATextBlack < 25 || radioBTextBlack < 25 {
		return fmt.Errorf("radiobutton labels not rendered: Option A text=%d, Option B text=%d", radioATextBlack, radioBTextBlack)
	}

	// 6. Verify Scale Widget (x=50, y=180, w=300, h=45): blue body (#0055aa) & yellow trough (#ffff00)
	scaleFullRect := relRect(50, 180, 350, 225)
	scaleTroughLeft := relRect(52, 195, 110, 223)
	scaleTroughRight := relRect(280, 195, 348, 223)
	scaleBlueCount, _ := countColorInRect(afterImg, scaleFullRect, colScaleBlue, tol)
	yellowLeftBefore, _ := countColorInRect(beforeImg, scaleTroughLeft, colYellow, tol)
	yellowLeftAfter, _ := countColorInRect(afterImg, scaleTroughLeft, colYellow, tol)
	yellowRightBefore, _ := countColorInRect(beforeImg, scaleTroughRight, colYellow, tol)
	yellowRightAfter, _ := countColorInRect(afterImg, scaleTroughRight, colYellow, tol)
	log.Printf("Visual check [Scale]: blue=%d, troughLeftYellow(before=%d, after=%d), troughRightYellow(before=%d, after=%d)",
		scaleBlueCount, yellowLeftBefore, yellowLeftAfter, yellowRightBefore, yellowRightAfter)
	if scaleBlueCount < 1000 {
		return fmt.Errorf("scale widget blue body (#0055aa) not rendered: got %d pixels", scaleBlueCount)
	}
	if yellowRightBefore < 300 {
		return fmt.Errorf("scale widget yellow trough (#ffff00) not rendered: got %d yellow pixels on right before click", yellowRightBefore)
	}
	if yellowLeftAfter <= yellowLeftBefore+100 || yellowRightAfter >= yellowRightBefore-100 {
		return fmt.Errorf("scale slider thumb did not visually move from left to right: leftYellow(%d->%d), rightYellow(%d->%d)",
			yellowLeftBefore, yellowLeftAfter, yellowRightBefore, yellowRightAfter)
	}

	// 7. Verify Listbox Widget (x=50, y=240, w=300, h=80) items and 'Cherry' selection highlight
	listboxRect := relRect(55, 242, 345, 318)
	cherryRowRect := relRect(55, 265, 345, 290)
	lbWhiteBefore, lbTotal := countColorInRect(beforeImg, listboxRect, colWhite, tol)
	lbBlackBefore, _ := countColorInRect(beforeImg, listboxRect, colBlack, 60)
	lbBlueBefore, _ := countColorInRect(beforeImg, listboxRect, colBlue, tol)
	cherryBlueAfter, _ := countColorInRect(afterImg, cherryRowRect, colBlue, tol)
	cherryWhiteAfter, _ := countColorInRect(afterImg, cherryRowRect, colWhite, 40)
	log.Printf("Visual check [Listbox]: before(white=%d/%d, blackText=%d, blue=%d), afterCherryRow(blue=%d, whiteText=%d)",
		lbWhiteBefore, lbTotal, lbBlackBefore, lbBlueBefore, cherryBlueAfter, cherryWhiteAfter)
	if lbWhiteBefore < lbTotal*7/10 || lbBlackBefore < 80 {
		return fmt.Errorf("listbox initial items/background not rendered: white=%d/%d, blackText=%d", lbWhiteBefore, lbTotal, lbBlackBefore)
	}
	if lbBlueBefore != 0 {
		return fmt.Errorf("listbox should have no blue selection before click: got %d blue pixels", lbBlueBefore)
	}
	if cherryBlueAfter < 1000 || cherryWhiteAfter < 15 {
		return fmt.Errorf("listbox 'Cherry' selection highlight not rendered: blue=%d (want >=1000), whiteText=%d (want >=15)",
			cherryBlueAfter, cherryWhiteAfter)
	}

	// 8. Verify Submit Button (x=130, y=360, w=140, h=40): green background (#008000) & white text
	btnRect := relRect(135, 365, 265, 395)
	btnGreen, btnTotal := countColorInRect(afterImg, btnRect, colGreen, tol)
	btnWhiteText, _ := countColorInRect(afterImg, btnRect, colWhite, 40)
	log.Printf("Visual check [SubmitButton]: green=%d/%d, whiteText=%d", btnGreen, btnTotal, btnWhiteText)
	if btnGreen < btnTotal*6/10 || btnWhiteText < 25 {
		return fmt.Errorf("submit button not rendered correctly: green=%d/%d, whiteText=%d", btnGreen, btnTotal, btnWhiteText)
	}

	// 9. Verify Canvas Geometric Primitives (x=50, y=420, w=300, h=60)
	rectShape := relRect(65, 435, 125, 465)
	ovalShape := relRect(175, 440, 215, 460)
	polyShape := relRect(285, 448, 315, 465)
	magCount, magTotal := countColorInRect(afterImg, rectShape, colMagenta, tol)
	cyanCount, cyanTotal := countColorInRect(afterImg, ovalShape, colCyan, tol)
	orangeCount, orangeTotal := countColorInRect(afterImg, polyShape, colOrange, tol)
	log.Printf("Visual check [CanvasShapes]: magentaRect=%d/%d, cyanOval=%d/%d, orangePoly=%d/%d",
		magCount, magTotal, cyanCount, cyanTotal, orangeCount, orangeTotal)
	if magCount < magTotal*8/10 {
		return fmt.Errorf("canvas magenta rectangle not rendered: %d/%d pixels", magCount, magTotal)
	}
	if cyanCount < cyanTotal*7/10 {
		return fmt.Errorf("canvas cyan oval not rendered: %d/%d pixels", cyanCount, cyanTotal)
	}
	if orangeCount < orangeTotal*6/10 {
		return fmt.Errorf("canvas orange polygon not rendered: %d/%d pixels", orangeCount, orangeTotal)
	}

	// 10. Verify xterm window is also rendered cleanly on the left side of the viewport
	xtermRect := image.Rect(10, 25, 400, 300)
	xtermWhite, xtermTotal := countColorInRect(afterImg, xtermRect, colWhite, tol)
	xtermBlack, _ := countColorInRect(afterImg, xtermRect, colBlack, 60)
	// The 2px top margin right below the xterm title bar (y=21..23) must be pure white
	// (no stray PolyLine cursor lines from CoordModePrevious or spurious child window borders).
	xtermTopMargin := image.Rect(2, 21, 100, 23)
	xtermMarginWhite, xtermMarginTotal := countColorInRect(afterImg, xtermTopMargin, colWhite, tol)
	log.Printf("Visual check [XTerm]: white=%d/%d, blackText=%d, topMarginWhite=%d/%d",
		xtermWhite, xtermTotal, xtermBlack, xtermMarginWhite, xtermMarginTotal)
	if xtermWhite < xtermTotal*8/10 || xtermBlack < 30 {
		return fmt.Errorf("xterm window not rendered properly: white=%d/%d, blackText=%d", xtermWhite, xtermTotal, xtermBlack)
	}
	if xtermMarginWhite != xtermMarginTotal {
		return fmt.Errorf("stray lines detected near xterm title bar: only %d/%d pixels are white in top margin %v",
			xtermMarginWhite, xtermMarginTotal, xtermTopMargin)
	}

	log.Println("All 10 visual GUI rendering checks passed!")
	return nil
}

func logAction(s string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		log.Println(s)
		return nil
	})
}

func insertText(s string) chromedp.Action {
	return chromedp.Evaluate(fmt.Sprintf(`window.sshApp.term.input(%q)`, s), nil)
}

func pressEnter() chromedp.Action {
	return chromedp.Evaluate(`window.sshApp.term.input("\r")`, nil)
}

func waitForCanvases(n int) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		for {
			var count int
			err := chromedp.Evaluate(`document.querySelectorAll('div[id^="x11-window-"]').length`, &count).Do(ctx)
			if err != nil {
				return err
			}
			if count >= n {
				log.Printf("Found %d X11 windows!", count)
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(1 * time.Second):
			}
		}
	})
}

func waitForTerminalText(text string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		target := strings.ToLower(text)
		for {
			var termText string
			err := chromedp.Evaluate(`
				(function() {
					try {
						if (window.sshApp && window.sshApp.term) {
							const term = window.sshApp.term;
							let s = "";
							const active = term.buffer.active;
							for (let i = 0; i < active.length; i++) {
								const line = active.getLine(i);
								if (line) s += line.translateToString() + "\n";
							}
							return s;
						}
						return "DEBUG: no term object";
					} catch (e) {
						return "DEBUG: error: " + e.message;
					}
				})()
			`, &termText).Do(ctx)
			if err != nil {
				return err
			}
			if termText != "DEBUG: no term object" && !strings.HasPrefix(termText, "DEBUG: error") {
				if strings.Contains(strings.ToLower(termText), target) {
					return nil
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
	})
}
