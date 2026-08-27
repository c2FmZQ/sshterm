package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/chromedp/chromedp/kb"
)

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
	for i := 0; i < 30; i++ {
		resp, err := client.Get(*targetURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				log.Printf("Target is ready!")
				break
			}
		}
		time.Sleep(1 * time.Second)
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

	testCtx, testCancel := context.WithTimeout(sessionCtx, *testTimeout)
	defer testCancel()

	var buf []byte
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
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		
		// Wait for next prompt
		waitForTerminalText("sshterm>"),
		
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Sending 'ssh -X' command...")
			return nil
		}),
		insertText("ssh -X testuser@x11-apps"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		
		waitForTerminalText("password:"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Found password prompt. Sending 'sshterm'...")
			return nil
		}),
		insertText("sshterm"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		
		waitForTerminalText("testuser@x11-apps:~$"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Connected! Launching multiple X11 applications with distinct positioning...")
			return nil
		}),

		// Launch xterm at top-left
		insertText("xterm -geometry 80x24+0+0 &"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		chromedp.Sleep(1*time.Second),

		// Launch test_ui.py with output redirected to a log file
		insertText("python3 /home/testuser/test_ui.py > /tmp/tkinter_ui.log 2>&1 &"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),

		logAction("Waiting for multiple X11 windows (canvases)..."),
		waitForCanvases(8),

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
						.find(s => s.innerText.toLowerCase().includes("tkinter"));
					return span ? span.id.replace("x11-window-title-", "") : "";
				})()
			`, &tkXID).Do(ctx)
			if err != nil || tkXID == "" {
				return fmt.Errorf("failed to find Tkinter window XID: %v", err)
			}
			log.Printf("Found Tkinter XID: %s", tkXID)

			canvasID := "#x11-canvas-" + tkXID
			windowID := "#x11-window-" + tkXID

			// Helper functions in Javascript to inject mouse events using deterministic pointer routing
			setupJS := `
				window.clickCanvasAt = function(canvasSelector, x, y) {
					const canvas = document.querySelector(canvasSelector);
					if (!canvas) return false;
					
					const parentWindow = canvas.parentNode;
					
					function findTargetWindow(win, rx, ry) {
						const children = Array.from(win.childNodes).filter(n => n.id && n.id.startsWith("x11-window-"));
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
			err = chromedp.Sleep(500 * time.Millisecond).Do(ctx)
			if err != nil {
				return err
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
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		waitForTerminalText(`"success": true`),
		waitForTerminalText(`"text": "WASM X11 test text"`),
		waitForTerminalText(`"checked": true`),
		waitForTerminalText(`"radio": 2`),
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
		chromedp.CaptureScreenshot(&buf),
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
			chromedp.Evaluate(`document.execCommand('insertText', false, "cat /tmp/tkinter_ui.log\n")`, nil),
			chromedp.Sleep(1 * time.Second),
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

	if err := os.WriteFile("x11-standalone-screenshot.png", buf, 0644); err != nil {
		log.Fatalf("Failed to save screenshot: %v", err)
	}
	log.Println("Test passed! Screenshot saved to x11-standalone-screenshot.png")
}

func logAction(s string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		log.Println(s)
		return nil
	})
}

func insertText(s string) chromedp.Action {
	return chromedp.Evaluate(fmt.Sprintf(`document.execCommand('insertText', false, %q)`, s), nil)
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
