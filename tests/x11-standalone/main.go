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

	testCtx, testCancel := context.WithTimeout(sessionCtx, 5*time.Minute)
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
		waitForTerminalText(sessionCtx, "sshterm>"),
		
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Sending 'ep add' command...")
			return nil
		}),
		chromedp.Click(".xterm-rows", chromedp.ByQuery),
		insertText("ep add x11-apps wss://tester:8443/websocket"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		
		// Wait for next prompt
		waitForTerminalText(sessionCtx, "sshterm>"),
		
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Sending 'ssh -X' command...")
			return nil
		}),
		insertText("ssh -X testuser@x11-apps"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		
		waitForTerminalText(sessionCtx, "password:"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Found password prompt. Sending 'sshterm'...")
			return nil
		}),
		insertText("sshterm"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		
		waitForTerminalText(sessionCtx, "testuser@x11-apps:~$"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			log.Println("Connected! Launching multiple X11 applications with distinct positioning...")
			return nil
		}),

		// Launch xterm at top-left
		insertText("xterm -geometry 80x24+0+0 -e top &"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		chromedp.Sleep(1*time.Second),

		// Launch xeyes to the right of xterm
		insertText("xeyes -geometry 200x150+650+0 &"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		chromedp.Sleep(1*time.Second),

		// Launch xclock below xeyes
		insertText("xclock -geometry 200x200+650+200 &"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),
		chromedp.Sleep(1*time.Second),

		// Launch xmessage below xclock
		insertText("xmessage -geometry +650+450 'SSH Term X11 Test Successful' &"),
		chromedp.SendKeys(".xterm-helper-textarea", kb.Enter),

		logAction("Waiting for multiple X11 windows (canvases)..."),
		waitForCanvases(4),
		
		chromedp.Sleep(5*time.Second),
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
		var termText string
		_ = chromedp.Run(sessionCtx,
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

func waitForTerminalText(ctx context.Context, text string) chromedp.Action {
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
