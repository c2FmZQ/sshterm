// MIT License
//
// Copyright (c) 2025 TTBT Enterprises LLC
// Copyright (c) 2025 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//go:build wasm

package app

import (
	"github.com/urfave/cli/v2"

	"github.com/c2FmZQ/sshterm/internal/jsutil"
)

func (a *App) setTheme(t string) {
	switch t {
	case "light":
		a.cfg.Term.Get("options").Set("theme", jsutil.NewObject(map[string]any{
			"background":          "#e0e0e0",
			"foreground":          "black",
			"cursor":              "black",
			"cursorAccent":        "#e0e0e0",
			"selectionBackground": "black",
			"selectionForeground": "#e0e0e0",
		}))
		a.cfg.Term.Get("element").Get("parentElement").Set("style", "background-color: #e0e0e0;")
	case "dark":
		a.cfg.Term.Get("options").Set("theme", jsutil.NewObject(map[string]any{
			"background":          "black",
			"foreground":          "white",
			"cursor":              "white",
			"cursorAccent":        "black",
			"selectionBackground": "white",
			"selectionForeground": "black",
		}))
		a.cfg.Term.Get("element").Get("parentElement").Set("style", "background-color: black;")
	case "green":
		a.cfg.Term.Get("options").Set("theme", jsutil.NewObject(map[string]any{
			"background":          "#003000",
			"foreground":          "lightgreen",
			"cursor":              "lightgreen",
			"cursorAccent":        "#003000",
			"selectionBackground": "lightgreen",
			"selectionForeground": "#003000",
		}))
		a.cfg.Term.Get("element").Get("parentElement").Set("style", "background-color: #003000;")
	}
}

func (a *App) setCommand() *cli.App {
	ret := &cli.App{
		Name:            "set",
		Usage:           "Set parameters",
		UsageText:       "set theme",
		Description:     "The set command is used to change app parameters.",
		HideHelpCommand: true,
		Commands: []*cli.Command{
			{
				Name:      "theme",
				Usage:     "Set the color theme.",
				UsageText: "set theme <light|dark|green>",
				Action: func(ctx *cli.Context) error {
					if ctx.Args().Len() != 1 {
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
					switch v := ctx.Args().Get(0); v {
					case "light", "dark", "green":
						a.setTheme(v)
						a.data.Params["theme"] = v
						return a.saveParams()

					default:
						cli.ShowSubcommandHelp(ctx)
						return nil
					}
				},
			},
		},
	}
	return ret
}
