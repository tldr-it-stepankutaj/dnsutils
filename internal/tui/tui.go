package tui

import (
	"fmt"
	"github.com/rivo/tview"

	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/scanner"
	"strings"
)

func RunTUI() {
	app := tview.NewApplication()

	outputView := tview.NewTextView()
	outputView.
		SetDynamicColors(true).
		SetScrollable(true).
		SetChangedFunc(func() {
			app.Draw()
		}).
		SetBorder(true).
		SetTitle(" Analyze result ")

	startScan := func(domain string, modules []string) {
		outputView.Clear()
		if strings.TrimSpace(domain) == "" {
			_, err := fmt.Fprintln(outputView, "[red]Error: enter domain![white]")
			if err != nil {
				return
			}
			return
		}

		results := &models.Results{
			Domain:        domain,
			Records:       make(map[string]interface{}),
			SubdomainData: make(map[string]models.SubdomainDetails),
		}

		go func() {
			_, err := fmt.Fprintf(outputView, "[yellow]Start analyze domain:[white] %s\n", domain)
			if err != nil {
				return
			}

			output := &scanner.TextOutput{View: outputView}

			for i, mod := range modules {
				_, err := fmt.Fprintf(outputView, "[green]✓ Modul active:[white] %s\n", mod)
				if err != nil {
					return
				}
				scanner.RunModule(domain, mod, "8.8.8.8:53", output, results)
				_, err = fmt.Fprintf(outputView, "[blue]→ Done:[white] %s (%d/%d)\n", mod, i+1, len(modules))
				if err != nil {
					return
				}
			}
			_, err = fmt.Fprintln(outputView, "[green]✔ All modules completed.")
			if err != nil {
				return
			}
		}()
	}

	form := CreateForm(app, startScan)

	layout := tview.NewFlex().
		AddItem(form, 60, 0, true).
		AddItem(outputView, 0, 1, false)

	if err := app.SetRoot(layout, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
