package scanner

import (
	"fmt"
	"github.com/rivo/tview"
)

type ScanOutput interface {
	Println(a ...any)
	Printf(format string, a ...any)
}

type TextOutput struct {
	View *tview.TextView
}

func (t *TextOutput) Println(a ...any) {
	_, err := fmt.Fprintln(t.View, a...)
	if err != nil {
		return
	}
}

func (t *TextOutput) Printf(format string, a ...any) {
	_, err := fmt.Fprintf(t.View, format, a...)
	if err != nil {
		return
	}
}
