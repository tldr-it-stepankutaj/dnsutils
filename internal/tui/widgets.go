package tui

import (
	"github.com/rivo/tview"
)

// CreateForm create form
func CreateForm(app *tview.Application, startScan func(domain string, modules []string)) *tview.Form {
	var (
		domainInput *tview.InputField
		dnsCheck    *tview.Checkbox
		subCheck    *tview.Checkbox
		sslCheck    *tview.Checkbox
		cloudCheck  *tview.Checkbox
		secCheck    *tview.Checkbox
	)

	form := tview.NewForm()

	domainInput = tview.NewInputField().
		SetLabel("Domain: ").
		SetFieldWidth(25)

	dnsCheck = tview.NewCheckbox().
		SetLabel("DNS records").
		SetChecked(true)

	subCheck = tview.NewCheckbox().
		SetLabel("Subdomain").
		SetChecked(true)

	sslCheck = tview.NewCheckbox().
		SetLabel("SSL certificates").
		SetChecked(true)

	cloudCheck = tview.NewCheckbox().
		SetLabel("Cloud infrastructure").
		SetChecked(false)

	secCheck = tview.NewCheckbox().
		SetLabel("Email security check").
		SetChecked(false)

	form.AddFormItem(domainInput)
	form.AddFormItem(dnsCheck)
	form.AddFormItem(subCheck)
	form.AddFormItem(sslCheck)
	form.AddFormItem(cloudCheck)
	form.AddFormItem(secCheck)

	form.AddButton("Start analyze", func() {
		domain := domainInput.GetText()
		var modules []string
		if dnsCheck.IsChecked() {
			modules = append(modules, "DNS")
		}
		if subCheck.IsChecked() {
			modules = append(modules, "Subdomain")
		}
		if sslCheck.IsChecked() {
			modules = append(modules, "SSL")
		}
		if cloudCheck.IsChecked() {
			modules = append(modules, "Cloud")
		}
		if secCheck.IsChecked() {
			modules = append(modules, "Security")
		}
		startScan(domain, modules)
	})

	form.AddButton("End", func() {
		app.Stop()
	})

	form.SetBorder(true).SetTitle(" ⚙️ DNSUtils Setup ").SetTitleAlign(tview.AlignLeft)
	return form
}
