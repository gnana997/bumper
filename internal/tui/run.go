package tui

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/gnana997/bumper/internal/engine"
	"github.com/gnana997/bumper/internal/rules"
	"github.com/gnana997/bumper/internal/setup"
)

// isTTY reports whether stdout is an interactive terminal. The TUI refuses to
// run when piped/redirected (CI) — the default text/json/sarif output is for
// those cases.
func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// RunFindings launches the hazard console for a scanned plan. target is the
// plan name shown in the navbar.
func RunFindings(fs []engine.Finding, set *rules.Set, llm, target string) error {
	if !isTTY() {
		return fmt.Errorf("the TUI needs an interactive terminal (stdout is not a TTY); use --format text instead")
	}
	_, err := tea.NewProgram(NewFindings(fs, set, llm, target), tea.WithAltScreen()).Run()
	return err
}

// RunRules launches the hazard console as a rule-set browser.
func RunRules(rs []*rules.Rule) error {
	if !isTTY() {
		return fmt.Errorf("the TUI needs an interactive terminal (stdout is not a TTY)")
	}
	_, err := tea.NewProgram(NewRules(rs), tea.WithAltScreen()).Run()
	return err
}

// RunInit launches the interactive init wizard, seeded with the given default
// scopes. It applies the chosen configuration itself; the returned InitResult
// lets the caller leave a persistent record after the alt-screen is torn down.
func RunInit(env setup.Env, mcp, hook setup.Scope) (InitResult, error) {
	if !isTTY() {
		return InitResult{}, fmt.Errorf("the init wizard needs an interactive terminal; re-run with --yes for non-interactive setup")
	}
	final, err := tea.NewProgram(newInitModel(env, mcp, hook), tea.WithAltScreen()).Run()
	if err != nil {
		return InitResult{}, err
	}
	if im, ok := final.(initModel); ok {
		return im.result(), nil
	}
	return InitResult{}, nil
}
