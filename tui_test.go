package main

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestDashboardMouseSelectionAndAction(t *testing.T) {
	m := &dashboard{
		a:        testAdmin(t),
		peers:    []Peer{{Name: "phone", AllowedIPs: "10.44.0.2/32", Managed: true}},
		selected: -1, width: 90, height: 28,
	}
	m.View()
	m.Update(tea.MouseMsg{X: 3, Y: m.rowY, Type: tea.MouseLeft})
	if m.selected != 0 {
		t.Fatalf("mouse did not select first peer: %d", m.selected)
	}
	m.Update(tea.MouseMsg{X: 3, Y: m.actionY, Type: tea.MouseLeft})
	if m.mode != "add" {
		t.Fatalf("new peer button did not open form: %q", m.mode)
	}
}
