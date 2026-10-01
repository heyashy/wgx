package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

func TestDashboardFitsStandardTerminal(t *testing.T) {
	m := &dashboard{a: testAdmin(t), width: 80, height: 24, selected: 0,
		peers:     []Peer{{Name: "workstation", PublicKey: strings.Repeat("A", 44), AllowedIPs: "10.44.0.2/32", Managed: true}},
		clients:   map[string]ClientMeta{strings.Repeat("A", 44): {Note: "Office laptop"}},
		telemetry: Telemetry{Peers: map[string]PeerTelemetry{}},
	}
	lines := strings.Split(m.View(), "\n")
	if len(lines) != 24 {
		t.Fatalf("rendered %d lines, want 24", len(lines))
	}
	for i, line := range lines {
		if width := lipgloss.Width(line); width > 80 {
			t.Fatalf("line %d is %d columns wide", i+1, width)
		}
	}
}
