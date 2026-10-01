package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var borderStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#52677B"))

func fit(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) > width {
		s = ansi.Truncate(s, width, "…")
	}
	return s + strings.Repeat(" ", max(0, width-lipgloss.Width(s)))
}

func panel(title string, width, height int, body []string) []string {
	inner := width - 2
	title = ansi.Truncate(title, max(1, inner-4), "…")
	top := borderStyle.Render("╭─ ") + brand.Render(title) + borderStyle.Render(" "+strings.Repeat("─", max(0, width-5-lipgloss.Width(title)))+"╮")
	lines := []string{top}
	for i := 0; i < height-2; i++ {
		content := ""
		if i < len(body) {
			content = body[i]
		}
		lines = append(lines, borderStyle.Render("│")+fit(content, inner)+borderStyle.Render("│"))
	}
	lines = append(lines, borderStyle.Render("╰"+strings.Repeat("─", inner)+"╯"))
	return lines
}

func short(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= n {
		return s
	}
	return ansi.Truncate(s, n, "…")
}

func (m *dashboard) addHit(x0, x1, y int, action string, index int) {
	m.hits = append(m.hits, hitbox{x0: x0, x1: x1, y: y, action: action, index: index})
}

func (m *dashboard) buttonRow(buttons [][2]string, y, width int) string {
	var line strings.Builder
	line.WriteString("  ")
	x := 2
	for _, button := range buttons {
		label := "[" + button[0] + "] " + button[1]
		if x+len(label) >= width {
			break
		}
		line.WriteString(accent.Render(label))
		m.addHit(x, x+len(label), y, button[0], -1)
		x += len(label) + 2
		line.WriteString("  ")
	}
	return fit(line.String(), width)
}

func (m *dashboard) dashboardView() string {
	w, h := m.width, m.height
	if w < 72 || h < 20 {
		return brand.Render("WGX") + "\n\nResize the terminal to at least 72 columns × 20 rows.\n"
	}
	m.hits = nil
	leftW, rightW := min(37, max(28, w/3)), 0
	rightW = w - leftW - 1
	mainH := h - 12
	state := warn.Render("STOPPED")
	if m.telemetry.Up {
		state = brand.Render("RUNNING")
	}
	recent := 0
	for _, p := range m.peers {
		if seen := m.clients[p.PublicKey].LastSeen; !seen.IsZero() && time.Since(seen) < 3*time.Minute {
			recent++
		}
	}
	clientWord := "clients"
	if len(m.peers) == 1 {
		clientWord = "client"
	}
	header := panel("WGX  /  WIREGUARD EXCHANGE", w, 3, []string{
		"  " + bright.Render(m.a.iface()) + "  " + state + "   " + muted.Render(fmt.Sprintf("%d %s  •  %d recent handshakes  •  refresh 5s", len(m.peers), clientWord, recent)),
	})

	left := make([]string, mainH-2)
	if m.telemetry.Up {
		left[0] = "  " + brand.Render("● INTERFACE UP")
		left[1] = muted.Render(fmt.Sprintf("  UDP %d  •  %d %s", m.telemetry.ListenPort, len(m.peers), clientWord))
	} else {
		left[0] = "  " + warn.Render("● INTERFACE DOWN")
		left[1] = muted.Render(fmt.Sprintf("  %d configured clients", len(m.peers)))
	}
	left[2] = "  " + accent.Render("[u] up") + "  " + accent.Render("[x] down")
	m.addHit(3, 9, 3+1+2, "u", -1)
	m.addHit(11, 19, 3+1+2, "x", -1)
	left[3] = muted.Render("  " + strings.Repeat("─", max(1, leftW-6)))
	left[4] = accent.Render(fmt.Sprintf("  CLIENTS  %d", len(m.peers)))
	m.rowY = 3 + 1 + 5
	visible := m.visibleRows()
	for i := 0; i < visible && 5+i < len(left); i++ {
		idx := m.scroll + i
		if idx >= len(m.peers) {
			break
		}
		p := m.peers[idx]
		seen := m.clients[p.PublicKey].LastSeen
		age := "never"
		if !seen.IsZero() {
			age = short(strings.TrimPrefix(lastSeenLabel(seen, time.Now()), "Seen "), 9)
		}
		nameWidth := leftW - 7 - len(age)
		label := fmt.Sprintf("  %-*s %s", nameWidth, short(p.Name, nameWidth), age)
		if idx == m.selected {
			left[5+i] = rowSelected.Render(fit(label, leftW-2))
		} else {
			left[5+i] = bright.Render(label)
		}
		m.addHit(1, leftW-1, m.rowY+i, "select", idx)
	}
	if len(m.peers) == 0 && len(left) > 5 {
		left[5] = muted.Render("  Press n to add a client")
	}
	leftPanel := panel("INTERFACE  /  "+m.a.iface(), leftW, mainH, left)

	right := make([]string, mainH-2)
	title := "CLIENT DETAILS"
	if m.selected >= 0 && m.selected < len(m.peers) {
		p := m.peers[m.selected]
		meta := m.clients[p.PublicKey]
		live := m.telemetry.Peers[p.PublicKey]
		title = "CLIENT  /  " + p.Name
		rows := []string{
			"  " + accent.Render(short(p.Name, rightW-8)) + "   " + muted.Render(func() string {
				if p.Managed {
					return "managed"
				}
				return "adopted"
			}()),
			"  " + muted.Render("ADDRESS    ") + bright.Render(short(p.AllowedIPs, rightW-16)),
			"  " + muted.Render("LAST SEEN  ") + bright.Render(lastSeenLabel(meta.LastSeen, time.Now())),
			"  " + muted.Render("HANDSHAKE  ") + func() string {
				if meta.LastSeen.IsZero() {
					return "—"
				}
				return meta.LastSeen.Local().Format("2006-01-02 15:04:05")
			}(),
			"  " + muted.Render("ENDPOINT   ") + short(live.Endpoint, rightW-16),
			"  " + muted.Render("RECEIVED   ") + humanBytes(live.Received),
			"  " + muted.Render("SENT       ") + humanBytes(live.Sent),
			"  " + muted.Render("PUBLIC KEY ") + short(p.PublicKey, rightW-16),
			"  " + muted.Render("NOTE       ") + short(meta.Note, rightW-16),
		}
		if live.Endpoint == "" {
			rows[4] = "  " + muted.Render("ENDPOINT   —")
		}
		if meta.Note == "" {
			rows[8] = "  " + muted.Render("NOTE       —  [p] edit")
		}
		if p.Managed {
			rows = append(rows, "  "+muted.Render("[e] Share profile  [m] Rename"))
		} else {
			rows = append(rows, "  "+muted.Render("[m] Rename  [p] Add note"))
		}
		copy(right, rows)
	} else {
		right[0] = muted.Render("  Select a client to inspect it")
	}
	rightPanel := panel(title, rightW, mainH, right)

	lines := append([]string{}, header...)
	for i := range leftPanel {
		lines = append(lines, leftPanel[i]+" "+rightPanel[i])
	}
	activity := make([]string, 4)
	for i := 0; i < len(activity) && i < len(m.events); i++ {
		e := m.events[len(m.events)-1-i]
		activity[i] = "  " + muted.Render(e.At.Local().Format("15:04:05")) + "  " + bright.Render(short(e.Message, w-18))
	}
	if len(m.events) == 0 {
		activity[0] = muted.Render("  Actions taken in wgx will appear here. Press l for logs.")
	}
	lines = append(lines, panel("ACTIVITY  /  [l] OPEN LOGS", w, 6, activity)...)
	m.addHit(14, 28, 3+mainH, "l", -1)
	m.actionY = len(lines)
	lines = append(lines, m.buttonRow([][2]string{{"n", "new"}, {"m", "rename"}, {"p", "note"}, {"d", "delete"}, {"e", "share"}, {"l", "logs"}}, len(lines), w))
	m.actionY2 = len(lines)
	lines = append(lines, m.buttonRow([][2]string{{"u", "up"}, {"x", "down"}, {"a", "apply"}, {"r", "refresh"}, {"q", "quit"}}, len(lines), w))
	message := muted.Render("  Handshake age is an observation, not a connection guarantee.")
	if m.message != "" {
		message = "  " + warn.Render(short(m.message, w-4))
	}
	lines = append(lines, fit(message, w))
	return strings.Join(lines, "\n")
}

func (m *dashboard) modalView() string {
	w := max(72, m.width)
	title, prompt := "", ""
	switch m.mode {
	case "add":
		title, prompt = "NEW CLIENT", "Give this client a clear name"
	case "rename":
		title, prompt = "RENAME CLIENT", "New display name"
	case "note":
		title, prompt = "CLIENT NOTE", "One line to identify this device or owner"
	case "delete":
		title, prompt = "REMOVE CLIENT", "This revokes the peer and deletes its saved profile"
	}
	body := []string{"", "  " + bright.Render(prompt), ""}
	if m.mode == "delete" {
		name := ""
		if m.selected >= 0 && m.selected < len(m.peers) {
			name = m.peers[m.selected].Name
		}
		body = append(body, "  "+warn.Render("Delete "+name+"?"), "", "  "+accent.Render("[y] Confirm")+"   "+muted.Render("[n] Cancel"))
	} else {
		body = append(body, "  "+accent.Render("› ")+m.input+"█", "", "  "+muted.Render("enter save  •  esc cancel"))
	}
	if m.message != "" {
		body = append(body, "", "  "+warn.Render(short(m.message, w-10)))
	}
	box := panel(title, min(68, w), len(body)+2, body)
	return strings.Join(append([]string{"  " + brand.Render("WGX") + "  " + muted.Render("/ control plane"), ""}, box...), "\n")
}

func (m *dashboard) logsView() string {
	w, h := m.width, m.height
	if w < 72 || h < 20 {
		return "Resize the terminal to at least 72 columns × 20 rows."
	}
	m.hits = nil
	header := panel("WGX  /  LOGS", w, 3, []string{"  " + muted.Render(m.a.iface()+"  •  activity is saved locally; system entries come from journalctl")})
	entries := []string{}
	title := "ACTIVITY"
	if m.logSource == "system" {
		title = "SYSTEM JOURNAL  /  wg-quick@" + m.a.iface()
		for _, line := range m.journal {
			entries = append(entries, line)
		}
		if m.journalErr != "" {
			entries = append(entries, "System journal unavailable: "+m.journalErr)
		}
	} else {
		for _, e := range m.events {
			entries = append(entries, e.At.Local().Format("2006-01-02 15:04:05")+"  "+strings.ToUpper(e.Kind)+"  "+e.Message)
		}
	}
	if len(entries) == 0 {
		entries = []string{"No entries yet."}
	}
	visible := h - 7
	maxOffset := max(0, len(entries)-visible)
	if m.logOffset > maxOffset {
		m.logOffset = maxOffset
	}
	start := max(0, len(entries)-visible-m.logOffset)
	body := make([]string, visible)
	for i := 0; i < visible && start+i < len(entries); i++ {
		body[i] = "  " + bright.Render(short(entries[start+i], w-6))
	}
	lines := append([]string{}, header...)
	lines = append(lines, panel(title, w, h-5, body)...)
	line := "  " + accent.Render("[1] activity") + "  " + accent.Render("[2] system") + "  " + accent.Render("[b] back") + "  " + muted.Render("↑↓ scroll  •  r refresh")
	m.addHit(2, 14, len(lines), "activity", -1)
	m.addHit(16, 26, len(lines), "system", -1)
	m.addHit(28, 36, len(lines), "back", -1)
	lines = append(lines, fit(line, w))
	return strings.Join(lines, "\n")
}
