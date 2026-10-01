package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	brand       = lipgloss.NewStyle().Foreground(lipgloss.Color("#8BE9D1")).Bold(true)
	muted       = lipgloss.NewStyle().Foreground(lipgloss.Color("#78899B"))
	bright      = lipgloss.NewStyle().Foreground(lipgloss.Color("#EDF6FF"))
	accent      = lipgloss.NewStyle().Foreground(lipgloss.Color("#A7B8FF")).Bold(true)
	warn        = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB380"))
	rowSelected = lipgloss.NewStyle().Background(lipgloss.Color("#22364A")).Foreground(lipgloss.Color("#FFFFFF")).Bold(true)
)

type dashboard struct {
	a             Admin
	peers         []Peer
	selected      int
	scroll        int
	width         int
	height        int
	mode          string
	input         string
	message       string
	rowY          int
	actionY       int
	actionY2      int
	setupAdopt    bool
	setupStep     int
	setupValues   []string
	shareName     string
	shareProfile  string
	shareQR       string
	shareTab      string
	secretVisible bool
	telemetry     Telemetry
	clients       map[string]ClientMeta
	events        []Event
	journal       []string
	journalErr    string
	logSource     string
	logOffset     int
	hits          []hitbox
}

type pulseMsg struct{}
type hitbox struct {
	x0, x1, y int
	action    string
	index     int
}

func pulse() tea.Cmd               { return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return pulseMsg{} }) }
func (m *dashboard) Init() tea.Cmd { return pulse() }

func (m *dashboard) refresh() {
	peers, err := m.a.peers()
	if err != nil {
		m.message = err.Error()
		m.peers = nil
		return
	}
	m.peers = peers
	m.telemetry, m.clients = m.a.collectTelemetry()
	m.events = m.a.recentEvents(100)
	if m.logSource == "system" {
		m.journal, err = m.a.systemJournal(100)
		if err != nil {
			m.journalErr = err.Error()
		} else {
			m.journalErr = ""
		}
	}
	if m.selected >= len(peers) {
		m.selected = len(peers) - 1
	}
	if m.selected < 0 && len(peers) > 0 {
		m.selected = 0
	}
}

func (m *dashboard) visibleRows() int {
	n := m.height - 19
	if n < 1 {
		n = 1
	}
	return n
}

func (m *dashboard) move(delta int) {
	if len(m.peers) == 0 {
		return
	}
	m.selected += delta
	if m.selected < 0 {
		m.selected = 0
	}
	if m.selected >= len(m.peers) {
		m.selected = len(m.peers) - 1
	}
	if m.selected < m.scroll {
		m.scroll = m.selected
	}
	if m.selected >= m.scroll+m.visibleRows() {
		m.scroll = m.selected - m.visibleRows() + 1
	}
}

func (m *dashboard) action(key string) {
	m.message = ""
	switch key {
	case "n":
		m.mode = "add"
		m.input = ""
		return
	case "d":
		if m.selected < 0 || m.selected >= len(m.peers) {
			m.message = "Select a peer first"
			return
		}
		if !m.peers[m.selected].Managed {
			m.message = "Existing peers are read-only"
			return
		}
		m.mode = "delete"
		return
	case "m", "p":
		if m.selected < 0 || m.selected >= len(m.peers) {
			m.message = "Select a client first"
			return
		}
		p := m.peers[m.selected]
		if key == "m" {
			m.mode = "rename"
			m.input = p.Name
		} else {
			m.mode = "note"
			m.input = m.clients[p.PublicKey].Note
		}
		return
	case "e":
		if m.selected < 0 || m.selected >= len(m.peers) {
			m.message = "Select a peer first"
			return
		}
		p := m.peers[m.selected]
		if !p.Managed {
			m.message = "No client profile is available for an existing peer"
			return
		}
		m.openShare(p.Name)
	case "r":
		m.refresh()
		if m.message == "" {
			m.message = "Refreshed"
		}
	case "a":
		if err := m.a.apply(); err != nil {
			m.message = err.Error()
		} else {
			m.message = "Live interface updated"
		}
		m.refresh()
	case "u":
		if err := m.a.up(); err != nil {
			m.message = err.Error()
		} else {
			m.message = "Interface started"
		}
		m.refresh()
	case "x":
		if err := m.a.down(); err != nil {
			m.message = err.Error()
		} else {
			m.message = "Interface stopped"
		}
		m.refresh()
	case "l":
		m.mode = "logs"
		m.logOffset = 0
		m.refresh()
	}
}

func (m *dashboard) logAction(action string) {
	switch action {
	case "activity":
		m.logSource = "activity"
		m.logOffset = 0
		m.refresh()
	case "system":
		m.logSource = "system"
		m.logOffset = 0
		m.refresh()
	case "back":
		m.mode = ""
	}
}

func (m *dashboard) openShare(name string) {
	profile, err := m.a.profile(name)
	if err != nil {
		m.message = err.Error()
		return
	}
	qr, err := m.a.qr(name, "")
	if err != nil {
		m.message = err.Error()
		return
	}
	m.shareName, m.shareProfile, m.shareQR = name, profile, qr
	m.shareTab, m.secretVisible, m.mode = "details", false, "share"
	m.message = ""
}

func (m *dashboard) setupPrompt() (string, string) {
	if m.setupAdopt {
		if m.setupStep == 0 {
			return "Public endpoint", "vpn.example.com:51820"
		}
		return "Client DNS", "1.1.1.1"
	}
	switch m.setupStep {
	case 0:
		return "Public endpoint", "vpn.example.com:51820"
	case 1:
		return "Tunnel address", "10.44.0.1/24"
	case 2:
		return "UDP listen port", "51820"
	default:
		return "Client DNS", "1.1.1.1"
	}
}

func (m *dashboard) submitSetup() {
	_, fallback := m.setupPrompt()
	value := strings.TrimSpace(m.input)
	if value == "" && m.setupStep > 0 {
		value = fallback
	}
	if value == "" {
		m.message = "Enter the server's public hostname or IP and UDP port"
		return
	}
	m.setupValues = append(m.setupValues, value)
	steps := 4
	if m.setupAdopt {
		steps = 2
	}
	if m.setupStep+1 < steps {
		m.setupStep++
		m.input = ""
		m.message = ""
		return
	}
	var err error
	if m.setupAdopt {
		err = m.a.adopt(Settings{Endpoint: m.setupValues[0], DNS: m.setupValues[1]})
	} else {
		var port int
		port, err = strconv.Atoi(m.setupValues[2])
		if err == nil {
			err = m.a.init(m.setupValues[1], port, Settings{Endpoint: m.setupValues[0], DNS: m.setupValues[3]})
		}
	}
	if err != nil {
		m.setupValues = m.setupValues[:len(m.setupValues)-1]
		m.message = err.Error()
		return
	}
	m.mode = ""
	m.message = "Server ready. Press u to start the interface, then n to add a peer."
	m.refresh()
}

func (m *dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case pulseMsg:
		if m.mode != "setup" {
			m.refresh()
		}
		return m, pulse()
	case tea.MouseMsg:
		if m.mode == "logs" {
			if msg.Type == tea.MouseWheelUp {
				m.logOffset++
			}
			if msg.Type == tea.MouseWheelDown && m.logOffset > 0 {
				m.logOffset--
			}
			if msg.Type == tea.MouseLeft {
				for _, h := range m.hits {
					if h.y == msg.Y && msg.X >= h.x0 && msg.X < h.x1 {
						m.logAction(h.action)
						break
					}
				}
			}
			return m, nil
		}
		if msg.Type == tea.MouseLeft && m.mode == "share" && msg.Y == m.actionY {
			if msg.X >= 2 && msg.X < 13 {
				m.shareTab = "details"
			}
			if msg.X >= 15 && msg.X < 21 {
				m.shareTab = "qr"
			}
			if msg.X >= 23 && msg.X < 31 {
				m.mode = ""
			}
			return m, nil
		}
		if msg.Type == tea.MouseLeft && m.mode == "setup" && msg.Y == m.actionY {
			m.submitSetup()
			return m, nil
		}
		if m.mode != "" {
			return m, nil
		}
		if msg.Type == tea.MouseWheelUp {
			m.move(-1)
		}
		if msg.Type == tea.MouseWheelDown {
			m.move(1)
		}
		if msg.Type == tea.MouseLeft {
			for _, h := range m.hits {
				if h.y == msg.Y && msg.X >= h.x0 && msg.X < h.x1 {
					if h.action == "select" {
						m.selected = h.index
					} else if h.action == "q" {
						return m, tea.Quit
					} else {
						m.action(h.action)
					}
					break
				}
			}
		}
	case tea.KeyMsg:
		if msg.Paste && (m.mode == "setup" || m.mode == "add" || m.mode == "rename" || m.mode == "note") {
			content := strings.TrimSpace(string(msg.Runes))
			if !strings.ContainsAny(content, "\r\n") {
				limit := 128
				if m.mode == "add" || m.mode == "rename" {
					limit = 32
				}
				if len(m.input)+len(content) <= limit {
					m.input += content
				}
			}
			return m, nil
		}
		key := msg.String()
		if m.mode == "setup" {
			switch key {
			case "ctrl+c":
				return m, tea.Quit
			case "enter":
				m.submitSetup()
			case "backspace":
				if len(m.input) > 0 {
					_, size := utf8.DecodeLastRuneInString(m.input)
					m.input = m.input[:len(m.input)-size]
				}
			case "esc":
				if m.setupStep > 0 {
					m.setupStep--
					m.input = m.setupValues[m.setupStep]
					m.setupValues = m.setupValues[:m.setupStep]
					m.message = ""
				}
			default:
				chars := string(msg.Runes)
				if chars != "" && !strings.ContainsAny(chars, "\r\n") && len(m.input)+len(chars) <= 128 {
					m.input += chars
				}
			}
			return m, nil
		}
		if m.mode == "share" {
			switch key {
			case "ctrl+c":
				return m, tea.Quit
			case "esc", "b", "q":
				m.mode = ""
				m.secretVisible = false
			case "1":
				m.shareTab = "details"
			case "2":
				m.shareTab = "qr"
			case "v":
				m.secretVisible = !m.secretVisible
			}
			return m, nil
		}
		if m.mode == "logs" {
			switch key {
			case "ctrl+c":
				return m, tea.Quit
			case "esc", "b", "q":
				m.mode = ""
			case "1":
				m.logAction("activity")
			case "2":
				m.logAction("system")
			case "r":
				m.refresh()
			case "up", "k":
				m.logOffset++
			case "down", "j":
				if m.logOffset > 0 {
					m.logOffset--
				}
			}
			return m, nil
		}
		if m.mode == "add" {
			switch key {
			case "esc":
				m.mode = ""
				m.input = ""
			case "enter":
				path, err := m.a.addAndApply(m.input)
				if err != nil {
					m.message = err.Error()
				} else {
					m.refresh()
					m.selected = len(m.peers) - 1
					m.openShare(m.input)
					if m.mode != "share" {
						m.message = "Created " + path
					}
				}
			case "backspace":
				if len(m.input) > 0 {
					_, size := utf8.DecodeLastRuneInString(m.input)
					m.input = m.input[:len(m.input)-size]
				}
			default:
				chars := string(msg.Runes)
				if chars != "" && !strings.ContainsAny(chars, "\r\n") && len(m.input)+len(chars) <= 32 {
					m.input += chars
				}
			}
			return m, nil
		}
		if m.mode == "delete" {
			switch key {
			case "y", "enter":
				name := m.peers[m.selected].Name
				if err := m.a.removeAndApply(name); err != nil {
					m.message = err.Error()
				} else {
					m.message = "Removed " + name
					m.refresh()
				}
				m.mode = ""
			case "n", "esc":
				m.mode = ""
			}
			return m, nil
		}
		if m.mode == "rename" || m.mode == "note" {
			switch key {
			case "esc":
				m.mode = ""
				m.input = ""
			case "enter":
				name := m.peers[m.selected].Name
				var err error
				if m.mode == "rename" {
					err = m.a.renamePeer(name, m.input)
				} else {
					err = m.a.setPeerNote(name, m.input)
				}
				if err != nil {
					m.message = err.Error()
				} else {
					m.mode = ""
					m.message = "Client details updated"
					m.refresh()
				}
			case "backspace":
				if len(m.input) > 0 {
					_, size := utf8.DecodeLastRuneInString(m.input)
					m.input = m.input[:len(m.input)-size]
				}
			default:
				chars := string(msg.Runes)
				limit := 160
				if m.mode == "rename" {
					limit = 32
				}
				if chars != "" && !strings.ContainsAny(chars, "\r\n") && len(m.input)+len(chars) <= limit {
					m.input += chars
				}
			}
			return m, nil
		}
		switch key {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			m.move(-1)
		case "down", "j":
			m.move(1)
		case "n", "d", "e", "m", "p", "l", "r", "a", "u", "x":
			m.action(key)
		}
	}
	return m, nil
}

func (m *dashboard) View() string {
	if m.mode == "setup" {
		return m.setupView()
	}
	if m.mode == "share" {
		return m.shareView()
	}
	if m.mode == "logs" {
		return m.logsView()
	}
	if m.mode == "add" || m.mode == "rename" || m.mode == "note" || m.mode == "delete" {
		return m.modalView()
	}
	return m.dashboardView()
}

func (m *dashboard) setupView() string {
	label, fallback := m.setupPrompt()
	title := "Create a WireGuard server"
	if m.setupAdopt {
		title = "Connect an existing WireGuard server"
	}
	stepCount := 4
	if m.setupAdopt {
		stepCount = 2
	}
	lines := []string{
		"  " + brand.Render("WGX") + "  " + muted.Render("/ first-run setup"),
		"",
		"  " + accent.Render(title),
		"  " + muted.Render(fmt.Sprintf("Step %d of %d", m.setupStep+1, stepCount)),
		"",
		"  " + bright.Render(label),
		"  " + brand.Render("› ") + m.input + "█",
		"  " + muted.Render("Default: "+fallback),
		"",
		"  " + muted.Render("The endpoint is the address clients can reach from outside this server."),
		"  " + muted.Render("Use your EC2 public DNS name or an Elastic IP with UDP 51820 open."),
		"",
	}
	m.actionY = len(lines)
	lines = append(lines, "  "+brand.Render("[enter] Continue")+"  "+muted.Render("esc back · ctrl+c quit"))
	if m.message != "" {
		lines = append(lines, "", "  "+warn.Render(m.message))
	}
	return strings.Join(lines, "\n")
}

func (m *dashboard) shareView() string {
	profilePath := m.a.profilePath(m.shareName)
	lines := []string{
		"  " + brand.Render("WGX") + "  " + muted.Render("/ peer onboarding"),
		"",
		"  " + accent.Render(m.shareName) + "  " + muted.Render("Ready to connect"),
		"  " + muted.Render("Keep this screen and client profile private; both contain the client key."),
		"",
	}
	m.actionY = len(lines)
	lines = append(lines, "  "+brand.Render("[1] Details")+"  "+bright.Render("[2] QR")+"  "+bright.Render("[b] Back"), "")
	if m.shareTab == "qr" {
		qrLines := strings.Split(m.shareQR, "\n")
		qrWidth := utf8.RuneCountInString(qrLines[0])
		if len(qrLines)+len(lines)+3 > m.height || qrWidth+4 > m.width {
			lines = append(lines, "  "+warn.Render(fmt.Sprintf("Enlarge the terminal to at least %d columns × %d rows to show the whole QR code.", qrWidth+4, len(qrLines)+len(lines)+3)))
		} else {
			lines = append(lines, "  "+muted.Render("Scan with the WireGuard mobile app:"))
			for _, line := range qrLines {
				lines = append(lines, "  "+line)
			}
		}
		lines = append(lines, "", "  "+muted.Render("Or transfer the profile file: "+profilePath))
		return strings.Join(lines, "\n")
	}
	lines = append(lines,
		"  "+bright.Render("Endpoint")+"       "+field(m.shareProfile, "Endpoint"),
		"  "+bright.Render("Client address")+" "+field(m.shareProfile, "Address"),
		"  "+bright.Render("DNS")+"            "+field(m.shareProfile, "DNS"),
		"  "+bright.Render("Routes")+"         "+field(m.shareProfile, "AllowedIPs"),
		"", "  "+bright.Render("Profile")+"  "+profilePath,
		"  "+muted.Render("Use 'wgx peer export "+m.shareName+" --output PATH' to save another copy."),
		"  "+muted.Render("Use 'wgx peer qr "+m.shareName+" --output PATH.png' to save a QR image."),
		"", "  "+muted.Render("Press v to show or hide the full client config."),
	)
	if m.secretVisible {
		lines = append(lines, "")
		for _, line := range strings.Split(strings.TrimSpace(m.shareProfile), "\n") {
			lines = append(lines, "  "+line)
		}
	}
	return strings.Join(lines, "\n")
}

func runTUI(a Admin) error {
	m := &dashboard{a: a, selected: -1, width: 90, height: 28}
	if err := a.validate(); err != nil {
		return err
	}
	if _, err := os.Stat(a.Config); errors.Is(err, os.ErrNotExist) {
		m.mode = "setup"
	} else if err != nil {
		return err
	} else if _, err := a.loadSettings(); err != nil {
		m.mode = "setup"
		m.setupAdopt = true
	} else {
		m.refresh()
	}
	_, err := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run()
	return err
}
