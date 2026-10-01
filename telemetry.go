package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type PeerTelemetry struct {
	PublicKey     string
	Endpoint      string
	AllowedIPs    string
	LastHandshake time.Time
	Received      uint64
	Sent          uint64
}

type Telemetry struct {
	Up         bool
	PublicKey  string
	ListenPort int
	Peers      map[string]PeerTelemetry
	CheckedAt  time.Time
	Error      string
}

// WireGuard's dump is tab-separated. The first row describes the interface;
// subsequent rows describe peers. The first row contains a private key, which
// deliberately never enters Telemetry.
func parseDump(raw string) (Telemetry, error) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return Telemetry{}, errors.New("empty WireGuard dump")
	}
	interfaceFields := strings.Split(strings.TrimSpace(lines[0]), "\t")
	if len(interfaceFields) < 4 {
		return Telemetry{}, errors.New("invalid WireGuard interface row")
	}
	port, err := strconv.Atoi(interfaceFields[2])
	if err != nil {
		return Telemetry{}, fmt.Errorf("invalid WireGuard listen port: %w", err)
	}
	t := Telemetry{Up: true, PublicKey: interfaceFields[1], ListenPort: port, Peers: make(map[string]PeerTelemetry), CheckedAt: time.Now()}
	for _, line := range lines[1:] {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) < 8 {
			return Telemetry{}, errors.New("invalid WireGuard peer row")
		}
		stamp, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			return Telemetry{}, fmt.Errorf("invalid handshake timestamp: %w", err)
		}
		rx, err := strconv.ParseUint(fields[5], 10, 64)
		if err != nil {
			return Telemetry{}, fmt.Errorf("invalid received bytes: %w", err)
		}
		tx, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil {
			return Telemetry{}, fmt.Errorf("invalid sent bytes: %w", err)
		}
		p := PeerTelemetry{PublicKey: fields[0], Endpoint: fields[2], AllowedIPs: fields[3], Received: rx, Sent: tx}
		if stamp > 0 {
			p.LastHandshake = time.Unix(stamp, 0)
		}
		t.Peers[p.PublicKey] = p
	}
	return t, nil
}

func (a Admin) collectTelemetry() (Telemetry, map[string]ClientMeta) {
	out, err := runOutput("wg", "show", a.iface(), "dump")
	unlock, lockErr := a.lock()
	if lockErr == nil {
		defer unlock()
	}
	clients := a.loadClients()
	if err != nil {
		return Telemetry{Peers: make(map[string]PeerTelemetry), CheckedAt: time.Now(), Error: err.Error()}, clients
	}
	t, err := parseDump(out)
	if err != nil {
		return Telemetry{Peers: make(map[string]PeerTelemetry), CheckedAt: time.Now(), Error: err.Error()}, clients
	}
	changed := false
	var handshakeEvents []string
	labels := make(map[string]string)
	if config, err := a.readConfig(); err == nil {
		_, peers := parseConfig(config)
		for _, peer := range peers {
			labels[peer.PublicKey] = peer.Name
		}
	}
	for key, peer := range t.Peers {
		meta := clients[key]
		if peer.LastHandshake.After(meta.LastSeen) {
			if meta.LastSeen.IsZero() || peer.LastHandshake.Sub(meta.LastSeen) > 10*time.Minute {
				name := labels[key]
				if meta.Name != "" {
					name = meta.Name
				}
				if name == "" {
					name = shortKey(key)
				}
				handshakeEvents = append(handshakeEvents, "Handshake observed from "+name)
			}
			meta.LastSeen = peer.LastHandshake
			clients[key] = meta
			changed = true
		}
	}
	if changed && lockErr == nil {
		if a.saveClients(clients) == nil {
			for _, message := range handshakeEvents {
				a.recordEvent("handshake", message)
			}
		}
	}
	return t, clients
}

type Event struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
}

func (a Admin) eventsPath() string { return filepath.Join(a.stateDir(), "activity.jsonl") }

func (a Admin) recordEvent(kind, message string) {
	if err := os.MkdirAll(a.stateDir(), 0700); err != nil {
		return
	}
	f, err := os.OpenFile(a.eventsPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	b, err := json.Marshal(Event{At: time.Now().UTC(), Kind: kind, Message: message})
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
}

func (a Admin) recentEvents(limit int) []Event {
	f, err := os.Open(a.eventsPath())
	if err != nil {
		return nil
	}
	defer f.Close()
	var events []Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e Event
		if json.Unmarshal(scanner.Bytes(), &e) == nil {
			events = append(events, e)
			if len(events) > limit {
				events = events[1:]
			}
		}
	}
	return events
}

func (a Admin) systemJournal(limit int) ([]string, error) {
	unit := "wg-quick@" + a.iface() + ".service"
	out, err := exec.Command("journalctl", "--no-pager", "--output=short-iso", "-n", strconv.Itoa(limit), "-u", unit).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("system journal unavailable: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && (lines[0] == "" || strings.HasPrefix(lines[0], "-- No entries --")) {
		return nil, nil
	}
	return lines, nil
}

func humanBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for value >= 1024 && i < len(units)-1 {
		value /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", value, units[i])
}

func lastSeenLabel(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "Never seen"
	}
	if now.Sub(t) < time.Minute {
		return "Seen <1m ago"
	}
	if now.Sub(t) < time.Hour {
		return fmt.Sprintf("Seen %dm ago", int(now.Sub(t).Minutes()))
	}
	if now.Sub(t) < 24*time.Hour {
		return fmt.Sprintf("Seen %dh ago", int(now.Sub(t).Hours()))
	}
	return "Seen " + t.Local().Format("2006-01-02 15:04")
}
