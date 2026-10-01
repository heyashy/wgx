package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Settings struct {
	Endpoint         string `json:"endpoint"`
	DNS              string `json:"dns"`
	ClientAllowedIPs string `json:"client_allowed_ips"`
}

type Peer struct {
	Name       string
	PublicKey  string
	AllowedIPs string
	Managed    bool
	Block      string
}

type Admin struct{ Config string }

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)
var hostRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*$`)
var peerRE = regexp.MustCompile(`(?m)^\[Peer\][ \t]*\r?$`)

func (a Admin) iface() string        { return strings.TrimSuffix(filepath.Base(a.Config), ".conf") }
func (a Admin) stateDir() string     { return filepath.Join(filepath.Dir(a.Config), "wgx", a.iface()) }
func (a Admin) settingsPath() string { return filepath.Join(a.stateDir(), "settings.json") }
func (a Admin) clientsPath() string  { return filepath.Join(a.stateDir(), "clients.json") }
func (a Admin) profilePath(name string) string {
	return filepath.Join(a.stateDir(), "peers", name+".conf")
}

func (a Admin) lock() (func(), error) {
	if err := os.MkdirAll(a.stateDir(), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(a.stateDir(), ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func (a Admin) validate() error {
	if filepath.Ext(a.Config) != ".conf" || !nameRE.MatchString(a.iface()) || len(a.iface()) > 15 {
		return errors.New("config must be an interface-named .conf file (for example wg0.conf)")
	}
	return nil
}

func keypair() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	b[0] &= 248
	b[31] &= 127
	b[31] |= 64
	priv, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()), base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func publicKey(private string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(private))
	if err != nil {
		return "", err
	}
	priv, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func field(section, key string) string {
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), key) {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func parseConfig(data string) (string, []Peer) {
	locs := peerRE.FindAllStringIndex(data, -1)
	if len(locs) == 0 {
		return data, nil
	}
	peers := make([]Peer, 0, len(locs))
	for i, loc := range locs {
		end := len(data)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := data[loc[0]:end]
		p := Peer{PublicKey: field(block, "PublicKey"), AllowedIPs: field(block, "AllowedIPs"), Block: block}
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "# wgx:name=") {
				p.Name = strings.TrimPrefix(line, "# wgx:name=")
				p.Managed = true
				break
			}
		}
		if p.Name == "" {
			p.Name = shortKey(p.PublicKey)
		}
		peers = append(peers, p)
	}
	return data[:locs[0][0]], peers
}

func shortKey(k string) string {
	if len(k) > 12 {
		return k[:12]
	}
	return k
}

func (a Admin) readConfig() (string, error) {
	if err := a.validate(); err != nil {
		return "", err
	}
	b, err := os.ReadFile(a.Config)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (a Admin) loadSettings() (Settings, error) {
	b, err := os.ReadFile(a.settingsPath())
	if err != nil {
		return Settings{}, fmt.Errorf("settings unavailable: run wgx adopt --endpoint HOST:PORT: %w", err)
	}
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		return s, err
	}
	return s, nil
}

func secureWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wgx-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (a Admin) saveSettings(s Settings) error {
	if s.Endpoint == "" {
		return errors.New("endpoint is required")
	}
	host, portText, err := net.SplitHostPort(s.Endpoint)
	if err != nil || host == "" {
		return errors.New("endpoint must be HOST:PORT (IPv6 hosts need brackets)")
	}
	if _, err := netip.ParseAddr(host); err != nil && !hostRE.MatchString(host) {
		return errors.New("endpoint host must be an IP address or hostname")
	}
	if _, err := parsePort(portText); err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}
	if s.DNS == "" {
		s.DNS = "1.1.1.1"
	}
	if s.ClientAllowedIPs == "" {
		s.ClientAllowedIPs = "0.0.0.0/0"
	}
	for _, value := range strings.Split(s.DNS, ",") {
		if _, err := netip.ParseAddr(strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("invalid DNS address %q", value)
		}
	}
	for _, value := range strings.Split(s.ClientAllowedIPs, ",") {
		if _, err := netip.ParsePrefix(strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("invalid client AllowedIPs %q", value)
		}
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return secureWrite(a.settingsPath(), append(b, '\n'))
}

func (a Admin) init(address string, port int, s Settings) error {
	if err := a.validate(); err != nil {
		return err
	}
	serverAddress, err := netip.ParsePrefix(address)
	if err != nil || !serverAddress.Addr().Is4() {
		return errors.New("address must be an IPv4 CIDR")
	}
	if port < 1 || port > 65535 {
		return errors.New("listen port must be 1-65535")
	}
	if s.Endpoint == "" {
		return errors.New("endpoint is required")
	}
	priv, _, err := keypair()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.Config), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(a.Config, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	content := fmt.Sprintf("[Interface]\nAddress = %s\nListenPort = %d\nPrivateKey = %s\n", address, port, priv)
	_, err = f.WriteString(content)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(a.Config)
		return err
	}
	if err := a.saveSettings(s); err != nil {
		os.Remove(a.Config)
		return err
	}
	a.recordEvent("server", "Created "+a.iface())
	return nil
}

func (a Admin) adopt(s Settings) error {
	data, err := a.readConfig()
	if err != nil {
		return err
	}
	if field(data, "PrivateKey") == "" || field(data, "Address") == "" {
		return errors.New("config needs Interface PrivateKey and Address")
	}
	if _, err := os.Stat(a.settingsPath()); err == nil {
		return errors.New("already adopted; use settings command to change settings")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := a.saveSettings(s); err != nil {
		return err
	}
	a.recordEvent("server", "Adopted "+a.iface())
	return nil
}

func (a Admin) peers() ([]Peer, error) {
	data, err := a.readConfig()
	if err != nil {
		return nil, err
	}
	_, peers := parseConfig(data)
	clients := a.loadClients()
	for i := range peers {
		if !peers[i].Managed {
			if name := clients[peers[i].PublicKey].Name; nameRE.MatchString(name) {
				peers[i].Name = name
			}
		}
	}
	return peers, nil
}

type ClientMeta struct {
	Name     string    `json:"name,omitempty"`
	Note     string    `json:"note,omitempty"`
	LastSeen time.Time `json:"last_seen,omitempty"`
}

func (a Admin) loadClients() map[string]ClientMeta {
	clients := make(map[string]ClientMeta)
	b, err := os.ReadFile(a.clientsPath())
	if err == nil {
		_ = json.Unmarshal(b, &clients)
		return clients
	}
	// Read state from older development builds if present.
	var aliases map[string]string
	if b, err := os.ReadFile(filepath.Join(a.stateDir(), "aliases.json")); err == nil {
		_ = json.Unmarshal(b, &aliases)
	}
	for key, name := range aliases {
		meta := clients[key]
		meta.Name = name
		clients[key] = meta
	}
	var seen map[string]time.Time
	if b, err := os.ReadFile(filepath.Join(a.stateDir(), "last-seen.json")); err == nil {
		_ = json.Unmarshal(b, &seen)
	}
	for key, at := range seen {
		meta := clients[key]
		meta.LastSeen = at
		clients[key] = meta
	}
	return clients
}

func (a Admin) saveClients(clients map[string]ClientMeta) error {
	if current, err := os.ReadFile(a.clientsPath()); err == nil {
		var valid map[string]ClientMeta
		if err := json.Unmarshal(current, &valid); err != nil {
			return fmt.Errorf("clients metadata is invalid; refusing to overwrite: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, err := json.MarshalIndent(clients, "", "  ")
	if err != nil {
		return err
	}
	return secureWrite(a.clientsPath(), append(b, '\n'))
}

func (a Admin) renamePeer(oldName, newName string) error {
	if !nameRE.MatchString(newName) {
		return errors.New("new name must be 1-32 letters, numbers, underscores or hyphens")
	}
	unlock, err := a.lock()
	if err != nil {
		return err
	}
	defer unlock()
	data, err := a.readConfig()
	if err != nil {
		return err
	}
	prefix, peers := parseConfig(data)
	clients := a.loadClients()
	for i := range peers {
		if !peers[i].Managed {
			if name := clients[peers[i].PublicKey].Name; nameRE.MatchString(name) {
				peers[i].Name = name
			}
		}
	}
	target := -1
	for i, p := range peers {
		if p.Name == newName && oldName != newName {
			return errors.New("name already in use")
		}
		if p.Name == oldName {
			target = i
		}
	}
	if target < 0 {
		return errors.New("peer not found")
	}
	if oldName == newName {
		return nil
	}
	p := peers[target]
	if p.Managed {
		oldPath, newPath := a.profilePath(oldName), a.profilePath(newName)
		if _, err := os.Stat(newPath); err == nil {
			return errors.New("destination profile already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		renamed := false
		if err := os.Rename(oldPath, newPath); err == nil {
			renamed = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		peers[target].Block = strings.Replace(p.Block, "# wgx:name="+oldName, "# wgx:name="+newName, 1)
		var out strings.Builder
		out.WriteString(prefix)
		for _, peer := range peers {
			out.WriteString(peer.Block)
		}
		if err := secureWrite(a.Config, []byte(out.String())); err != nil {
			if renamed {
				_ = os.Rename(newPath, oldPath)
			}
			return err
		}
	} else {
		meta := clients[p.PublicKey]
		meta.Name = newName
		clients[p.PublicKey] = meta
		if err := a.saveClients(clients); err != nil {
			return err
		}
	}
	a.recordEvent("peer", "Renamed "+oldName+" to "+newName)
	return nil
}

func (a Admin) setPeerNote(name, note string) error {
	if len(note) > 160 || strings.ContainsAny(note, "\r\n") {
		return errors.New("note must be one line, at most 160 characters")
	}
	unlock, err := a.lock()
	if err != nil {
		return err
	}
	defer unlock()
	peers, err := a.peers()
	if err != nil {
		return err
	}
	var key string
	for _, p := range peers {
		if p.Name == name {
			key = p.PublicKey
			break
		}
	}
	if key == "" {
		return errors.New("peer not found")
	}
	clients := a.loadClients()
	meta := clients[key]
	meta.Note = strings.TrimSpace(note)
	clients[key] = meta
	if err := a.saveClients(clients); err != nil {
		return err
	}
	a.recordEvent("peer", "Updated note for "+name)
	return nil
}

func nextAddress(data string, peers []Peer) (netip.Addr, error) {
	address := field(data, "Address")
	var network netip.Prefix
	var server netip.Addr
	for _, value := range strings.Split(address, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err == nil && p.Addr().Is4() {
			network = p.Masked()
			server = p.Addr()
			break
		}
	}
	if !network.IsValid() {
		return netip.Addr{}, errors.New("Interface Address needs an IPv4 CIDR")
	}
	used := []netip.Prefix{}
	for _, p := range peers {
		for _, v := range strings.Split(p.AllowedIPs, ",") {
			if prefix, err := netip.ParsePrefix(strings.TrimSpace(v)); err == nil {
				used = append(used, prefix)
			}
		}
	}
	for ip, count := network.Addr().Next(), 0; network.Contains(ip) && count < 65536; ip, count = ip.Next(), count+1 {
		if ip == server || network.Bits() <= 30 && !network.Contains(ip.Next()) {
			continue
		}
		occupied := false
		for _, p := range used {
			if p.Contains(ip) {
				occupied = true
				break
			}
		}
		if !occupied {
			return ip, nil
		}
	}
	return netip.Addr{}, errors.New("no available IPv4 address in the first 65536 addresses")
}

func (a Admin) addPeer(name string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", errors.New("peer name must be 1-32 letters, numbers, underscores or hyphens")
	}
	unlock, err := a.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	data, err := a.readConfig()
	if err != nil {
		return "", err
	}
	s, err := a.loadSettings()
	if err != nil {
		return "", err
	}
	_, peers := parseConfig(data)
	clients := a.loadClients()
	for i := range peers {
		if !peers[i].Managed {
			if name := clients[peers[i].PublicKey].Name; nameRE.MatchString(name) {
				peers[i].Name = name
			}
		}
	}
	for _, p := range peers {
		if p.Name == name {
			return "", errors.New("peer already exists")
		}
	}
	if _, err := os.Stat(a.profilePath(name)); err == nil {
		return "", errors.New("profile already exists")
	}
	ip, err := nextAddress(data, peers)
	if err != nil {
		return "", err
	}
	priv, pub, err := keypair()
	if err != nil {
		return "", err
	}
	serverPub, err := publicKey(field(data, "PrivateKey"))
	if err != nil {
		return "", fmt.Errorf("invalid server private key: %w", err)
	}
	profile := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", priv, ip, s.DNS, serverPub, s.Endpoint, s.ClientAllowedIPs)
	block := fmt.Sprintf("\n[Peer]\n# wgx:name=%s\nPublicKey = %s\nAllowedIPs = %s/32\n", name, pub, ip)
	path := a.profilePath(name)
	if err := secureWrite(path, []byte(profile)); err != nil {
		return "", err
	}
	if err := secureWrite(a.Config, []byte(strings.TrimRight(data, "\n")+"\n"+block)); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func (a Admin) removePeer(name string) error {
	if !nameRE.MatchString(name) {
		return errors.New("invalid peer name")
	}
	unlock, err := a.lock()
	if err != nil {
		return err
	}
	defer unlock()
	data, err := a.readConfig()
	if err != nil {
		return err
	}
	prefix, peers := parseConfig(data)
	found := false
	removedKey := ""
	var out strings.Builder
	out.WriteString(prefix)
	for _, p := range peers {
		if p.Name == name && p.Managed {
			found = true
			removedKey = p.PublicKey
			continue
		}
		out.WriteString(p.Block)
	}
	if !found {
		return errors.New("managed peer not found")
	}
	if err := secureWrite(a.Config, []byte(out.String())); err != nil {
		return err
	}
	if err := os.Remove(a.profilePath(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	clients := a.loadClients()
	delete(clients, removedKey)
	_ = a.saveClients(clients)
	return nil
}

func (a Admin) addAndApply(name string) (string, error) {
	path, err := a.addPeer(name)
	if err != nil {
		return "", err
	}
	a.recordEvent("peer", "Added "+name)
	if a.active() {
		if err := a.apply(); err != nil {
			a.recordEvent("error", "Live apply failed after adding "+name)
			return path, fmt.Errorf("peer saved, but live apply failed: %w", err)
		}
	}
	return path, nil
}

func (a Admin) removeAndApply(name string) error {
	if err := a.removePeer(name); err != nil {
		return err
	}
	a.recordEvent("peer", "Removed "+name)
	if a.active() {
		if err := a.apply(); err != nil {
			a.recordEvent("error", "Live apply failed after removing "+name)
			return fmt.Errorf("peer removed from file, but live apply failed: %w", err)
		}
	}
	return nil
}

func (a Admin) exportPeer(name, output string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", errors.New("invalid peer name")
	}
	peers, err := a.peers()
	if err != nil {
		return "", err
	}
	found := false
	for _, p := range peers {
		if p.Name == name && p.Managed {
			found = true
		}
	}
	if !found {
		return "", errors.New("managed peer not found")
	}
	b, err := os.ReadFile(a.profilePath(name))
	if err != nil {
		return "", err
	}
	if output != "" {
		if err := secureWrite(output, b); err != nil {
			return "", err
		}
		return output, nil
	}
	return string(b), nil
}

func runOutput(name string, args ...string) (string, error) {
	c := exec.Command(name, args...)
	b, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}

func (a Admin) active() bool { return exec.Command("wg", "show", a.iface()).Run() == nil }
func (a Admin) up() error {
	_, err := runOutput("wg-quick", "up", a.Config)
	if err == nil {
		a.recordEvent("server", "Started "+a.iface())
	} else {
		a.recordEvent("error", "Failed to start "+a.iface())
	}
	return err
}
func (a Admin) down() error {
	_, err := runOutput("wg-quick", "down", a.Config)
	if err == nil {
		a.recordEvent("server", "Stopped "+a.iface())
	} else {
		a.recordEvent("error", "Failed to stop "+a.iface())
	}
	return err
}
func (a Admin) apply() error {
	if !a.active() {
		return errors.New("interface is down; run wgx up first")
	}
	stripped, err := runOutput("wg-quick", "strip", a.Config)
	if err != nil {
		return err
	}
	c := exec.Command("wg", "syncconf", a.iface(), "/dev/stdin")
	c.Stdin = strings.NewReader(stripped)
	b, err := c.CombinedOutput()
	if err != nil {
		a.recordEvent("error", "Live apply failed for "+a.iface())
		return fmt.Errorf("wg syncconf: %w: %s", err, strings.TrimSpace(string(b)))
	}
	a.recordEvent("server", "Applied config to "+a.iface())
	return nil
}

func (a Admin) status() (string, error) {
	peers, err := a.peers()
	if err != nil {
		return "", err
	}
	telemetry, clients := a.collectTelemetry()
	state := "DOWN"
	if telemetry.Up {
		state = "RUNNING"
	}
	var out strings.Builder
	clientWord := "clients"
	if len(peers) == 1 {
		clientWord = "client"
	}
	fmt.Fprintf(&out, "%s  %s  %d %s", a.iface(), state, len(peers), clientWord)
	if telemetry.Up {
		fmt.Fprintf(&out, "  UDP %d", telemetry.ListenPort)
	}
	for _, peer := range peers {
		live := telemetry.Peers[peer.PublicKey]
		fmt.Fprintf(&out, "\n%-20s %-18s %-20s ↓ %s  ↑ %s", peer.Name, peer.AllowedIPs, lastSeenLabel(clients[peer.PublicKey].LastSeen, time.Now()), humanBytes(live.Received), humanBytes(live.Sent))
	}
	return out.String(), nil
}

func parsePort(v string) (int, error) {
	p, err := strconv.Atoi(v)
	if err != nil || p < 1 || p > 65535 {
		return 0, errors.New("port must be 1-65535")
	}
	return p, nil
}
