package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenameManagedAndAdoptedClients(t *testing.T) {
	a := testAdmin(t)
	if err := a.init("10.44.0.1/24", 51820, Settings{Endpoint: "vpn.example.com:51820"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.addPeer("laptop"); err != nil {
		t.Fatal(err)
	}
	before, err := a.peers()
	if err != nil {
		t.Fatal(err)
	}
	key := before[0].PublicKey
	if err := a.renamePeer("laptop", "workstation"); err != nil {
		t.Fatal(err)
	}
	after, err := a.peers()
	if err != nil {
		t.Fatal(err)
	}
	if after[0].Name != "workstation" || after[0].PublicKey != key {
		t.Fatal("managed rename changed identity")
	}
	if _, err := os.Stat(a.profilePath("laptop")); !os.IsNotExist(err) {
		t.Fatal("old profile remains")
	}
	if _, err := a.exportPeer("workstation", ""); err != nil {
		t.Fatal(err)
	}
	legacy := "\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 10.44.0.8/32\n"
	f, err := os.OpenFile(a.Config, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(legacy); err != nil {
		t.Fatal(err)
	}
	f.Close()
	peers, err := a.peers()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.renamePeer(peers[1].Name, "router"); err != nil {
		t.Fatal(err)
	}
	if err := a.setPeerNote("router", "living room gateway"); err != nil {
		t.Fatal(err)
	}
	peers, err = a.peers()
	if err != nil {
		t.Fatal(err)
	}
	if peers[1].Name != "router" || peers[1].Managed {
		t.Fatal("adopted peer identity incorrect")
	}
	if a.loadClients()[peers[1].PublicKey].Note != "living room gateway" {
		t.Fatal("note missing")
	}
	config, err := a.readConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, legacy) {
		t.Fatal("adopted peer config changed")
	}
	if err := a.renamePeer("router", "workstation"); err == nil {
		t.Fatal("duplicate name accepted")
	}
}

func TestTelemetryLastSeenPersistsAfterInterfaceStops(t *testing.T) {
	a := testAdmin(t)
	bin := t.TempDir()
	command := filepath.Join(bin, "wg")
	dump := "private\tserverpub\t51820\toff\npeerpub\t(none)\t198.51.100.5:51820\t10.44.0.2/32\t1700000000\t2048\t4096\t25\n"
	if err := os.WriteFile(command, []byte("#!/bin/sh\ncat <<'EOF'\n"+dump+"EOF\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	telemetry, clients := a.collectTelemetry()
	if !telemetry.Up || telemetry.ListenPort != 51820 {
		t.Fatal("interface telemetry missing")
	}
	if telemetry.Peers["peerpub"].Received != 2048 || telemetry.Peers["peerpub"].Sent != 4096 {
		t.Fatal("transfer counters incorrect")
	}
	if !clients["peerpub"].LastSeen.Equal(time.Unix(1700000000, 0)) {
		t.Fatal("handshake not cached")
	}
	if events := a.recentEvents(10); len(events) != 1 || events[0].Kind != "handshake" {
		t.Fatal("handshake activity not recorded")
	}
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	telemetry, clients = a.collectTelemetry()
	if telemetry.Up {
		t.Fatal("stopped interface reported running")
	}
	if clients["peerpub"].LastSeen.IsZero() {
		t.Fatal("last seen lost when interface stopped")
	}
	if strings.Contains(telemetry.PublicKey, "private") {
		t.Fatal("private key entered telemetry")
	}
}

func TestStatusUsesClientName(t *testing.T) {
	a := testAdmin(t)
	if err := a.init("10.44.0.1/24", 51820, Settings{Endpoint: "vpn.example.com:51820"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.addPeer("phone"); err != nil {
		t.Fatal(err)
	}
	if err := a.renamePeer("phone", "alice-phone"); err != nil {
		t.Fatal(err)
	}
	status, err := a.status()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "alice-phone") || !strings.Contains(status, "Never seen") {
		t.Fatal("status omits human client details")
	}
	if strings.Contains(status, "PrivateKey") {
		t.Fatal("status exposed private key")
	}
}

func TestCorruptMetadataIsNotOverwritten(t *testing.T) {
	a := testAdmin(t)
	if err := a.init("10.44.0.1/24", 51820, Settings{Endpoint: "vpn.example.com:51820"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.addPeer("phone"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.clientsPath(), []byte("invalid json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.setPeerNote("phone", "note"); err == nil {
		t.Fatal("corrupt metadata overwritten")
	}
	b, err := os.ReadFile(a.clientsPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "invalid json" {
		t.Fatal("corrupt metadata changed")
	}
}
