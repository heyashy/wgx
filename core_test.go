package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testAdmin(t *testing.T) Admin {
	t.Helper()
	return Admin{Config: filepath.Join(t.TempDir(), "wg0.conf")}
}

func TestQRExport(t *testing.T) {
	a := testAdmin(t)
	if err := a.init("10.44.0.1/24", 51820, Settings{Endpoint: "vpn.example.com:51820"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.addPeer("phone"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "phone.png")
	if _, err := a.qr("phone", path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("QR export is not a PNG")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("QR permission %o", info.Mode().Perm())
	}
}

func TestPeerLifecycleAndPreservation(t *testing.T) {
	a := testAdmin(t)
	if err := a.init("10.44.0.1/29", 51820, Settings{Endpoint: "vpn.example.com:51820"}); err != nil {
		t.Fatal(err)
	}
	_, legacyKey, err := keypair()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(a.Config, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	legacy := "\n# operator note\n[Peer]\nPublicKey = " + legacyKey + "\nAllowedIPs = 10.44.0.2/32\n"
	if _, err := f.WriteString(legacy); err != nil {
		t.Fatal(err)
	}
	f.Close()
	path, err := a.addPeer("laptop")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profile), "Address = 10.44.0.3/32") {
		t.Fatalf("wrong allocation: %s", profile)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("profile permission %o", info.Mode().Perm())
	}
	if _, err := a.addPeer("laptop"); err == nil {
		t.Fatal("duplicate peer accepted")
	}
	if err := a.removePeer("laptop"); err != nil {
		t.Fatal(err)
	}
	config, err := a.readConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, legacy) {
		t.Fatal("unmanaged config changed")
	}
	if strings.Contains(config, "wgx:name=laptop") {
		t.Fatal("removed peer remains")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("client profile remains")
	}
}

func TestValidation(t *testing.T) {
	a := testAdmin(t)
	if err := a.init("fd00::1/64", 51820, Settings{Endpoint: "vpn.example.com:51820"}); err == nil {
		t.Fatal("IPv6-only init accepted")
	}
	if err := a.init("10.44.0.1/24", 51820, Settings{Endpoint: "bad\nendpoint:51820"}); err == nil {
		t.Fatal("bad endpoint accepted")
	}
	if _, err := os.Stat(a.Config); !os.IsNotExist(err) {
		t.Fatal("failed init left config behind")
	}
}

func TestAllocationExhaustion(t *testing.T) {
	a := testAdmin(t)
	if err := a.init("10.44.0.1/30", 51820, Settings{Endpoint: "vpn.example.com:51820"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.addPeer("one"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.addPeer("two"); err == nil {
		t.Fatal("allocated network or broadcast address")
	}
}
