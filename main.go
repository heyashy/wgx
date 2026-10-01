package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

const usage = `wgx — WireGuard Exchange

Usage:
  wgx [--config PATH]                 Open the dashboard
  wgx [--config PATH] init --address CIDR --endpoint HOST:PORT [--listen-port PORT] [--dns IP]
  wgx [--config PATH] adopt --endpoint HOST:PORT [--dns IP]
  wgx [--config PATH] settings --endpoint HOST:PORT [--dns IP] [--allowed-ips CIDRS]
  wgx [--config PATH] peer list
  wgx [--config PATH] peer add NAME
  wgx [--config PATH] peer remove NAME
  wgx [--config PATH] peer export NAME [--output PATH]
  wgx [--config PATH] peer qr NAME [--output PNG|-]
  wgx [--config PATH] status | up | down | apply

Peer changes are applied automatically when the interface is running.
Run 'wgx apply' to sync manual edits to the config.
`

func fail(err error) { fmt.Fprintln(os.Stderr, "wgx:", err); os.Exit(1) }

func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	return f
}

func run(args []string) error {
	global := flags("wgx")
	config := global.String("config", "/etc/wireguard/wg0.conf", "WireGuard server config")
	if err := global.Parse(args); err != nil {
		return err
	}
	a := Admin{Config: *config}
	if err := a.validate(); err != nil {
		return err
	}
	args = global.Args()
	if len(args) == 0 || args[0] == "tui" {
		return runTUI(a)
	}
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Print(usage)
		return nil
	case "init":
		f := flags("init")
		address := f.String("address", "10.44.0.1/24", "server tunnel CIDR")
		endpoint := f.String("endpoint", "", "public host:port")
		port := f.Int("listen-port", 51820, "UDP listen port")
		dns := f.String("dns", "1.1.1.1", "client DNS")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("init takes no positional arguments")
		}
		if err := a.init(*address, *port, Settings{Endpoint: *endpoint, DNS: *dns}); err != nil {
			return err
		}
		fmt.Printf("Created %s\nRun 'wgx up' to start the interface.\n", a.Config)
	case "adopt":
		f := flags("adopt")
		endpoint := f.String("endpoint", "", "public host:port")
		dns := f.String("dns", "1.1.1.1", "client DNS")
		allowed := f.String("allowed-ips", "0.0.0.0/0", "client tunnel routes")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("adopt takes no positional arguments")
		}
		if err := a.adopt(Settings{Endpoint: *endpoint, DNS: *dns, ClientAllowedIPs: *allowed}); err != nil {
			return err
		}
		fmt.Printf("Adopted %s\n", a.Config)
	case "settings":
		f := flags("settings")
		endpoint := f.String("endpoint", "", "public host:port")
		dns := f.String("dns", "", "client DNS")
		allowed := f.String("allowed-ips", "", "client tunnel routes")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("settings takes no positional arguments")
		}
		s, err := a.loadSettings()
		if err != nil {
			return err
		}
		if *endpoint != "" {
			s.Endpoint = *endpoint
		}
		if *dns != "" {
			s.DNS = *dns
		}
		if *allowed != "" {
			s.ClientAllowedIPs = *allowed
		}
		if err := a.saveSettings(s); err != nil {
			return err
		}
		fmt.Println("Settings updated; existing client profiles are unchanged.")
	case "peer":
		return peerCommand(a, args[1:])
	case "status":
		fmt.Println(a.status())
	case "up":
		return a.up()
	case "down":
		return a.down()
	case "apply":
		return a.apply()
	default:
		return fmt.Errorf("unknown command %q; run wgx help", args[0])
	}
	return nil
}

func peerCommand(a Admin, args []string) error {
	if len(args) == 0 {
		return errors.New("peer command required: list, add, remove, export, qr")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("peer list takes no arguments")
		}
		peers, err := a.peers()
		if err != nil {
			return err
		}
		fmt.Println("NAME\tADDRESS\tPUBLIC KEY\tTYPE")
		for _, p := range peers {
			kind := "existing"
			if p.Managed {
				kind = "wgx"
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", p.Name, p.AllowedIPs, p.PublicKey, kind)
		}
	case "add":
		if len(args) != 2 {
			return errors.New("usage: wgx peer add NAME")
		}
		path, err := a.addAndApply(args[1])
		if err != nil {
			return err
		}
		fmt.Printf("Added %s; client profile: %s\n", args[1], path)
	case "remove", "rm":
		if len(args) != 2 {
			return errors.New("usage: wgx peer remove NAME")
		}
		if err := a.removeAndApply(args[1]); err != nil {
			return err
		}
		fmt.Printf("Removed %s\n", args[1])
	case "export":
		if len(args) < 2 {
			return errors.New("usage: wgx peer export NAME [--output PATH]")
		}
		f := flags("peer export")
		output := f.String("output", "", "save profile to path")
		if err := f.Parse(args[2:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments to peer export")
		}
		result, err := a.exportPeer(args[1], *output)
		if err != nil {
			return err
		}
		if *output != "" {
			fmt.Println("Exported", result)
		} else {
			fmt.Print(result)
		}
	case "qr":
		if len(args) < 2 {
			return errors.New("usage: wgx peer qr NAME [--output PNG|-]")
		}
		f := flags("peer qr")
		output := f.String("output", "", "save QR as PNG, or - for PNG on stdout")
		if err := f.Parse(args[2:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments to peer qr")
		}
		return printQR(a, args[1], *output)
	default:
		return fmt.Errorf("unknown peer command %q", strings.Join(args, " "))
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fail(err)
	}
}
