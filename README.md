# wgx — WireGuard Exchange

`wgx` is a Go terminal app for administering one WireGuard server interface. It creates or adopts a `wg-quick` config, allocates peer addresses, writes client profiles, and applies saved changes to a running interface. The dashboard supports keyboard and mouse input. CLI subcommands are available for scripts.

## Build

Go 1.24 or newer is required.

Run `make build` for a local binary, `make test` for the unit tests, or `make demo` to build and open the Docker lab TUI.

```sh
go build -o wgx .
sudo install -m 755 wgx /usr/local/bin/wgx
```

The host also needs `wg`, `wg-quick`, and `ip` from WireGuard tools and iproute2. Manage the server as root (or with equivalent permissions), because WireGuard configuration and client private keys are sensitive.

## Start a server

Run `sudo wgx` to open the app. On first launch it walks through server setup or adoption of an existing config. Add a peer from the dashboard and its onboarding screen shows connection details, a scannable QR code, and the profile path. The QR code contains the full client config, including its private key.

For scripted setup:

```sh
sudo wgx init --address 10.44.0.1/24 --listen-port 51820 --endpoint vpn.example.com:51820
sudo wgx up
sudo wgx peer add laptop
sudo wgx peer list
sudo wgx peer export laptop --output ./laptop.conf
sudo wgx
```

`init` creates `/etc/wireguard/wg0.conf` and a server key. It never replaces an existing config. Point `--endpoint` at the public hostname or IP and the exposed UDP port. Client profiles route all IPv4 traffic through the tunnel by default. To route only a private subnet, use `wgx settings --allowed-ips 10.44.0.0/24` before adding peers. The server's network forwarding, firewall, NAT, and public DNS are deployment decisions and are not configured by `wgx`.

For an existing server config:

```sh
sudo wgx adopt --endpoint vpn.example.com:51820
sudo wgx peer add phone
sudo wgx apply
```

`adopt` leaves existing peer blocks untouched. `wgx` peers are marked in the server config and can be removed by name. Existing unmarked peers are shown read-only; their private keys cannot be recovered from a server config. `wgx peer remove phone` removes the saved client profile. Peer additions and removals update the live interface automatically when it is running.

Use `wgx --config /path/to/wg1.conf` before any command to select a different interface. `wgx help` shows all commands. Run `wgx` without a command for the app. The dashboard supports arrow keys or `j`/`k`, mouse row selection and wheel scrolling. Use `n` to add, `d` to delete, `e` to open onboarding details, `a` to apply, `u` to bring up, `x` to bring down, `r` to refresh, and `q` to quit. Onboarding uses `1` for details, `2` for QR, `v` to reveal the full config, and `b` to return. The QR needs enough terminal space to display in full.

For secure handoff from a remote VM, stream the client profile or QR image over SSH to a private local file:

```sh
umask 077
ssh ec2-user@your-vm 'sudo wgx peer export laptop' > laptop.conf
ssh ec2-user@your-vm 'sudo wgx peer qr laptop --output -' > laptop.png
```

Delete local copies after importing them. Inside the Docker lab, use `umask 077; docker compose exec -T wgx wgx peer export laptop > laptop.conf` to copy a profile out of the named volume.

## Docker lab

The Compose lab installs WireGuard tools and `wgx` in a Debian container. It stores server configuration and client profiles in the `wgx-data` Docker volume. Docker must run on a Linux host with WireGuard support and allow `NET_ADMIN` in the container.

```sh
docker compose up -d --build
docker compose exec wgx wgx init --address 10.44.0.1/24 --endpoint localhost:51820
docker compose exec wgx wgx up
docker compose exec wgx wgx peer add laptop
docker compose exec wgx wgx peer list
docker compose exec wgx wgx
```

Use the host's reachable IP or DNS name instead of `localhost` if you will connect a client from another device. The lab publishes UDP port 51820. When done, `docker compose down` stops the container; the named volume remains. `docker compose down -v` removes the lab keys and profiles.

## Security and limitations

- Server config, settings, and client profiles are written with mode `0600`; their directories are created with mode `0700`.
- `peer export` without `--output` prints the client private key to stdout. Save it only to a secure location.
- `settings` affects newly created client profiles. Existing client profiles retain their original endpoint, DNS, and routes.
- Address allocation currently supports IPv4 server CIDRs, up to the first 65,536 addresses. The tool manages one interface per invocation.
- Config edits are saved to disk first. Live peer changes use `wg-quick strip` and `wg syncconf` so peers can be changed without cycling the interface. If a live apply fails, the saved config remains changed; retry with `wgx apply`.
