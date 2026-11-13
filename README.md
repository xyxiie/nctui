# nctui

A fast terminal UI for finding open Minecraft Java servers.

IPv4 ranges and country codes use a built-in async connect scanner: it probes
port 25565 directly, skips nmap's host-discovery phase, keeps thousands of
connections in flight, and walks targets in random order so servers show up
quickly. Every open port is then verified with the Minecraft server list ping to
show MOTD, version and player count. Press `v` in the UI to filter the results
by the Minecraft version each server reports; scanning itself is
version-agnostic. nmap remains the fallback for hostnames and other target
syntax.

## Requirements

- Rust (stable) to build
- `nmap` on `PATH` only for the fallback path (`--nmap`, hostnames, nmap ranges)
- Internet access for country range lists

Running as root would allow raw SYN scanning, but this app deliberately uses
non-privileged connect scans; no root is needed.

## Install

Clone the repository and build the release binary:

```sh
git clone <repository-url> nctui
cd nctui
cargo build --release
ln -sfn "$PWD/target/release/nctui" ~/.local/bin/nctui   # or copy it onto your PATH
```

Or let Cargo build and install it straight from the repository:

```sh
cargo install --git <repository-url>
```

Either way you end up with an `nctui` command; `nctui --help` lists the options.

## Build and run

```sh
cargo run --release -- 192.168.1.0/24
cargo run --release -- DE --sample 2 --stop-after 25
cargo run --release -- 10.0.0.1-50 --nmap
```

`cargo build --release` writes the command to `target/release/nctui`; link or
copy that onto your `PATH` to run it as `nctui` from anywhere.

## Speed options

| Option | Meaning |
| --- | --- |
| `--sample <1-100>` | Scan a random percentage of the address space (default 100) |
| `--stop-after <N>` | Stop once N open ports are found (default 0 = never) |
| `--concurrency <N>` | Concurrent connections; clamped to fd/ephemeral-port limits |
| `--timeout <MS>` | Per-connection timeout in milliseconds (default 400) |
| `--nmap` | Force nmap for every target |

Examples:

```sh
# Country quick pass: ~1% random sample, stop after 25 open ports
nctui DE --sample 1 --stop-after 25

# Full country scan with shorter timeouts (more speed, may miss slow hosts)
nctui US --timeout 300

# Full exhaustive scan; press x in the UI to stop when you have enough
nctui DE
```

Sampling is ignored for small ranges (1,024 addresses or fewer), so scanning a
single /24 still checks every address.

## Measured performance

On this 8-core machine, non-root, with the default auto-tuned concurrency
(3,968 connections, hard fd limit 4096):

| Benchmark | Fast scanner | nmap |
| --- | --- | --- |
| 16,384 loopback addresses (`127.0.0.0/18`, closed port) | 16,384 in 0.15s (~108,000/s) | 0.37s (~44,000/s) |
| 4,096 filtered addresses (`198.18.0.0/20`, `-Pn` forced) | 4,096 in 0.62s (~6,600/s) | did not finish in 150s |

These use reserved/loopback ranges, not country scans. Real-country throughput
depends on routing, filtering, and the network path; expect thousands of
addresses per second, not the loopback figure. The benchmark functions are
ignored tests:

```sh
cargo test --release fast::tests::benchmark_loopback -- --ignored --nocapture
cargo test --release fast::tests::benchmark_filtered -- --ignored --nocapture
```

## Controls

| Key | Action |
| --- | --- |
| `s` | Start a scan of the current target / port |
| `i` / `/` | Edit target and port |
| `Tab` | Switch between target and port while editing |
| `Enter` | Apply edits |
| `Esc` | Cancel edits |
| `↑` / `↓`, `j` / `k` | Move selection |
| `x` | Stop the running fast scan |
| `v` | Select a Minecraft version filter |
| `p` | Re-run the Minecraft ping (and mode check) on the selected host |
| `c` | Clear results and the version filter |
| `q` / `Ctrl-C` | Quit |

## Version filter

Press `v` to open a picker populated with the versions reported by the servers
found so far, plus **All versions**. Selecting one filters the table to matching
servers; `Esc` cancels, and choosing All versions clears the filter. Matching is
case-insensitive and also accepts brand-prefixed versions such as
`Paper 1.20.4`. The filter persists across new scans and is cleared by `c`.

## Online vs. offline mode

The table's **Mode** column shows whether a server requires a Mojang/Microsoft
account:

- `online mode` — the server answers a login with an Encryption Request, so only
  authentic accounts can join.
- `offline mode` — the server goes straight to Login Success (`online-mode=false`),
  so cracked/pirated clients can join.
- `?` — the login was rejected before either packet (whitelist, full, bad name,
  timeout), so the mode is unknown.

The server list ping does not report this, so the scanner opens a second
connection per Minecraft server and sends a Login Start as a player named
`MCScan`. It never authenticates and disconnects right after the first reply, but
the name can briefly appear in the server's log. The icon appears after the
status ping; press `p` to re-check the selected server.

## How it works

1. A country code is resolved to its aggregated IPv4 ranges from
   [ipdeny.com](https://www.ipdeny.com/ipblocks/); a CIDR or single IPv4 is used
   directly. Large lists (US is ~460 KB) are fetched with ranged requests, so an
   interrupted download resumes where it stopped instead of restarting or failing.
2. The fast scanner randomizes the range and address order, then starts a
   connect probe to port 25565 for each address. No separate host discovery is
   performed, so firewalled servers are still checked.
3. Open ports are shown immediately and probed with the Minecraft server list
   ping for version, players and MOTD. Each Minecraft server then gets one
   login attempt to detect its online mode (see below).
4. Hostnames, nmap range expressions, and `--nmap` use nmap with XML streaming
   instead.

## Limits

- Java Edition only. Bedrock Edition uses UDP 19132 and a different protocol.
- Country mode and the fast scanner cover IPv4 only.
- A non-root connect scan is bounded by the file-descriptor limit and the
  ephemeral-port range. On this machine that is ~4,000 simultaneous probes.
  Raw SYN scanning (masscan/root) is the next order-of-magnitude step but is not
  used here.
- A full country is still tens to hundreds of millions of addresses. Use
  `--sample`, `--stop-after`, or `x` for practical runs.
- Only scan networks you are authorized to scan.

## License

MIT — see [LICENSE](LICENSE).
