# vyos-hardening: CCDC edition

A defense toolkit for the **VyOS router in a CCDC-style competition**. It assumes three things that a normal hardening script doesn't:

1. **The box is already compromised.** Images are handed out with planted users, keys, scheduled tasks and backdoors, so finding persistence comes before hardening.
2. **Scored services must stay up.** A deny-all firewall that breaks the web server costs more points than the red team does. The firewall is built *around* the services in your team packet.
3. **You'll break something under pressure.** Every config change arms a **dead-man rollback timer**. If you lose access or kill scoring, it reverts on its own in N minutes, without a reboot.

Targets **VyOS 1.4 (Sagitta) and newer**. `audit`, `backup`, `creds` and `purge` mostly work on older builds. `harden` needs the 1.4 firewall syntax and refuses to run on 1.3.

---

## Setup (before the competition)

```bash
git clone https://github.com/jogeshwaranish/vyos-hardening
cp ccdc.conf.example ccdc.conf      # fill in from the team packet at drop
```

Getting it onto the router at drop time (pick whatever the rules allow):

```bash
scp ccdc-vyos.sh ccdc.conf vyos@ROUTER:      # if you have a jump box
# or paste it: on the router run  cat > ccdc-vyos.sh  , paste, Ctrl-D
chmod +x ccdc-vyos.sh
```

> Check your competition's rules on pre-written scripts and internet access. Some regionals require tooling to be typed in or allow only public repos.

---

## The first 15 minutes

| # | Command | Time | Why this order |
|---|---|---|---|
| 1 | `./ccdc-vyos.sh backup` | 5 s | Known-good snapshot of the config as handed to you |
| 2 | `./ccdc-vyos.sh creds` | 1 min | Red team already has the default creds. **Lock them out first** |
| 3 | `./ccdc-vyos.sh audit` | 30 s | Find what they planted. Read the `[!]` lines |
| 4 | `./ccdc-vyos.sh purge` | 2–5 min | Remove what audit found, item by item |
| 5 | **check scoreboard** → `./ccdc-vyos.sh confirm` | | Purge armed the rollback timer |
| 6 | `./ccdc-vyos.sh harden` | 1 min | Rebuild the firewall around scored services |
| 7 | **check scoreboard + SSH from a new terminal** → `./ccdc-vyos.sh confirm` | | |
| ∞ | `./ccdc-vyos.sh status` / `block <ip>` | | Watch drops, ban attackers |

`creds` saves right away, because you never want a red-team reboot to bring the default password back. `purge` and `harden` commit but **don't save** until you `confirm`.

---

## Commands

### `backup`
Copies `/config/config.boot` and `show configuration commands` to `/config/ccdc/backup-<time>.{boot,cmds}` and points `last-backup.boot` at it. Every config-changing command runs this first automatically.

### `audit` (read-only)
Prints a report and saves it to `/config/ccdc/audit-<time>.txt`, with a full config dump next to it for the incident report. `[!]` marks a finding.

| Section | What it looks for |
|---|---|
| **1. Accounts (config)** | Every `system login user`, whether it has SSH keys (any key you didn't add is a backdoor), users not in `KEEP_USERS`, RADIUS/TACACS servers (an auth server the red team controls = universal password) |
| **2. Accounts (OS)** | Non-root UID 0 accounts, OS users with a shell that aren't in the VyOS config (added with `useradd`, invisible to `show configuration`), sudoers entries, every `authorized_keys` file with key comments, who's logged in now, recent logins |
| **3. Triggered execution** | `system task-scheduler` (VyOS cron), `service event-handler` (runs a script when a log line matches, so a red-team-triggerable backdoor), `container`, `commit-archive` (uploads your config to a remote URL on every commit), non-empty `vyos-pre/postconfig-bootup.script`, commit hooks in `/config/scripts/commit/` (run on **every** commit, including yours), cron, `ld.so.preload` (userland rootkit), `rc.local`, custom systemd units and timers |
| **4. Files changed vs stock image** | VyOS runs from a read-only squashfs and every change lives in an overlay directory. The script lists everything in that overlay, so you see exactly what was modified on the image, however old. Changed binaries, PAM or sshd files get flagged |
| **5. Network redirection** | Destination NAT (a port forward to an attacker host?), source NAT, static/dynamic/policy routes, tunnel interfaces (WireGuard/OpenVPN/GRE/VXLAN = covert channels), DNS forwarding overrides and static host mappings (DNS hijack), remote syslog targets, custom sysctls |
| **6. Management services** | telnet, the HTTPS API (and its keys), SNMP communities, UPnP, LLDP, the full SSH config |
| **7. Firewall as found** | The whole existing ruleset, hooks people forget (output, prerouting/raw, bridge), `invalid` traffic set to accept, nftables tables VyOS didn't create |
| **8. Live state** | Listening sockets with owning process, established connections, suspicious processes (`nc`, `socat`, `bash -i`, `/dev/tcp`, `python -c`, anything running from `/tmp` or `/dev/shm`, known C2 names), executables in tmp dirs, promiscuous interfaces (sniffers), addresses, routes, `ip rule` |

### `creds`
1. Prompts for a new password (twice, 12+ characters) for every user in `KEEP_USERS`.
2. **Deletes every SSH key** on those users. Pre-planted keys are the #1 VyOS backdoor. If `TEAM_PUBKEY` is set, it adds that back.
3. Offers to delete every user **not** in `KEEP_USERS`, one at a time. It never deletes you, and it refuses to run if you aren't in `KEEP_USERS`.
4. Offers to remove RADIUS/TACACS.
5. Commits and **saves**.
6. Offers to **kill every other login session**. Changing a password doesn't end shells that are already open, so this step is what actually kicks the red team out.

### `purge`
Walks each persistence location and asks `y/N` per item, showing the item's config first:
- **Config:** task-scheduler tasks, event handlers, containers, DNAT rules, WireGuard/OpenVPN/GRE interfaces, static host mappings, DNS overrides, remote syslog, telnet, HTTPS API, SNMP, UPnP, commit-archive, RADIUS/TACACS.
- **Filesystem:** boot scripts (reset to empty), commit hooks, files changed from the stock image in cron/systemd/profile/bashrc/`/usr/local/bin`/`ld.so.preload`, `authorized_keys` files. Files are **quarantined** to `/config/ccdc/quarantine/` with mode 000, not deleted, so you keep the evidence for the incident report inject.
- **Processes:** offers `kill -9` on suspicious processes.

Arms the rollback timer at the end. **DNAT rules are often scored services.** Only delete the ones that point somewhere that isn't in your packet.

### `harden`
Shows the plan, asks once, backs up, then **wipes the existing filter chains** (`input`, `forward`, `output`, every named chain and the zone firewall, which takes any red-team allow rules with them) and rebuilds:

**Groups:** `WAN`, `LAN` (interfaces), `MGMT-v4` (admin networks), `SCORING` (scoring engine IPs), `BLOCKLIST` (persists across re-runs so bans aren't lost).

**Input (traffic to the router). Default drop.**

| Rule | |
|---|---|
| 5 | Drop + log anything from `BLOCKLIST` |
| 10 | Loopback |
| 20 | SSH only from `MGMT_NETS`, only arriving on LAN. **Never from WAN** |
| 30/31 | Ping from LAN, and from WAN at 5/s |
| 40/50/60 | DNS / DHCP / NTP from LAN, if the router provides them (`ROUTER_SERVES_*`) |
| 999 | Log + drop |

**Forward (traffic through the router). Default drop.**

| Rule | |
|---|---|
| 5/6 | Drop + log to/from `BLOCKLIST` (6 catches internal hosts calling home to C2) |
| 10 | Scoring engine IPs: always accepted |
| 100+ | One rule per `SCORED_SERVICES` entry (internal IP + ports, from anywhere) |
| 200 | LAN ↔ LAN |
| 300–302 | Egress: if `restricted`, only `EGRESS_TCP`/`EGRESS_UDP` ports and ICMP leave the network |
| 390 | **Log + drop all other egress.** This is what stops reverse shells and beacons from compromised internal boxes |
| 999 | Log + drop |

**IPv6:** `block` (default) drops all routed IPv6. The red team uses v6 because teams forget it. ICMPv6 to the router stays open so neighbor discovery still works. `passthrough` mirrors the IPv4 LAN-out policy.

**Kernel:** no source routing, no ICMP redirects (sent or received), no broadcast ping, SYN cookies, martian logging, RFC 1337 protection, **loose** reverse-path filtering (strict breaks the asymmetric routing common in CCDC topologies), established/related accept, invalid drop.

**SSH:** listens on all addresses (the firewall does the restricting). sshguard bans after repeated failures (allow-listing your admin networks and the scoring engine). Modern ciphers/MACs/KEX only. 60 s keepalive. Password auth is disabled only if `TEAM_PUBKEY` is set.

**Misc:** login banner, idle shells log out after 15 min, Ctrl-Alt-Del ignored.

### `confirm`
Cancels the rollback timer and saves. Run it **only** after you've checked the scoreboard and SSH'd in from a *new* terminal.

### `rollback [file]`
Loads `last-backup.boot` (or the file you give it) and commits immediately, with no reboot.

### `block IP [IP...]` / `unblock IP [IP...]`
Adds IPs (or `a.b.c.d-e.f.g.h` ranges) to `BLOCKLIST`, commits, saves, and **flushes their existing connections** with `conntrack -D`. The state policy accepts established traffic before any rule runs, so without the flush an attacker's open shell would survive the block. It refuses to block scoring engine IPs. Know your competition's rules on blocking.

### `status`
Rollback timer state, the current blocklist, the last 20 firewall log lines, logged-in users.

---

## How the rollback timer works
`purge` and `harden` write `/tmp/ccdc-deadman.sh`, which sleeps `ROLLBACK_MINUTES`, then runs `load <backup>; commit`. It starts detached (`setsid nohup`), so it survives your SSH session dying, which is the exact failure it exists for. `confirm` kills it. Unlike VyOS's built-in `commit-confirm`, which reboots by default, it doesn't reboot the router, so scored traffic doesn't drop for the length of a boot.

## Safety details
- Must run as a VyOS admin user. It re-executes itself under the `vyattacfg` group, and refuses root/sudo (that corrupts VyOS config sessions).
- If any `set` fails, nothing is committed.
- Config node names are read without `eval`. Names on a compromised box are attacker-controlled, so a user named `$(rm -rf /)` is just printed.
- `ASSUME_YES=1 ./ccdc-vyos.sh <cmd>` answers yes to every prompt. It's for testing; **don't** use it with `purge`.

## Files
| File | |
|---|---|
| `ccdc-vyos.sh` | The toolkit |
| `ccdc.conf.example` | Every setting, commented. Copy to `ccdc.conf` (git-ignored) |
| `/config/ccdc/` on the router | Backups, audit reports, quarantine, rollback log (survives reboot) |

## Tested?
Logic was tested against a stubbed VyOS CLI (command generation, input validation, prompts, rollback-timer lifecycle). **Run it on your homelab VyOS before competition day.** Practice the whole first-15-minutes sequence on a deliberately backdoored VM.

## License
MIT
