# vyos-hardening

One script that takes a **fresh VyOS router** (default config: `vyos`/`vyos` login, no firewall, SSH open on every interface) to a hardened baseline: deny-by-default firewall, SSH locked to keys and a management network, modern crypto, brute-force protection, and kernel anti-spoofing settings.

Targets **VyOS 1.4 (Sagitta LTS)** and **1.5 / rolling**. It uses the new firewall syntax (`firewall ipv4 input filter`), so it **will not work on 1.3 or older**.

---

## Quick start

```bash
# 1. Copy the script and your public key to the router
scp harden-vyos.sh ~/.ssh/id_ed25519.pub vyos@192.168.0.1:

# 2. On the router (operational mode, NOT sudo). Do a dry run first:
vbash harden-vyos.sh \
  --wan eth0 \
  --lan eth1 --lan eth1.10 \
  --mgmt-net 192.168.0.0/24 \
  --admin-user anish --pubkey-file ~/id_ed25519.pub \
  --ssh-listen 192.168.0.1 \
  --dry-run

# 3. Same command without --dry-run to apply (commits, does NOT save)
# 4. From a NEW terminal:  ssh anish@192.168.0.1   -> works? then on the router:
configure; save; exit

# 5. Optional, logged in as the new user: remove the default 'vyos' account
vbash harden-vyos.sh <same args> --remove-default-user --save --force
```

### Options

| Flag | Required | Meaning |
|---|---|---|
| `--wan IFACE` | yes | Untrusted/internet-facing interface |
| `--lan IFACE` | yes, repeatable | Trusted interfaces (VLAN subinterfaces such as `eth1.10` work) |
| `--mgmt-net CIDR` | yes, repeatable | IPv4 networks allowed to SSH to the router |
| `--mgmt-net6 CIDR` | repeatable | IPv6 networks allowed to SSH |
| `--admin-user NAME` | | Creates a key-only admin account |
| `--pubkey-file PATH` | | OpenSSH public key. If given, **SSH password login is disabled**. Without `--admin-user` the key goes to whoever is running the script |
| `--ssh-listen ADDR` | repeatable | Bind sshd only to these router addresses |
| `--ssh-port PORT` | | Default `22` |
| `--banner TEXT` | | Pre-login banner |
| `--remove-default-user` | | Deletes `vyos`. Refuses to run if you're logged in as `vyos` |
| `--save` | | Saves after commit. Off by default so a reboot undoes a lockout |
| `--force` | | Run even if an IPv4 input filter already exists (rules are merged) |
| `--dry-run` | | Print every `set`/`delete` command and change nothing |

---

## What it does, section by section

### 0. Safety checks (before any change)
- Refuses to run as root/sudo, since VyOS config commands must run as a config-group user.
- Refuses to run without `--mgmt-net`, because the input firewall would drop your SSH session.
- Refuses to disable password auth unless a public key is actually installed for a user.
- Refuses `--remove-default-user` while you're logged in as `vyos`.
- Aborts if an input firewall already exists, so it won't silently stack rules on top of yours (`--force` overrides).
- Copies `/config/config.boot` to `/config/config.boot.pre-hardening-<timestamp>`.
- **Warns** (never deletes) if `telnet`, `snmp`, `https` (the API), `lldp`, `upnp`, `mdns` or `broadcast-relay` are enabled.

### 1. Firewall groups
| Group | Contents | Why |
|---|---|---|
| `interface-group WAN` | `--wan` | Rules say "from WAN" instead of hard-coding `eth0` |
| `interface-group LAN` | every `--lan` | Adding a VLAN later = one `set` into the group |
| `network-group MGMT-v4` / `ipv6-network-group MGMT-v6` | `--mgmt-net(6)` | Who can manage the box |

### 2. Kernel / IP stack (`firewall global-options` → sysctls)
| Setting | Value | Defends against |
|---|---|---|
| `broadcast-ping` | disable | Smurf amplification (answering pings sent to broadcast) |
| `ip-src-route`, `ipv6-src-route` | disable | Source-routed packets that dictate their own path past your filters |
| `receive-redirects`, `ipv6-receive-redirects` | disable | Forged ICMP redirects that rewrite the routing table (MITM) |
| `send-redirects` | disable | A router has no reason to send these, and they leak topology |
| `log-martians` | enable | Logs packets with impossible source addresses (spoofing signal) |
| `source-validation` | **strict** | Reverse-path filter: drops packets whose source wouldn't be routed back out the interface they came in on |
| `syn-cookies` | enable | Keeps accepting connections during a SYN flood |
| `twa-hazards-protection` | enable | RFC 1337 TIME-WAIT assassination |
| `all-ping` | enable | Kept on for troubleshooting; actual ping access is rate-limited in the filters |

> ⚠️ **Strict RPF breaks asymmetric routing** (multi-WAN, policy routing, or a firewall VM that routes back through a different interface). If traffic mysteriously drops, set `source-validation loose`.

### 3. Global state policy
`established` and `related` → **accept**, `invalid` → **drop**, applied to every hook (input/forward/output, IPv4 and IPv6). Return traffic for connections you started just works, and malformed/out-of-state packets die before rule evaluation.

### 4. IPv4 input (traffic *to* the router). Default: **drop**
| Rule | Allows |
|---|---|
| 10 | Loopback (local services talking to each other) |
| 20 | SSH on `--ssh-port`, **only** from `MGMT-v4` **and** only arriving on a LAN interface |
| 30 | Ping from LAN, 10/s |
| 31 | Ping from WAN, 2/s (reachability without becoming a flood target) |
| 40 | DNS (53 tcp/udp) from LAN, for `service dns forwarding` |
| 50 | DHCP (udp 67) from LAN, for `service dhcp-server` |
| 60 | NTP (udp 123) from LAN |
| 990 | Everything else from WAN: **logged** and dropped |
| default | Drop |

Rules 40–60 are harmless if the matching service isn't enabled, since nothing is listening.

### 5. IPv4 forward (traffic *through* the router). Default: **drop**
- 100: anything entering on a LAN interface may go anywhere.
- 990: unsolicited WAN→inside is logged and dropped. Replies to LAN traffic pass via the state policy.
- Port forwards or inter-VLAN restrictions? Add rules between 100 and 990.

### 6. IPv6 input and forward. Default: **drop**
Same policy as IPv4, plus:
- **ICMPv6 allowed.** IPv6 can't work without Neighbor Discovery, Router Advertisements and Path-MTU messages, so blocking ICMPv6 the way people block ICMPv4 breaks it.
- DHCPv6 client replies (udp 547→546), so a WAN DHCPv6/PD lease keeps working.
- SSH only if `--mgmt-net6` is set.

### 7. SSH daemon
| Setting | Effect |
|---|---|
| `listen-address` | sshd binds only to the addresses you give (not the WAN IP). Defence in depth on top of the firewall |
| `disable-password-authentication` | Keys only, so password brute-force is impossible (only when a key is supplied) |
| `dynamic-protection` (sshguard) | Blocks IPs that rack up failed-login score 30 within 30 min: first ban 300 s, growing ×1.5 on repeat. Your `--mgmt-net`s are allow-listed so you can't ban yourself |
| `ciphers`/`cipher` | `chacha20-poly1305`, `aes256-gcm`, `aes128-gcm`, `aes256-ctr`. Removes CBC and 3DES |
| `mac` | Encrypt-then-MAC SHA-2 / UMAC-128 only. Removes MD5, SHA-1 and non-ETM MACs |
| `key-exchange` | `curve25519`, DH group 16/18. Removes group1/group14-sha1 and NIST curves |
| `disable-host-validation` | No reverse-DNS lookup on login (faster, no DNS dependency) |
| `client-keepalive-interval 300` | Detects dead sessions |

The script auto-detects whether your VyOS build calls the cipher node `ciphers` (1.4) or `cipher` (newer).

### 8. Accounts
- Creates `--admin-user` with your public key (VyOS 1.4+ has no privilege levels, so every user is an admin).
- `--remove-default-user` deletes `vyos`, the account every scanner tries with password `vyos`.
- The new user has **no password**, which means no console login. For console access (you want this for recovery), set one manually:
  `set system login user anish authentication plaintext-password '<strong-password>'`

### 9. Miscellaneous (applied only if the node exists in your version)
- Pre-login legal banner.
- `system option ctrl-alt-delete ignore`: someone at the hypervisor console can't reboot it with a keystroke.
- `system login timeout 900`: idle shells log out after 15 minutes.
- `system ip disable-directed-broadcast`.

---

## What it deliberately does *not* do
- **No NAT, DHCP or DNS config.** It hardens the router; it doesn't build your network.
- **No deleting of existing services.** It warns, and you decide.
- **No inter-VLAN segmentation.** All `--lan` interfaces trust each other. For a lab with untrusted VLANs (IoT, a malware sandbox), add forward rules or move to `firewall zone`.
- **No remote syslog.** The syntax changed between 1.4 and 1.5. Add `system syslog` yourself to ship logs to your SIEM/NIDS box.
- **No SNMP, flow export or auth server (RADIUS/TACACS).**

## Verifying
```bash
show firewall                       # rulesets + hit counters
show firewall ipv4 input filter
show log firewall                   # rules 990 (WAN drops) land here
show configuration commands | match ssh
sudo sshd -T | egrep 'ciphers|macs|kexalgorithms|passwordauthentication'
```
From outside: `nmap -Pn -p- <WAN-IP>` should show everything filtered. `ssh -o PubkeyAuthentication=no user@router` should be refused.

## Rollback
```bash
# Not yet saved?   just reboot.
# Already saved:
configure
load /config/config.boot.pre-hardening-<timestamp>
commit; save; exit
```

## License
MIT
