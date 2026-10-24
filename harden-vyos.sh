#!/bin/vbash
# =============================================================================
# harden-vyos.sh — baseline hardening for a fresh VyOS 1.4 (Sagitta) / 1.5 router
#
# Run from operational mode as an admin user (NOT with sudo):
#     vbash harden-vyos.sh --wan eth0 --lan eth1 --mgmt-net 192.168.0.0/24 \
#         --admin-user anish --pubkey-file ~/id_ed25519.pub --dry-run
#
# Safety model:
#   * --dry-run prints every command and changes nothing.
#   * The config is backed up to /config/ before anything is touched.
#   * By default changes are COMMITTED but NOT SAVED. If you lock yourself out,
#     reboot from the console/hypervisor and the router comes back unhardened.
#     Once you've confirmed access from a NEW ssh session, run `save` (or rerun
#     with --save).
#   * If any `set` fails, nothing is committed.
#
# See README.md for an explanation of every change.
# =============================================================================

source /opt/vyatta/etc/functions/script-template

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
WAN_IF=""
LAN_IFS=()
MGMT_NETS=()
MGMT_NETS6=()
ADMIN_USER=""
PUBKEY_FILE=""
SSH_LISTEN=()
SSH_PORT="22"
DRY_RUN=0
DO_SAVE=0
REMOVE_DEFAULT_USER=0
FORCE=0
BANNER="Authorized access only. All activity is logged and monitored."

TEMPLATES=/opt/vyatta/share/vyatta-cfg/templates
FAILED=()

usage() {
  cat <<'EOF'
Usage: vbash harden-vyos.sh [options]

Required:
  --wan IFACE              WAN/untrusted interface (e.g. eth0)
  --lan IFACE              LAN/trusted interface; repeat for more (eth1, eth1.10 ...)
  --mgmt-net CIDR          IPv4 network allowed to SSH to the router; repeatable

Optional:
  --mgmt-net6 CIDR         IPv6 network allowed to SSH to the router; repeatable
  --admin-user NAME        Create this admin user (requires --pubkey-file)
  --pubkey-file PATH       OpenSSH public key for the admin user (ed25519 recommended)
  --ssh-listen ADDR        Bind sshd only to this router address; repeatable
  --ssh-port PORT          SSH port (default 22)
  --banner TEXT            Pre-login banner text
  --remove-default-user    Delete the built-in 'vyos' user (must NOT be logged in as vyos)
  --save                   Save config after commit (default: commit only)
  --force                  Proceed even if a firewall ruleset already exists
  --dry-run                Print commands, change nothing
  -h, --help               Show this help
EOF
}

die()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
info() { echo "[*] $*"; }

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --wan)                 WAN_IF="$2"; shift 2 ;;
    --lan)                 LAN_IFS+=("$2"); shift 2 ;;
    --mgmt-net)            MGMT_NETS+=("$2"); shift 2 ;;
    --mgmt-net6)           MGMT_NETS6+=("$2"); shift 2 ;;
    --admin-user)          ADMIN_USER="$2"; shift 2 ;;
    --pubkey-file)         PUBKEY_FILE="$2"; shift 2 ;;
    --ssh-listen)          SSH_LISTEN+=("$2"); shift 2 ;;
    --ssh-port)            SSH_PORT="$2"; shift 2 ;;
    --banner)              BANNER="$2"; shift 2 ;;
    --remove-default-user) REMOVE_DEFAULT_USER=1; shift ;;
    --save)                DO_SAVE=1; shift ;;
    --force)               FORCE=1; shift ;;
    --dry-run)             DRY_RUN=1; shift ;;
    -h|--help)             usage; exit 0 ;;
    *)                     usage; die "unknown option: $1" ;;
  esac
done

# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------
[ -n "$WAN_IF" ]          || die "--wan is required"
[ ${#LAN_IFS[@]} -gt 0 ]  || die "at least one --lan is required"
[ ${#MGMT_NETS[@]} -gt 0 ] || die "at least one --mgmt-net is required (or you'll lose SSH)"
[ "$(id -u)" -ne 0 ]      || die "do not run with sudo/root; run as a VyOS admin user"

if [ -n "$ADMIN_USER" ] && [ -z "$PUBKEY_FILE" ]; then
  die "--admin-user requires --pubkey-file (passwordless key login is the point)"
fi

KEY_TYPE=""; KEY_BODY=""; KEY_NAME=""
if [ -n "$PUBKEY_FILE" ]; then
  [ -r "$PUBKEY_FILE" ] || die "cannot read $PUBKEY_FILE"
  read -r KEY_TYPE KEY_BODY KEY_NAME < "$PUBKEY_FILE"
  case "$KEY_TYPE" in
    ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa) ;;
    *) die "unsupported key type '$KEY_TYPE' in $PUBKEY_FILE" ;;
  esac
  [ -n "$KEY_BODY" ] || die "no key material found in $PUBKEY_FILE"
  KEY_NAME="${KEY_NAME:-${ADMIN_USER:-admin}-key}"
  KEY_NAME="${KEY_NAME//[^A-Za-z0-9@._-]/_}"   # VyOS key ids: keep it simple
fi

CURRENT_USER="$(id -un)"
# A key with no user would still disable password auth -> lockout. Attach it to
# whoever is running the script unless another admin user was named.
if [ -n "$PUBKEY_FILE" ] && [ -z "$ADMIN_USER" ]; then
  ADMIN_USER="$CURRENT_USER"
fi
if [ "$REMOVE_DEFAULT_USER" -eq 1 ] && [ "$CURRENT_USER" = "vyos" ]; then
  die "you are logged in as 'vyos'. Run once without --remove-default-user, log in as \
the new admin, then rerun with --remove-default-user."
fi

# Does a config node exist in this VyOS version's schema?
has_node() { [ -d "$TEMPLATES/$1" ]; }

# Does a node exist in the running config?
active() { cli-shell-api existsActive "$@"; }

if [ "$FORCE" -eq 0 ] && active firewall ipv4 input filter rule; then
  die "an IPv4 input filter already exists. Review it first; rerun with --force to merge."
fi

# -----------------------------------------------------------------------------
# Command wrappers (print in dry-run, apply otherwise, record failures)
# -----------------------------------------------------------------------------
S() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'set'; printf " '%s'" "$@"; printf '\n'
  else
    set "$@" || FAILED+=("set $*")
  fi
}
D() {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'delete'; printf " '%s'" "$@"; printf '\n'
  else
    delete "$@" || FAILED+=("delete $*")
  fi
}

# -----------------------------------------------------------------------------
# Backup
# -----------------------------------------------------------------------------
TS="$(date +%Y%m%d-%H%M%S)"
if [ "$DRY_RUN" -eq 0 ]; then
  if cp /config/config.boot "/config/config.boot.pre-hardening-$TS"; then
    info "Backed up config to /config/config.boot.pre-hardening-$TS"
  else
    die "backup failed; refusing to continue"
  fi
fi

# -----------------------------------------------------------------------------
# Report risky services that are already enabled (we warn, never auto-delete)
# -----------------------------------------------------------------------------
for svc in "service telnet" "service snmp" "service https" "service lldp" \
           "service upnp" "service mdns" "service broadcast-relay"; do
  # shellcheck disable=SC2086
  active $svc && warn "'$svc' is enabled — make sure you need it and it's restricted."
done

[ "$DRY_RUN" -eq 1 ] && echo "# ---- DRY RUN: nothing will be changed ----"
[ "$DRY_RUN" -eq 0 ] && configure

# =============================================================================
# 1. Interface groups & address groups (makes every rule below readable)
# =============================================================================
S firewall group interface-group WAN interface "$WAN_IF"
for i in "${LAN_IFS[@]}"; do
  S firewall group interface-group LAN interface "$i"
done
for n in "${MGMT_NETS[@]}"; do
  S firewall group network-group MGMT-v4 network "$n"
done
for n in "${MGMT_NETS6[@]}"; do
  S firewall group ipv6-network-group MGMT-v6 network "$n"
done

# =============================================================================
# 2. Kernel / IP-stack hardening (firewall global-options -> sysctls)
# =============================================================================
S firewall global-options all-ping enable              # keep ping for troubleshooting (rate-limited below)
S firewall global-options broadcast-ping disable       # no smurf amplification
S firewall global-options ip-src-route disable         # ignore source-routed packets
S firewall global-options ipv6-src-route disable
S firewall global-options receive-redirects disable    # ignore ICMP redirects (route hijack)
S firewall global-options ipv6-receive-redirects disable
S firewall global-options send-redirects disable
S firewall global-options log-martians enable          # log impossible source addresses
S firewall global-options source-validation strict     # reverse-path filter (anti-spoofing)
S firewall global-options syn-cookies enable           # survive SYN floods
S firewall global-options twa-hazards-protection enable  # RFC 1337 TIME-WAIT assassination

# =============================================================================
# 3. Stateful baseline: allow replies, drop garbage (applies to all hooks)
# =============================================================================
S firewall global-options state-policy established action accept
S firewall global-options state-policy related action accept
S firewall global-options state-policy invalid action drop

# =============================================================================
# 4. IPv4 INPUT — traffic destined to the router itself. Default: DROP.
# =============================================================================
F4="firewall ipv4 input filter"
S $F4 default-action drop

S $F4 rule 10 description "Allow loopback"
S $F4 rule 10 action accept
S $F4 rule 10 inbound-interface name lo

S $F4 rule 20 description "SSH from management networks on LAN only"
S $F4 rule 20 action accept
S $F4 rule 20 protocol tcp
S $F4 rule 20 destination port "$SSH_PORT"
S $F4 rule 20 source group network-group MGMT-v4
S $F4 rule 20 inbound-interface group LAN

S $F4 rule 30 description "Rate-limited ping from LAN"
S $F4 rule 30 action accept
S $F4 rule 30 protocol icmp
S $F4 rule 30 icmp type-name echo-request
S $F4 rule 30 inbound-interface group LAN
S $F4 rule 30 limit rate 10/second

S $F4 rule 31 description "Rate-limited ping from WAN"
S $F4 rule 31 action accept
S $F4 rule 31 protocol icmp
S $F4 rule 31 icmp type-name echo-request
S $F4 rule 31 inbound-interface group WAN
S $F4 rule 31 limit rate 2/second

S $F4 rule 40 description "DNS from LAN"
S $F4 rule 40 action accept
S $F4 rule 40 protocol tcp_udp
S $F4 rule 40 destination port 53
S $F4 rule 40 inbound-interface group LAN

S $F4 rule 50 description "DHCP requests from LAN"
S $F4 rule 50 action accept
S $F4 rule 50 protocol udp
S $F4 rule 50 destination port 67
S $F4 rule 50 inbound-interface group LAN

S $F4 rule 60 description "NTP from LAN"
S $F4 rule 60 action accept
S $F4 rule 60 protocol udp
S $F4 rule 60 destination port 123
S $F4 rule 60 inbound-interface group LAN

S $F4 rule 990 description "Log + drop everything else from WAN"
S $F4 rule 990 action drop
S $F4 rule 990 inbound-interface group WAN
S $F4 rule 990 log

# =============================================================================
# 5. IPv4 FORWARD — traffic routed THROUGH the router. Default: DROP.
# =============================================================================
FF4="firewall ipv4 forward filter"
S $FF4 default-action drop
S $FF4 rule 100 description "LAN may go anywhere (replies handled by state-policy)"
S $FF4 rule 100 action accept
S $FF4 rule 100 inbound-interface group LAN
S $FF4 rule 990 description "Log unsolicited WAN->inside"
S $FF4 rule 990 action drop
S $FF4 rule 990 inbound-interface group WAN
S $FF4 rule 990 log

# =============================================================================
# 6. IPv6 INPUT / FORWARD — same policy. ICMPv6 must stay open or v6 breaks.
# =============================================================================
F6="firewall ipv6 input filter"
S $F6 default-action drop
S $F6 rule 10 description "Allow loopback"
S $F6 rule 10 action accept
S $F6 rule 10 inbound-interface name lo
S $F6 rule 15 description "ICMPv6 (ND, RA, PMTU) — required for IPv6"
S $F6 rule 15 action accept
S $F6 rule 15 protocol ipv6-icmp
S $F6 rule 16 description "DHCPv6 client replies on WAN"
S $F6 rule 16 action accept
S $F6 rule 16 protocol udp
S $F6 rule 16 source port 547
S $F6 rule 16 destination port 546
if [ ${#MGMT_NETS6[@]} -gt 0 ]; then
  S $F6 rule 20 description "SSH from IPv6 management networks on LAN"
  S $F6 rule 20 action accept
  S $F6 rule 20 protocol tcp
  S $F6 rule 20 destination port "$SSH_PORT"
  S $F6 rule 20 source group network-group MGMT-v6
  S $F6 rule 20 inbound-interface group LAN
fi
S $F6 rule 40 description "DNS from LAN"
S $F6 rule 40 action accept
S $F6 rule 40 protocol tcp_udp
S $F6 rule 40 destination port 53
S $F6 rule 40 inbound-interface group LAN

FF6="firewall ipv6 forward filter"
S $FF6 default-action drop
S $FF6 rule 15 description "ICMPv6 through the router"
S $FF6 rule 15 action accept
S $FF6 rule 15 protocol ipv6-icmp
S $FF6 rule 100 description "LAN may go anywhere"
S $FF6 rule 100 action accept
S $FF6 rule 100 inbound-interface group LAN

# =============================================================================
# 7. SSH daemon hardening
# =============================================================================
S service ssh port "$SSH_PORT"
for a in "${SSH_LISTEN[@]}"; do
  S service ssh listen-address "$a"
done
S service ssh disable-host-validation          # no reverse-DNS lookups on login
S service ssh client-keepalive-interval 300

# Brute-force protection (sshguard)
S service ssh dynamic-protection
S service ssh dynamic-protection threshold 30
S service ssh dynamic-protection detect-time 1800
S service ssh dynamic-protection block-time 300
for n in "${MGMT_NETS[@]}"; do
  S service ssh dynamic-protection allow-from "$n"
done

# Modern crypto only. Node is 'ciphers' on 1.4 and 'cipher' on newer builds.
if   has_node service/ssh/cipher;  then CIPH=cipher
elif has_node service/ssh/ciphers; then CIPH=ciphers
else CIPH=""; warn "ssh cipher node not found; skipping cipher restriction"; fi
if [ -n "$CIPH" ]; then
  for c in chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr; do
    S service ssh "$CIPH" "$c"
  done
fi
for m in hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com; do
  S service ssh mac "$m"
done
for k in curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group16-sha512 diffie-hellman-group18-sha512; do
  S service ssh key-exchange "$k"
done

# =============================================================================
# 8. Accounts: key-based admin, no passwords over SSH, optional removal of 'vyos'
# =============================================================================
if [ -n "$ADMIN_USER" ]; then
  S system login user "$ADMIN_USER" authentication public-keys "$KEY_NAME" type "$KEY_TYPE"
  S system login user "$ADMIN_USER" authentication public-keys "$KEY_NAME" key "$KEY_BODY"
  # Locks the account to keys over SSH; set a console password manually afterwards:
  #   set system login user <name> authentication plaintext-password <pw>
fi

if [ -n "$PUBKEY_FILE" ]; then
  S service ssh disable-password-authentication
else
  warn "No --pubkey-file given: leaving SSH password auth ON. Change the 'vyos' password!"
fi

if [ "$REMOVE_DEFAULT_USER" -eq 1 ]; then
  D system login user vyos
fi

# =============================================================================
# 9. Misc system hardening
# =============================================================================
S system login banner pre-login "$BANNER"
has_node system/option/ctrl-alt-delete && S system option ctrl-alt-delete ignore
has_node system/login/timeout          && S system login timeout 900   # idle shell logout (s)
has_node system/ip/disable-directed-broadcast && S system ip disable-directed-broadcast

# =============================================================================
# Commit / save
# =============================================================================
if [ "$DRY_RUN" -eq 1 ]; then
  echo "# ---- end of dry run ----"
  exit 0
fi

if [ ${#FAILED[@]} -gt 0 ]; then
  echo
  echo "The following commands failed; NOTHING was committed:" >&2
  printf '   %s\n' "${FAILED[@]}" >&2
  exit 1      # leaving the session discards uncommitted changes
fi

info "Committing..."
commit || { echo "Commit failed; config left unchanged." >&2; exit 1; }

if [ "$DO_SAVE" -eq 1 ]; then
  save && info "Saved to /config/config.boot"
else
  cat <<EOF

=====================================================================
 Committed but NOT saved.
 1. Open a NEW SSH session${ADMIN_USER:+ as '$ADMIN_USER'} and confirm you can log in.
 2. If it works:    configure; save; exit
 3. If locked out:  reboot from the console — the old config returns.
 Backup:            /config/config.boot.pre-hardening-$TS
=====================================================================
EOF
fi
exit
