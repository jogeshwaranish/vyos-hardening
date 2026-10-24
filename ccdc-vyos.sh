#!/bin/vbash
# =============================================================================
# ccdc-vyos.sh: VyOS defense toolkit for CCDC-style competitions
#
#   audit      read-only hunt for red-team persistence + full state dump
#   backup     snapshot config (boot + commands) to $REPORT_DIR
#   creds      rotate passwords, wipe SSH keys, remove rogue users, kick sessions
#   purge      interactively remove config/filesystem persistence found by audit
#   harden     rebuild firewall around scored services + SSH/kernel hardening
#   confirm    cancel the rollback timer and save
#   rollback   restore the most recent backup immediately
#   block IP.. drop an attacker everywhere and flush their connections
#   unblock IP..
#   status     show rollback timer, blocklist, recent firewall drops
#
# Targets VyOS 1.4 (Sagitta) and newer. `audit` and `backup` work on older builds.
# Run as a VyOS admin user, NOT with sudo:   ./ccdc-vyos.sh audit
# =============================================================================

SELF="$(readlink -f "$0")"
CMD="${1:-help}"; shift 2>/dev/null

# Config-changing commands need the vyattacfg group or VyOS config gets corrupted.
case "$CMD" in
  creds|purge|harden|confirm|rollback|block|unblock)
    if [ "$(id -g -n)" != "vyattacfg" ]; then
      exec sg vyattacfg -c "/bin/vbash $(printf '%q ' "$SELF" "$CMD" "$@")"
    fi ;;
esac
[ "$(id -u)" -eq 0 ] && { echo "Do not run as root/sudo (breaks VyOS config sessions)." >&2; exit 1; }

source /opt/vyatta/etc/functions/script-template

# ----------------------------------------------------------------------------- config
CONF=""
if [ "$1" = "-c" ]; then CONF="$2"; shift 2; fi
[ -z "$CONF" ] && CONF="$(dirname "$SELF")/ccdc.conf"
if [ -r "$CONF" ]; then
  # shellcheck disable=SC1090
  source "$CONF"
fi
REPORT_DIR="${REPORT_DIR:-/config/ccdc}"
ROLLBACK_MINUTES="${ROLLBACK_MINUTES:-5}"
SSH_PORT="${SSH_PORT:-22}"
EGRESS_MODE="${EGRESS_MODE:-restricted}"
IPV6_MODE="${IPV6_MODE:-block}"
TS="$(date +%Y%m%d-%H%M%S)"
DEADMAN_SCRIPT=/tmp/ccdc-deadman.sh
TEMPLATES=/opt/vyatta/share/vyatta-cfg/templates
mkdir -p "$REPORT_DIR" "$REPORT_DIR/quarantine" 2>/dev/null

# ----------------------------------------------------------------------------- helpers
R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; B=$'\e[1m'; N=$'\e[0m'
die()  { echo "${R}ERROR:${N} $*" >&2; cli-shell-api inSession 2>/dev/null && exit_cfg; builtin exit 1; }
info() { echo "${G}[*]${N} $*"; }
warn() { echo "${Y}[!]${N} $*"; }
ask()  { [ "${ASSUME_YES:-0}" = 1 ] && { echo "$1 [auto-yes]"; return 0; }; local a; read -r -p "$1 [y/N] " a </dev/tty; [[ "$a" == [yY]* ]]; }
has_node() { [ -d "$TEMPLATES/$1" ]; }
need_conf() { [ -r "$CONF" ] || die "no config: copy ccdc.conf.example to $CONF and fill it in"; }

# List child node names of a running-config path WITHOUT eval. Node names are
# attacker-controlled on a pre-compromised box; never eval them.
nodes() { cli-shell-api listActiveNodes "$@" 2>/dev/null | xargs -r -n1 printf '%s\n' 2>/dev/null; }
exists() { cli-shell-api existsActive "$@" 2>/dev/null; }

cfg_cmds() {
  run show configuration commands 2>/dev/null \
    || /opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands 2>/dev/null
}

# Writable overlay layer of the running image ("" if not found)
rw_dir() {
  local union rw
  union="$(tr ' ' '\n' < /proc/cmdline | sed -n 's/^vyos-union=//p')"
  rw="/usr/lib/live/mount/persistence${union}/rw"
  if [ -n "$union" ] && sudo test -d "$rw"; then echo "$rw"; return; fi
  # fallback: ask the kernel which upperdir backs /
  rw="$(findmnt -n -o OPTIONS / 2>/dev/null | tr ',' '\n' | sed -n 's/^upperdir=//p')"
  [ -n "$rw" ] && sudo test -d "$rw" && echo "$rw"
}

FAILED=()
S() { set "$@"    || FAILED+=("set $*"); }
D() { exists "$@" && { delete "$@" || FAILED+=("delete $*"); }; return 0; }

commit_or_bail() {
  if [ ${#FAILED[@]} -gt 0 ]; then
    echo "${R}These commands failed. NOTHING committed:${N}" >&2
    printf '   %s\n' "${FAILED[@]}" >&2
    exit_cfg; builtin exit 1
  fi
  commit || die "commit failed; running config unchanged"
}

do_backup() {
  local f="$REPORT_DIR/backup-$TS"
  sudo cp /config/config.boot "$f.boot" || die "backup failed"
  sudo chmod 644 "$f.boot"
  cfg_cmds > "$f.cmds"
  ln -sf "$f.boot" "$REPORT_DIR/last-backup.boot"
  info "Backup: $f.boot (+ .cmds)"
  LAST_BACKUP="$f.boot"
}

start_deadman() {
  local backup="$1" mins="$ROLLBACK_MINUTES"
  stop_deadman quiet
  cat > "$DEADMAN_SCRIPT" <<EOF
#!/bin/vbash
sleep $((mins * 60))
source /opt/vyatta/etc/functions/script-template
configure
load $backup
commit
exit
EOF
  chmod 700 "$DEADMAN_SCRIPT"
  setsid nohup sg vyattacfg -c "/bin/vbash $DEADMAN_SCRIPT" \
    >> "$REPORT_DIR/deadman.log" 2>&1 < /dev/null &
  echo "$(date -d "+$mins min" +%H:%M:%S)" > /tmp/ccdc-deadman.at
  echo
  echo "${B}${Y}=== ROLLBACK ARMED: config reverts at $(cat /tmp/ccdc-deadman.at) (${mins} min) ===${N}"
  echo "${Y}    Test from a NEW session: SSH in, check scored services on the scoreboard.${N}"
  echo "${Y}    Then run:  $SELF confirm${N}"
}

stop_deadman() {
  if pkill -f "$DEADMAN_SCRIPT" 2>/dev/null; then
    [ "$1" = quiet ] || info "Rollback timer cancelled."
  fi
  rm -f /tmp/ccdc-deadman.at
}

# =============================================================================
# AUDIT: read-only. Everything goes to the screen and to a report file.
# =============================================================================
cmd_audit() {
  local rpt="$REPORT_DIR/audit-$TS.txt"
  local CFG; CFG="$(cfg_cmds)"
  local FINDINGS=0

  sec()  { printf '\n%s==== %s ====%s\n' "$B" "$*" "$N"; }
  flag() { printf '%s[!] %s%s\n' "$R" "$*" "$N"; FINDINGS=$((FINDINGS+1)); }
  grepcfg() { grep -E "$1" <<< "$CFG"; }
  show_if() {   # show_if "title" "regex" -> print + flag if anything matches
    local m; m="$(grepcfg "$2")"
    if [ -n "$m" ]; then flag "$1"; sed 's/^/    /' <<< "$m"; fi
  }

  {
  echo "CCDC VyOS audit: $(hostname) - $(date)"
  run show version 2>/dev/null | grep -E '^(Version|Built on|Boot via|System type)'

  sec "1. Accounts (config)"
  local u users=()
  mapfile -t users < <(nodes system login user)
  for u in "${users[@]}"; do
    local keys; keys="$(nodes system login user "$u" authentication public-keys | tr '\n' ' ')"
    printf '    %-16s keys: %s\n' "$u" "${keys:-none}"
    if [ ${#KEEP_USERS[@]} -gt 0 ] && [[ ! " ${KEEP_USERS[*]} " =~ " $u " ]]; then
      flag "user '$u' not in KEEP_USERS"
    fi
    [ -n "$keys" ] && flag "user '$u' has SSH keys. Did YOU add them?"
  done
  show_if "remote auth server configured (auth backdoor?)" '^set system login (radius|tacacs)'

  sec "2. Accounts (OS level)"
  local extra
  extra="$(awk -F: '$3==0 && $1!="root"' /etc/passwd)"
  [ -n "$extra" ] && { flag "non-root UID 0 accounts:"; sed 's/^/    /' <<< "$extra"; }
  while IFS=: read -r name _ uid _ _ home shell; do
    [ "$uid" -ge 1000 ] || continue
    [[ "$shell" =~ (nologin|false)$ ]] && continue
    [[ " ${users[*]} " =~ " $name " ]] || flag "OS user '$name' ($shell) is not in VyOS config"
  done < /etc/passwd
  sudo grep -hvE '^\s*(#|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/^/    sudoers: /'
  echo "    -- authorized_keys files --"
  sudo find /root /home -name 'authorized_keys*' -type f 2>/dev/null | while read -r f; do
    printf '    %s (%s keys)\n' "$f" "$(sudo grep -cvE '^\s*(#|$)' "$f")"
    sudo awk '!/^#/ && NF {print "        " $1, $NF}' "$f"
  done
  echo "    -- logged in now --"; who | sed 's/^/    /'
  echo "    -- recent logins --"; last -n 15 2>/dev/null | sed 's/^/    /'

  sec "3. Scheduled / triggered execution (classic persistence)"
  show_if "task-scheduler tasks"         '^set system task-scheduler'
  show_if "event-handler (runs scripts on log patterns)" '^set service event-handler'
  show_if "containers"                   '^set container'
  show_if "commit-archive (config exfil to remote)" '^set system config-management commit-archive'
  for f in /config/scripts/vyos-preconfig-bootup.script /config/scripts/vyos-postconfig-bootup.script; do
    [ -f "$f" ] || continue
    local body; body="$(grep -vE '^\s*(#|$)' "$f")"
    [ -n "$body" ] && { flag "non-empty boot script $f:"; sed 's/^/    /' <<< "$body"; }
  done
  local hooks; hooks="$(find /config/scripts/commit -type f 2>/dev/null)"
  [ -n "$hooks" ] && { flag "commit hooks (run on EVERY commit):"; sed 's/^/    /' <<< "$hooks"; }
  local cron; cron="$(sudo sh -c 'grep -vhE "^\s*(#|$)|^[A-Z_]+=" /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null')"
  [ -n "$cron" ] && { echo "    -- cron entries (review) --"; sed 's/^/    /' <<< "$cron"; }
  [ -s /etc/ld.so.preload ] && { flag "/etc/ld.so.preload is set (userland rootkit):"; sed 's/^/    /' /etc/ld.so.preload; }
  [ -s /etc/rc.local ] && grep -vqE '^\s*(#|$|builtin exit 0)' /etc/rc.local && flag "/etc/rc.local has content"
  echo "    -- systemd units that are real files in /etc (not symlinks) --"
  sudo find /etc/systemd/system -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null | sed 's/^/    /'
  echo "    -- timers --"; systemctl list-timers --all --no-pager 2>/dev/null | head -20 | sed 's/^/    /'

  sec "4. Files changed vs. the stock image (overlay upper dir)"
  # VyOS runs from a read-only squashfs; every modified/added system file lives
  # in the rw overlay. This is the single best "what did they touch" view.
  local rw; rw="$(rw_dir)"
  if [ -n "$rw" ]; then
    sudo find "$rw" -xdev -type f \
      \( -path "$rw/var/*" -o -path "$rw/tmp/*" -o -path "$rw/run/*" \
         -o -path "$rw/opt/vyatta/config/*" -o -path "*/__pycache__/*" \) -prune -o -type f \
      -printf '    %TY-%Tm-%Td %TH:%TM  %P\n' 2>/dev/null | sort -r | head -80
    sudo find "$rw" -xdev -type f \( -path "$rw/usr/*" -o -path "$rw/bin/*" -o -path "$rw/sbin/*" \
      -o -path "$rw/lib/*" -o -path "$rw/etc/pam.d/*" -o -path "$rw/etc/ssh/*" \) -printf '%P\n' 2>/dev/null \
      | while read -r f; do flag "system binary/auth file modified: /$f"; done
  else
    echo "    (overlay rw dir not found; live ISO or unusual install. Check mounts: findmnt -t overlay)"
  fi

  sec "5. Network persistence & redirection"
  show_if "destination NAT / port forwards (verify each one is a scored service)" '^set nat destination'
  show_if "source NAT"                    '^set nat source'
  show_if "static routes"                 '^set protocols static'
  show_if "dynamic routing"               '^set protocols (bgp|ospf|ospfv3|rip|isis)'
  show_if "policy routing"                '^set policy (route|route6|local-route)'
  show_if "tunnels / VPN interfaces"      '^set interfaces (wireguard|openvpn|tunnel|vxlan|l2tpv3|geneve|pseudo-ethernet|sstpc|pppoe)'
  show_if "VPN services"                  '^set vpn'
  show_if "DNS overrides / forwarders (hijack?)" '^set service dns forwarding (domain|name-server|authoritative-domain)'
  show_if "static host mappings"          '^set system static-host-mapping'
  show_if "remote syslog targets"         '^set system syslog (host|remote)'
  show_if "load-balancing / proxy / relay" '^set (load-balancing|service webproxy|service broadcast-relay|service mdns)'
  show_if "custom sysctls"                '^set system sysctl'
  echo "    -- system name-servers --"; grepcfg '^set system name-server' | sed 's/^/    /'

  sec "6. Management-plane services"
  show_if "telnet"        '^set service telnet'
  show_if "HTTPS API"     '^set service https'
  show_if "SNMP"          '^set service snmp'
  show_if "UPnP"          '^set service upnp'
  show_if "LLDP"          '^set service lldp'
  echo "    -- ssh --"; grepcfg '^set service ssh' | sed 's/^/    /'

  sec "7. Firewall as found"
  grepcfg '^set firewall' | sed 's/^/    /' | head -150
  show_if "firewall hooks outside input/forward (output, prerouting, bridge, raw)" \
          '^set firewall (ipv4|ipv6) (output|prerouting)|^set firewall bridge'
  show_if "state-policy accepting invalid" '^set firewall global-options state-policy invalid action .accept'
  echo "    -- nftables tables (anything not vyos_* is suspicious) --"
  sudo nft list tables 2>/dev/null | sed 's/^/    /'
  sudo nft list tables 2>/dev/null | grep -vE 'vyos|VYOS|nat|filter|raw|mangle|vrf' | while read -r t; do flag "unexpected nft table: $t"; done

  sec "8. Live sockets & processes"
  echo "    -- listening --"; sudo ss -tulpnH 2>/dev/null | sed 's/^/    /'
  echo "    -- established --"; sudo ss -tnpH state established 2>/dev/null | sed 's/^/    /'
  local susp
  susp="$(ps -eo pid,user,args --no-headers | grep -E '(^|[ /])(nc|ncat|netcat|socat|telnet)( |$)|/dev/tcp|bash -i|sh -i|python[0-9.]* -c|perl -e|php -r|/tmp/|/dev/shm/|/var/tmp/|meterpreter|sliver|chisel|ligolo' | grep -v -e grep -e ccdc-vyos)"
  [ -n "$susp" ] && { flag "suspicious processes:"; sed 's/^/    /' <<< "$susp"; }
  local drops; drops="$(sudo find /tmp /var/tmp /dev/shm -type f -perm -u+x 2>/dev/null)"
  [ -n "$drops" ] && { flag "executables in tmp dirs:"; sed 's/^/    /' <<< "$drops"; }
  ip -d link 2>/dev/null | grep -q PROMISC && flag "interface in promiscuous mode (sniffer?)"
  echo "    -- addresses --"; ip -br addr | sed 's/^/    /'
  echo "    -- routes --"; ip route | sed 's/^/    /'
  echo "    -- ip rules --"; ip rule | sed 's/^/    /'

  sec "SUMMARY"
  echo "    $FINDINGS item(s) flagged. Full config dump: $REPORT_DIR/audit-$TS.cmds"
  } 2>&1 | tee "$rpt"
  cfg_cmds > "$REPORT_DIR/audit-$TS.cmds"
  echo; info "Report saved: $rpt"
}

# =============================================================================
# CREDS: rotate passwords, wipe keys, delete rogue users, kick sessions
# =============================================================================
cmd_creds() {
  local me; me="$(id -un)"
  [ ${#KEEP_USERS[@]} -gt 0 ] || KEEP_USERS=( "$me" )
  [[ " ${KEEP_USERS[*]} " =~ " $me " ]] || die "you ($me) aren't in KEEP_USERS; you'd lock yourself out"
  do_backup
  configure

  local u users=()
  mapfile -t users < <(nodes system login user)
  for u in "${users[@]}"; do
    if [[ " ${KEEP_USERS[*]} " =~ " $u " ]]; then
      local p1 p2
      while :; do
        read -r -s -p "New password for $u: " p1 </dev/tty; echo
        read -r -s -p "Again: " p2 </dev/tty; echo
        [ "$p1" = "$p2" ] && [ ${#p1} -ge 12 ] && break
        warn "mismatch or shorter than 12 chars, try again"
      done
      S system login user "$u" authentication plaintext-password "$p1"
      D system login user "$u" authentication public-keys
      D system login user "$u" authentication otp
    elif [ "$u" != "$me" ] && ask "Delete user '$u'?"; then
      D system login user "$u"
    fi
  done
  # Users in KEEP_USERS that don't exist yet are NOT created (typo protection).

  if [ -n "$TEAM_PUBKEY" ]; then
    local kt kb kc; read -r kt kb kc <<< "$TEAM_PUBKEY"
    kc="${kc:-team}"; kc="${kc//[^A-Za-z0-9@._-]/_}"
    for u in "${KEEP_USERS[@]}"; do
      exists system login user "$u" || continue
      S system login user "$u" authentication public-keys "$kc" type "$kt"
      S system login user "$u" authentication public-keys "$kc" key "$kb"
    done
  fi

  exists system login radius  && ask "Remove RADIUS auth?"  && D system login radius
  exists system login tacacs  && ask "Remove TACACS auth?"  && D system login tacacs

  commit_or_bail
  save && info "Credentials committed and SAVED (a red-team reboot won't revert them)."
  exit_cfg

  echo; info "Other sessions:"; who | grep -v "$(tty | sed 's|/dev/||')" | sed 's/^/    /'
  if ask "Kill ALL other login sessions (existing shells survive password changes)?"; then
    local mytty; mytty="$(tty | sed 's|/dev/||')"
    who | awk '{print $2}' | grep -vx "$mytty" | sort -u | while read -r t; do
      sudo pkill -KILL -t "$t" && info "killed $t"
    done
  fi
}

# =============================================================================
# PURGE: walk every persistence location, ask per item
# =============================================================================
# Files in classic persistence locations that differ from the stock image.
# VyOS boots a read-only squashfs; anything added/modified lives in the rw
# overlay, so this catches implants planted BEFORE the image was handed to you.
changed_persistence_files() {
  local rw; rw="$(rw_dir)"
  if [ -n "$rw" ]; then
    sudo find "$rw/etc/cron.d" "$rw/etc/cron.hourly" "$rw/etc/cron.daily" "$rw/etc/crontab" \
              "$rw/var/spool/cron" "$rw/etc/profile.d" "$rw/etc/bash.bashrc" "$rw/etc/profile" \
              "$rw/usr/local/bin" "$rw/usr/local/sbin" "$rw/etc/systemd/system" "$rw/lib/systemd/system" \
              "$rw/etc/ld.so.preload" "$rw/etc/rc.local" "$rw/etc/update-motd.d" \
              "$rw/root/.bashrc" "$rw/root/.profile" \
              -type f 2>/dev/null | sed "s|^$rw||"
    sudo find "$rw/home" -maxdepth 2 -type f \( -name '.bash*' -o -name '.profile' \) 2>/dev/null \
      | sed "s|^$rw||"
  else   # live/non-installed image: fall back to the obvious spots
    sudo find /etc/cron.d /var/spool/cron/crontabs /usr/local/bin /usr/local/sbin -type f 2>/dev/null
    [ -s /etc/ld.so.preload ] && echo /etc/ld.so.preload
  fi
}

quarantine() {   # move a file out of the way but keep it for the incident report
  local f="$1" dst; dst="$REPORT_DIR/quarantine/$(echo "$f" | tr / _)-$TS"
  sudo mv "$f" "$dst" && sudo chmod 000 "$dst" && info "quarantined $f -> $dst"
}

purge_nodes() {   # purge_nodes "label" path... ; asks per child node
  local label="$1"; shift
  local n
  while read -r n; do
    [ -z "$n" ] && continue
    echo "${B}-- $label: $n${N}"
    cfg_cmds | grep -F -e "set $* $n " -e "set $* '$n'" | sed 's/^/    /' | head -12
    ask "  delete $label '$n'?" && D "$@" "$n"
  done < <(nodes "$@")
}

cmd_purge() {
  do_backup
  local backup="$LAST_BACKUP"
  configure

  purge_nodes "scheduled task"   system task-scheduler task
  purge_nodes "event handler"    service event-handler event
  purge_nodes "container"        container name
  purge_nodes "DNAT rule"        nat destination rule
  purge_nodes "wireguard if"     interfaces wireguard
  purge_nodes "openvpn if"       interfaces openvpn
  purge_nodes "tunnel if"        interfaces tunnel
  purge_nodes "static host map"  system static-host-mapping host-name
  purge_nodes "DNS override"     service dns forwarding domain
  purge_nodes "syslog host"      system syslog host
  purge_nodes "syslog remote"    system syslog remote
  for svc in "service telnet" "service https" "service snmp" "service upnp" \
             "system config-management commit-archive" "system login radius" "system login tacacs"; do
    # shellcheck disable=SC2086
    exists $svc && ask "delete '$svc'?" && D $svc
  done

  commit_or_bail
  exit_cfg

  # Filesystem persistence (not covered by config rollback, so we quarantine)
  local f
  for f in /config/scripts/vyos-preconfig-bootup.script /config/scripts/vyos-postconfig-bootup.script; do
    [ -f "$f" ] && grep -vqE '^\s*(#|$)' "$f" || continue
    echo "${B}-- $f${N}"; grep -vE '^\s*(#|$)' "$f" | sed 's/^/    /'
    if ask "  reset $f to an empty stock script?"; then
      quarantine "$f"; printf '#!/bin/sh\n# reset by ccdc-vyos.sh %s\n' "$TS" | sudo tee "$f" >/dev/null
      sudo chmod 755 "$f"; sudo chgrp vyattacfg "$f" 2>/dev/null
    fi
  done
  while read -r f; do
    [ -z "$f" ] && continue
    echo "${B}-- commit hook $f${N}"; sudo head -15 "$f" | sed 's/^/    /'
    ask "  quarantine?" && quarantine "$f"
  done < <(find /config/scripts/commit -type f 2>/dev/null)
  while read -r f; do
    [ -z "$f" ] && continue
    echo "${B}-- $f${N}"; sudo head -10 "$f" | sed 's/^/    /'
    ask "  quarantine?" && quarantine "$f"
  done < <(changed_persistence_files)
  while read -r f; do
    [ -z "$f" ] && continue
    echo "${B}-- $f${N}"; sudo awk '!/^#/ && NF {print "    " $1, $NF}' "$f"
    ask "  quarantine (VyOS re-creates keys that are in the config on commit)?" && quarantine "$f"
  done < <(sudo find /root /home -name 'authorized_keys*' -type f 2>/dev/null)
  while read -r pid args; do
    echo "${B}-- suspicious process $pid: $args${N}"
    ask "  kill -9 $pid?" && sudo kill -9 "$pid"
  done < <(ps -eo pid,args --no-headers | grep -E '(^|[ /])(nc|ncat|netcat|socat)( |$)|/dev/tcp|bash -i|sh -i|python[0-9.]* -c|perl -e|/tmp/|/dev/shm/|/var/tmp/' | grep -v -e grep -e ccdc-vyos)

  start_deadman "$backup"
}

# =============================================================================
# HARDEN: rebuild the firewall around scored services
# =============================================================================
cmd_harden() {
  need_conf
  has_node firewall/ipv4/input/filter || die "VyOS < 1.4 firewall syntax detected; harden needs 1.4+. Use audit/creds/purge."
  [ -n "$WAN_IF" ] && [ ${#LAN_IFS[@]} -gt 0 ] && [ ${#MGMT_NETS[@]} -gt 0 ] \
    || die "WAN_IF, LAN_IFS and MGMT_NETS must be set in $CONF"

  echo "${B}Plan:${N} WAN=$WAN_IF LAN=${LAN_IFS[*]} MGMT=${MGMT_NETS[*]} egress=$EGRESS_MODE ipv6=$IPV6_MODE"
  printf '      scored: %s\n' "${SCORED_SERVICES[@]:-(none!)}"
  [ ${#SCORED_SERVICES[@]} -eq 0 ] && warn "No SCORED_SERVICES: ALL inbound WAN->LAN traffic will be dropped."
  ask "Rebuild firewall now (rollback timer: ${ROLLBACK_MINUTES}m)?" || builtin exit 0

  do_backup
  local backup="$LAST_BACKUP"
  configure

  # --- wipe the filter chains we own (red team rules go with them). Keep BLOCKLIST.
  D firewall ipv4 input filter
  D firewall ipv4 forward filter
  D firewall ipv4 output filter
  D firewall ipv6 input filter
  D firewall ipv6 forward filter
  D firewall ipv6 output filter
  local n
  while read -r n; do D firewall ipv4 name "$n"; done < <(nodes firewall ipv4 name)
  while read -r n; do D firewall ipv6 name "$n"; done < <(nodes firewall ipv6 name)
  if exists firewall zone; then
    warn "zone-based firewall found; it references named chains and must go too."
    ask "Delete 'firewall zone'?" && D firewall zone || die "aborting: zone firewall conflicts with rebuild"
  fi
  D firewall group interface-group WAN
  D firewall group interface-group LAN
  D firewall group network-group MGMT-v4
  D firewall group address-group SCORING

  # --- groups
  S firewall group interface-group WAN interface "$WAN_IF"
  for n in "${LAN_IFS[@]}";   do S firewall group interface-group LAN interface "$n"; done
  for n in "${MGMT_NETS[@]}"; do S firewall group network-group MGMT-v4 network "$n"; done
  for n in "${SCORING_ENGINE_IPS[@]}"; do S firewall group address-group SCORING address "$n"; done
  # BLOCKLIST must exist for rules to reference it; 192.0.2.1 (TEST-NET) is a harmless placeholder
  exists firewall group address-group BLOCKLIST || S firewall group address-group BLOCKLIST address 192.0.2.1

  # --- kernel
  S firewall global-options all-ping enable
  S firewall global-options broadcast-ping disable
  S firewall global-options ip-src-route disable
  S firewall global-options ipv6-src-route disable
  S firewall global-options receive-redirects disable
  S firewall global-options ipv6-receive-redirects disable
  S firewall global-options send-redirects disable
  S firewall global-options log-martians enable
  S firewall global-options source-validation loose   # strict breaks asymmetric CCDC topologies
  S firewall global-options syn-cookies enable
  S firewall global-options twa-hazards-protection enable
  S firewall global-options state-policy established action accept
  S firewall global-options state-policy related action accept
  S firewall global-options state-policy invalid action drop

  # --- IPv4 INPUT (to the router)
  local I="firewall ipv4 input filter"
  S $I default-action drop
  S $I rule 5 action drop;    S $I rule 5 source group address-group BLOCKLIST;  S $I rule 5 log
  S $I rule 10 action accept; S $I rule 10 inbound-interface name lo
  S $I rule 20 description "SSH from MGMT via LAN"
  S $I rule 20 action accept; S $I rule 20 protocol tcp; S $I rule 20 destination port "$SSH_PORT"
  S $I rule 20 source group network-group MGMT-v4; S $I rule 20 inbound-interface group LAN
  S $I rule 30 action accept; S $I rule 30 protocol icmp; S $I rule 30 icmp type-name echo-request
  S $I rule 30 inbound-interface group LAN
  S $I rule 31 action accept; S $I rule 31 protocol icmp; S $I rule 31 icmp type-name echo-request
  S $I rule 31 inbound-interface group WAN; S $I rule 31 limit rate 5/second
  if [ "$ROUTER_SERVES_DNS" = yes ]; then
    S $I rule 40 action accept; S $I rule 40 protocol tcp_udp; S $I rule 40 destination port 53
    S $I rule 40 inbound-interface group LAN
  fi
  if [ "$ROUTER_SERVES_DHCP" = yes ]; then
    S $I rule 50 action accept; S $I rule 50 protocol udp; S $I rule 50 destination port 67
    S $I rule 50 inbound-interface group LAN
  fi
  if [ "$ROUTER_SERVES_NTP" = yes ]; then
    S $I rule 60 action accept; S $I rule 60 protocol udp; S $I rule 60 destination port 123
    S $I rule 60 inbound-interface group LAN
  fi
  S $I rule 999 action drop; S $I rule 999 log

  # --- IPv4 FORWARD (through the router)
  local F="firewall ipv4 forward filter" r=100 svc proto ip ports
  S $F default-action drop
  S $F rule 5 action drop; S $F rule 5 source group address-group BLOCKLIST;      S $F rule 5 log
  S $F rule 6 action drop; S $F rule 6 destination group address-group BLOCKLIST; S $F rule 6 log
  if [ ${#SCORING_ENGINE_IPS[@]} -gt 0 ]; then
    S $F rule 10 description "Scoring engine: never block"
    S $F rule 10 action accept; S $F rule 10 source group address-group SCORING
  fi
  for svc in "${SCORED_SERVICES[@]}"; do
    read -r proto ip ports _ <<< "$svc"
    [ -n "$ports" ] || { FAILED+=("bad SCORED_SERVICES entry: '$svc'"); continue; }
    S $F rule $r description "scored $proto $ip:$ports"
    S $F rule $r action accept
    S $F rule $r protocol "$proto"
    S $F rule $r destination address "$ip"
    S $F rule $r destination port "$ports"
    r=$((r+1))
  done
  S $F rule 200 description "LAN <-> LAN"
  S $F rule 200 action accept; S $F rule 200 inbound-interface group LAN; S $F rule 200 outbound-interface group LAN
  if [ "$EGRESS_MODE" = open ]; then
    S $F rule 300 action accept; S $F rule 300 inbound-interface group LAN
  else
    S $F rule 300 description "egress TCP";  S $F rule 300 action accept; S $F rule 300 protocol tcp
    S $F rule 300 destination port "$EGRESS_TCP"; S $F rule 300 inbound-interface group LAN
    S $F rule 301 description "egress UDP";  S $F rule 301 action accept; S $F rule 301 protocol udp
    S $F rule 301 destination port "$EGRESS_UDP"; S $F rule 301 inbound-interface group LAN
    S $F rule 302 description "egress ICMP"; S $F rule 302 action accept; S $F rule 302 protocol icmp
    S $F rule 302 inbound-interface group LAN
    S $F rule 390 description "EGRESS DENY (reverse shells / C2)"
    S $F rule 390 action drop; S $F rule 390 inbound-interface group LAN; S $F rule 390 log
  fi
  S $F rule 999 action drop; S $F rule 999 log

  # --- IPv6
  local I6="firewall ipv6 input filter" F6="firewall ipv6 forward filter"
  S $I6 default-action drop
  S $I6 rule 10 action accept; S $I6 rule 10 inbound-interface name lo
  S $I6 rule 15 action accept; S $I6 rule 15 protocol ipv6-icmp
  S $F6 default-action drop
  if [ "$IPV6_MODE" = passthrough ]; then
    S $F6 rule 15 action accept; S $F6 rule 15 protocol ipv6-icmp
    S $F6 rule 300 action accept; S $F6 rule 300 inbound-interface group LAN
  fi
  S $F6 rule 999 action drop; S $F6 rule 999 log

  # --- SSH
  D service ssh listen-address
  S service ssh port "$SSH_PORT"
  S service ssh disable-host-validation
  S service ssh client-keepalive-interval 60
  S service ssh dynamic-protection
  S service ssh dynamic-protection threshold 30
  S service ssh dynamic-protection detect-time 1800
  S service ssh dynamic-protection block-time 600
  for n in "${MGMT_NETS[@]}" "${SCORING_ENGINE_IPS[@]}"; do S service ssh dynamic-protection allow-from "$n"; done
  local CIPH=""
  has_node service/ssh/cipher && CIPH=cipher
  has_node service/ssh/ciphers && CIPH=ciphers
  if [ -n "$CIPH" ]; then
    D service ssh "$CIPH"
    for n in chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr; do
      S service ssh "$CIPH" "$n"; done
  fi
  D service ssh mac
  for n in hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com; do
    S service ssh mac "$n"; done
  D service ssh key-exchange
  for n in curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group16-sha512 diffie-hellman-group18-sha512; do
    S service ssh key-exchange "$n"; done
  if [ -n "$TEAM_PUBKEY" ]; then
    S service ssh disable-password-authentication
  else
    D service ssh disable-password-authentication
  fi

  # --- misc
  S system login banner pre-login "Authorized access only. All activity is monitored."
  has_node system/option/ctrl-alt-delete && S system option ctrl-alt-delete ignore
  has_node system/login/timeout          && S system login timeout 900

  commit_or_bail
  exit_cfg
  start_deadman "$backup"
}

# =============================================================================
# BLOCK / UNBLOCK / CONFIRM / ROLLBACK / STATUS
# =============================================================================
cmd_block() {
  [ $# -gt 0 ] || die "usage: block IP [IP...]"
  exists firewall group address-group BLOCKLIST || die "run harden first (BLOCKLIST group missing)"
  local ip ok=()
  for ip in "$@"; do
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(-[0-9]{1,3}(\.[0-9]{1,3}){3})?$ ]] || die "not an IPv4 address/range: $ip"
    if [[ " ${SCORING_ENGINE_IPS[*]} " =~ " $ip " ]]; then warn "refusing to block scoring engine $ip"; continue; fi
    ok+=("$ip")
  done
  [ ${#ok[@]} -gt 0 ] || die "nothing to block"
  configure
  for ip in "${ok[@]}"; do S firewall group address-group BLOCKLIST address "$ip"; done
  commit_or_bail; save >/dev/null; exit_cfg
  for ip in "${ok[@]}"; do
    # state-policy accepts ESTABLISHED before any rule, so kill live sessions too
    sudo conntrack -D -s "$ip" >/dev/null 2>&1
    sudo conntrack -D -d "$ip" >/dev/null 2>&1
    info "blocked $ip (existing connections flushed)"
  done
}

cmd_unblock() {
  [ $# -gt 0 ] || die "usage: unblock IP [IP...]"
  configure
  local ip; for ip in "$@"; do D firewall group address-group BLOCKLIST address "$ip"; done
  commit_or_bail; save >/dev/null; exit_cfg
  info "unblocked: $*"
}

cmd_confirm() {
  stop_deadman
  configure; save && info "Config saved to /config/config.boot"; exit_cfg
}

cmd_rollback() {
  local b="${1:-$REPORT_DIR/last-backup.boot}"
  [ -r "$b" ] || die "no backup at $b"
  stop_deadman quiet
  configure; load "$b"; commit && info "Rolled back to $(readlink -f "$b")"; exit_cfg
}

cmd_status() {
  if [ -f /tmp/ccdc-deadman.at ] && pgrep -f "$DEADMAN_SCRIPT" >/dev/null; then
    warn "Rollback timer ARMED: reverts at $(cat /tmp/ccdc-deadman.at)"
  else
    info "No rollback timer running."
  fi
  echo "${B}Blocklist:${N}"; nodes firewall group address-group BLOCKLIST address | sed 's/^/    /'
  echo "${B}Recent firewall drops:${N}"
  run show log firewall 2>/dev/null | tail -20 | sed 's/^/    /'
  echo "${B}Sessions:${N}"; who | sed 's/^/    /'
}

# After sourcing script-template, plain `exit` is an ALIAS that tears down the
# config session (it does not end the script). Script exits use `builtin exit`.
exit_cfg() { exit; }

usage() { sed -n '3,19p' "$SELF" | sed 's/^# \{0,1\}//'; }

case "$CMD" in
  audit)    cmd_audit ;;
  backup)   do_backup ;;
  creds)    cmd_creds ;;
  purge)    cmd_purge ;;
  harden)   cmd_harden ;;
  confirm)  cmd_confirm ;;
  rollback) cmd_rollback "$@" ;;
  block)    cmd_block "$@" ;;
  unblock)  cmd_unblock "$@" ;;
  status)   cmd_status ;;
  *)        usage ;;
esac
