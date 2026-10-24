#!/bin/vbash
# rotate-passwords.sh: set a random password for every VyOS login user.
# Usage:  ./rotate-passwords.sh            (all users)
#         ./rotate-passwords.sh vyos bob   (only these users)
# Run as a VyOS admin user, not with sudo. Write the passwords down before closing the terminal.

if [ "$(id -g -n)" != "vyattacfg" ]; then
  exec sg vyattacfg -c "/bin/vbash $(readlink -f "$0") $*"
fi

source /opt/vyatta/etc/functions/script-template

if [ $# -gt 0 ]; then
  users=("$@")
else
  mapfile -t users < <(cli-shell-api listActiveNodes system login user | xargs -r -n1 printf '%s\n')
fi

configure
out=()
for u in "${users[@]}"; do
  pw="$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)"
  if set system login user "$u" authentication plaintext-password "$pw" >/dev/null; then
    out+=("$u  $pw")
  else
    echo "failed to set password for $u" >&2
  fi
done
if ! commit; then
  exit   # in VyOS scripts this closes the config session
  echo "commit failed, no passwords were changed" >&2
  builtin exit 1
fi
save >/dev/null
exit

printf '\n%-16s %s\n' USER PASSWORD
printf '%s\n' "${out[@]}" | awk '{printf "%-16s %s\n", $1, $2}'
