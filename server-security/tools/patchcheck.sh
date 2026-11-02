#!/bin/zsh
# (c) 2026 David Reuchlein - https://david-reuchlein.de - https://github.com/reuchleindavid
# Lesende Patch-Prüfung auf eigenen Root-Servern: PHP-Quelle, installierte und verfügbare Versionen, Reboot.
# apt-get update holt nur Paketlisten, installiert nichts. Aufruf: zsh patchcheck.sh [hostdatei]
DIR=${0:A:h}; HF=${1:-$DIR/hosts-root.txt}
REMOTE='
echo "host: $(hostname)  os: $(. /etc/os-release; echo $PRETTY_NAME)"
echo "php-quelle: $(grep -rhs "^deb" /etc/apt/sources.list.d/ /etc/apt/sources.list | grep -iE "ondrej|sury|php" | head -1 || echo "nur Distributions-Repo")"
echo "fpm-dienste: $(systemctl list-units --type=service --state=running 2>/dev/null | grep -oE "php[0-9.]+-fpm" | tr "\n" " ")"
apt-get update -qq 2>/dev/null
for p in $(dpkg -l 2>/dev/null | grep -oE "^ii +php[0-9]\.[0-9]-(fpm|cli)" | awk "{print \$2}"); do
  inst=$(dpkg-query -W -f="\${Version}" $p 2>/dev/null)
  cand=$(apt-cache policy $p 2>/dev/null | awk "/Candidate:/{print \$2}")
  echo "$p: installiert $inst  verfuegbar $cand"
done
echo "unattended-upgrades: $(systemctl is-active unattended-upgrades 2>/dev/null)"
echo "reboot-required: $([ -f /var/run/reboot-required ] && echo ja || echo nein)"
'
grep -v -E '^\s*(#|$)' "$HF" | while IFS= read -r h; do
  echo "=================== $h"
  ssh -n -o BatchMode=yes -o ConnectTimeout=8 -o IdentitiesOnly=yes ${=h} "$REMOTE" 2>&1 | tail -12
done
