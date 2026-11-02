#!/bin/zsh
# (c) 2026 David Reuchlein - https://david-reuchlein.de - https://github.com/reuchleindavid
# PHP-Versionen aller Hosts per SSH abfragen (nur lesend), eine Zeile je Host.
# Aufruf: zsh sweep.sh [hostdatei]   (Standard: hosts.txt neben dem Skript, Vorlage hosts.example)
DIR=${0:A:h}; HF=${1:-$DIR/hosts.txt}
REMOTE='printf "%s | %s | CLI %s | FPM: %s | Binaries: %s\n" "$(hostname)" "$(. /etc/os-release 2>/dev/null; echo ${PRETTY_NAME:-?})" "$(php -v 2>/dev/null | head -1 | cut -d" " -f2)" "$(ls /usr/sbin/php-fpm* /usr/sbin/php*-fpm 2>/dev/null | xargs -n1 basename 2>/dev/null | tr "\n" " ")" "$(ls /usr/bin/php[578]* /usr/local/bin/php[578]* /opt/plesk/php/*/bin/php /opt/php*/bin/php 2>/dev/null | grep -v -E "cgi|dbg|config|ize" | tr "\n" " ")"'
grep -v -E '^\s*(#|$)' "$HF" | while IFS= read -r h; do
  printf "%-48s " "$h"
  ssh -n -o BatchMode=yes -o ConnectTimeout=8 -o IdentitiesOnly=yes ${=h} "$REMOTE" 2>&1 | tail -1
done
