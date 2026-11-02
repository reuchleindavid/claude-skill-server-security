#!/bin/zsh
# (c) 2026 David Reuchlein - https://david-reuchlein.de - https://github.com/reuchleindavid
# Forensik auf allen Hosts parallel (6 gleichzeitig, nur lesend). Ausgabe je Host als Textdatei.
# Aufruf: RUN_DATE=2026-11-02 SINCE=2026-10-27 zsh forensik_run.sh [host-filter]
# Hosts aus hosts.txt (HOSTS_FILE überschreibt), Ausgabe nach $OUT_BASE/<RUN_DATE>/ (Standard ~/forensik).
DIR=${0:A:h}; HF=${HOSTS_FILE:-$DIR/hosts.txt}
OUT=${OUT_BASE:-$HOME/forensik}/${RUN_DATE:-$(date +%F)}; mkdir -p $OUT
SCRIPT=$DIR/forensik_remote.sh
run_one() {
  local h="$1"
  local n=$(echo "$h" | awk '{print $NF}' | tr '@' '_')
  ssh -n -o BatchMode=yes -o ConnectTimeout=12 -o IdentitiesOnly=yes ${=h} "SINCE=${SINCE:-$(date -v-7d +%F)} bash -s" < $SCRIPT > $OUT/$n.txt 2>&1
  echo "$n: exit $? $(wc -l < $OUT/$n.txt) Zeilen"
}
grep -v -E '^\s*(#|$)' "$HF" | while IFS= read -r h; do
  [ -n "$1" ] && [[ "$h" != *"$1"* ]] && continue
  run_one "$h" &
  while [ $(jobs -r | wc -l) -ge 6 ]; do sleep 2; done
done
wait
echo "FERTIG -> $OUT"
