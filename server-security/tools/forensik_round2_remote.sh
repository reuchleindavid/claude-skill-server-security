#!/bin/bash
# (c) 2026 David Reuchlein - https://david-reuchlein.de - https://github.com/reuchleindavid
# Runde 2 (nur lesend): Botnetz-Ranges vom 25.10., Multipart-POST-Flut, Status je Tag. Stand 27.10.2026.
export LC_ALL=C
echo "### $(hostname) | $(date '+%F %T') | user=$(id -un)"
LOGS=$(find "$HOME"/logs /var/log/apache2 /var/log/nginx /var/log/httpd /var/www/*/log /var/www/share/logs /var/www/clients/*/*/log /var/www/vhosts/system/*/logs -maxdepth 3 -type f \( -name '*access*' -o -name 'access_log*' \) -newermt '2026-10-17 00:00' 2>/dev/null | grep -v -E 'ssl_request' | sort -u)
echo "Logdateien: $(echo $LOGS | wc -w)"
catlogs() { for l in $LOGS; do case "$l" in *.gz) zcat "$l";; *) cat "$l";; esac; done 2>/dev/null | grep -a -v '^{'; }
echo "## [A] Botnetz-Ranges 45.148.10/24 45.138.12/24 93.123.109/24 195.178.110/24 45.94.31/24 185.177.72/24 78.153.140/24: Methode+Status (gesamt seit 17.10.)"
catlogs | grep -a -E '^(- )?(45\.148\.10\.|45\.138\.12\.|93\.123\.109\.|195\.178\.110\.|45\.94\.31\.|185\.177\.72\.|78\.153\.140\.)' | awk '{for(i=1;i<=NF;i++) if($i ~ /^"(GET|POST|HEAD|OPTIONS)$/){print $i, $(i+3); break}}' | sort | uniq -c | sort -rn | head -10
echo "## [B] POST mit Status 200/500 aus diesen Ranges: Tag, URI, Status, Bytes (Top 15)"
catlogs | grep -a -E '^(- )?(45\.148\.10\.|45\.138\.12\.|93\.123\.109\.|195\.178\.110\.|45\.94\.31\.|185\.177\.72\.|78\.153\.140\.)' | grep -a -E '"POST [^"]+" (200|500|502|503) ' | awk '{d=""; for(i=1;i<=NF;i++){ if($i ~ /^\[/) d=substr($i,2,11); if($i=="\"POST"){print d, $(i+1), $(i+3), $(i+4); break}}}' | sed 's/?[^ ]*//' | sort | uniq -c | sort -rn | head -15
echo "## [C] Botnetz-UA 'Chrome/120.0.0.0\"' (ohne AppleWebKit) POST je Tag+Status"
catlogs | grep -a -F 'Win64; x64) Chrome/120.0.0.0"' | grep -a '"POST ' | awk '{d=""; for(i=1;i<=NF;i++){ if($i ~ /^\[/) d=substr($i,2,6); if($i=="\"POST"){print d, $(i+3); break}}}' | sort | uniq -c | sort -k2 | head -30
echo "## [D] Alle POST / (Root) je Tag+Status seit 17.10. (Exploit zielt auf /)"
catlogs | grep -a -E '"POST / HTTP' | awk '{d=""; for(i=1;i<=NF;i++){ if($i ~ /^\[/) d=substr($i,2,6); if($i=="\"POST"){print d, $(i+3); break}}}' | sort | uniq -c | sort -k2 | head -40
echo "## [E] POST / mit 200 im Patch-Fenster 17.-22.10.: Top IPs"
catlogs | grep -a -E '\[(1[7-9]|2[0-2])/Oct/2026' | grep -a -E '"POST / HTTP[^"]*" 200 ' | awk '{print ($1=="-")?$2:$1}' | sort | uniq -c | sort -rn | head -10
echo "## [F] Vhost-Verteilung der Botnetz-Treffer (Logpfad)"
for l in $LOGS; do n=$(zcat -f "$l" 2>/dev/null | grep -a -c -E '^(- )?(45\.148\.10\.|45\.138\.12\.|93\.123\.109\.|195\.178\.110\.)'); [ "$n" -gt 20 ] && echo "$n $l"; done | sort -rn | head -8
echo "### ENDE"
