#!/bin/bash
# (c) 2026 David Reuchlein - https://david-reuchlein.de - https://github.com/reuchleindavid
# PHP2Shell-Forensik (CVE-2026-109618/109619), NUR LESEND. Stand 27.10.2026.
# Eigene Webroot-Pfade bei ROOTS= ergaenzen. IOC-Liste in [11b] stammt aus dem PHP2Shell-Vorfall 10/2026, bei neuen Advisories austauschen.
# Aufruf: ssh <host> bash -s < forensik_remote.sh   (laeuft als web-user oder root)
# Zeitraum: ab 17.10.2026. Keine Schreibzugriffe: nur find, grep, stat, ps, ss, cat, dpkg-query, apache2ctl -M.
SINCE="${SINCE:-2026-10-17}"   # Stichtag, ueberschreibbar: ssh host "SINCE=2026-11-01 bash -s" < script
TS_SINCE="$SINCE 00:00"
export LC_ALL=C
hr(){ echo; echo "## $*"; }
echo "### $(hostname) | $(date '+%F %T %Z') | user=$(id -un) | $(. /etc/os-release 2>/dev/null; echo ${PRETTY_NAME:-?}) | kernel $(uname -r) | up: $(uptime -p 2>/dev/null)"

hr "[0] PHP-Stand: CLI, FPM-Binaries, mod_php, Pakete"
echo "CLI: $(php -v 2>/dev/null | head -1)"
for b in /usr/sbin/php-fpm* /usr/sbin/php*-fpm /opt/php*/sbin/php-fpm /opt/plesk/php/*/sbin/php-fpm; do [ -x "$b" ] && echo "FPM $b: $($b -v 2>/dev/null | head -1 | cut -d' ' -f2) (mtime $(stat -c %y "$b" | cut -c1-16))"; done
ls /usr/lib/apache2/modules/libphp*.so 2>/dev/null | while read m; do echo "mod_php: $m (mtime $(stat -c %y "$m" | cut -c1-16))"; done
(apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null) | grep -i php | sed 's/^/apache-module: /'
dpkg-query -W -f='${Package} ${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | grep -E '^(php[0-9.]+-(fpm|cli|common)|libapache2-mod-php|php[0-9.]*) ' | head -12
echo "-- php ini auto_prepend/append + session.upload_progress + save_path (CLI-Sicht):"
php -i 2>/dev/null | grep -E '^(auto_prepend_file|auto_append_file|session.upload_progress.enabled|session.save_path|disable_functions) ' | head -6
echo "-- Patch-Zeitpunkt laut dpkg.log (php upgrade seit $SINCE):"
zgrep -h -E ' upgrade (php|libapache2-mod-php)[^ ]* ' /var/log/dpkg.log /var/log/dpkg.log.1 /var/log/dpkg.log.*.gz 2>/dev/null | awk '$1>="'$SINCE'"' | awk '{print $1, $2, $4, "->", $6}' | grep -E '(fpm|cli|libapache2|php-common)' | sort | tail -8
echo "-- FPM/Apache-Dienste gestartet (Neustart nach Patch?):"
systemctl show 'php*-fpm.service' apache2.service nginx.service -p Id -p ActiveEnterTimestamp 2>/dev/null | paste - - | sed 's/Id=//;s/ActiveEnterTimestamp=/ seit /' | grep -v '^ seit' | head -8
echo "-- Hinweise: reboot-required=$([ -f /var/run/reboot-required ] && echo ja || echo nein); unattended-upgrades=$(systemctl is-active unattended-upgrades 2>/dev/null); offene Updates laut apt-Cache: $(apt list --upgradable 2>/dev/null | grep -c upgradable)"

ROOTS=$(ls -d /var/www/share/*/htdocs /var/www/share/*/shopware /var/www/share/*/public /var/www/html /var/www/*/public /opt/*/public /www/htdocs/*/ "$HOME"/httpdocs "$HOME"/*/httpdocs "$HOME"/htdocs_shop "$HOME"/htdocs "$HOME"/web /var/www/clients/*/*/web /var/www/*/web 2>/dev/null | sort -u)
[ -z "$ROOTS" ] && ROOTS="$HOME"
hr "[1] Webroots ($(echo $ROOTS | wc -w)): $(echo $ROOTS | tr '\n' ' ')"
EXCL='-not -path */var/cache/* -not -path */cache/* -not -path */node_modules/* -not -path */var/log/*'

hr "[2] PHP/.htaccess/.user.ini/.phar/.phtml geaendert seit $SINCE (ohne cache/node_modules; vendor extra gezaehlt)"
F2=$(for r in $ROOTS; do
  find "$r" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[0-9]' -o -name '*.inc' -o -name '.htaccess' -o -name '.user.ini' \) -newermt "$TS_SINCE" $EXCL -not -path '*/vendor/*' -printf '%TY-%Tm-%Td %TH:%TM %u %s %p\n' 2>/dev/null
done | sort)
if [ -n "$F2" ]; then echo "Gesamt: $(echo "$F2" | wc -l) Dateien"; echo "-- je Tag:"; echo "$F2" | cut -c1-10 | sort | uniq -c; echo "-- je Ordner (Top 15):"; echo "$F2" | awk '{print $NF}' | awk -F/ '{print "/"$2"/"$3"/"$4"/"$5}' | sort | uniq -c | sort -rn | head -15; echo "-- Liste (max 80):"; echo "$F2" | head -80; else echo "keine"; fi
echo "-- geaenderte PHP in vendor/ seit $SINCE (Anzahl je Root):"
for r in $ROOTS; do n=$(find "$r" -xdev -type f -name '*.php' -path '*/vendor/*' -newermt "$TS_SINCE" 2>/dev/null | wc -l); [ "$n" -gt 0 ] && echo "$n $r"; done

hr "[3] PHP in Upload-/Media-Verzeichnissen (jedes Alter) + Doppel-Endungen (*.php.jpg usw.) + Polyglots"
for r in $ROOTS; do
  find "$r" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[0-9]' \) \
    \( -path '*/media/*' -o -path '*/files/*' -o -path '*/uploads/*' -o -path '*/wp-content/uploads/*' -o -path '*/attachment/*' -o -path '*/documents/*' -o -path '*/public/thumbnail/*' -o -path '*/sitemap/*' -o -path '*/var/tmp/*' \) \
    -printf '%TY-%Tm-%Td %u %s %p\n' 2>/dev/null
  find "$r" -xdev -type f \( -name '*.php.*' -o -name '*.phtml.*' \) -not -name '*.php.bak*' -not -name '*.php.dist' -not -name '*.php.orig' -not -name '*.php.sample' -not -name '*.php.md5' -not -name '*.php.map' -not -path '*/vendor/*' -not -path '*/node_modules/*' -printf 'DOPPELENDUNG %TY-%Tm-%Td %u %s %p\n' 2>/dev/null
done | head -40
echo "-- Bilddateien in media/uploads mit PHP-Tag (<?php) seit $SINCE:"
for r in $ROOTS; do
  find "$r" -xdev -type f \( -path '*/media/*' -o -path '*/uploads/*' -o -path '*/files/*' \) \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.svg' -o -iname '*.ico' -o -iname '*.webp' \) -newermt "$TS_SINCE" -size -2M 2>/dev/null | head -3000 | xargs -r grep -l -a -m1 -E '<\?php|<\?=|\bbase64_decode\(|\beval\(' 2>/dev/null
done | head -10

hr "[4] Webshell-Signaturen in PHP-Dateien geaendert seit $SINCE (ohne vendor/cache) + PWNED-Marker"
for r in $ROOTS; do
  find "$r" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.inc' -o -name '*.php[0-9]' \) -newermt "$TS_SINCE" $EXCL -not -path '*/vendor/*' -size -3M 2>/dev/null \
   | xargs -r grep -l -a -I -E 'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev)|(system|passthru|shell_exec|exec|popen|proc_open|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]+\]\s*\(\s*\$_|preg_replace\s*\([^,]*/e["'"'"']|\bFilesMan\b|\bWSO\b|c99sh|r57shell|b374k|PWNED::|move_uploaded_file\s*\(\s*\$_FILES\[[^]]+\]\[.tmp_name.\]\s*,\s*\$_(GET|POST)|\\x65\\x76\\x61\\x6c|chr\(101\)\.chr\(118\)' 2>/dev/null
done | head -30
echo "-- PWNED::/php2shell-Marker in allen Webroots (alle Dateitypen, max 200k, seit $SINCE):"
for r in $ROOTS; do find "$r" -xdev -type f -newermt "$TS_SINCE" -size -200k -not -path '*/node_modules/*' -not -path '*/var/cache/*' 2>/dev/null | head -20000 | xargs -r grep -l -a -m1 -E 'PWNED::|php2shell|B7kQpoc618|p2s9rdme2st6guc9g0rafic' 2>/dev/null; done | head -10

hr "[5] Session-Dateien mit PHP-Code (Exploit-Technik: Webshell in sess_*)"
SDIRS="/var/lib/php/sessions /var/lib/php/session /var/lib/php*/sessions /tmp /var/tmp $HOME/tmp $HOME/.tmp $HOME/sessions"
for r in $ROOTS; do SDIRS="$SDIRS $r/var/sessions $r/../var/sessions $r/var/cache/*/sessions $r/../sessions $r/session $r/../session"; done
php -i 2>/dev/null | awk -F'=> ' '/^session.save_path/{print $NF}' | grep -v 'no value' | sed 's/^[0-9]*;//' | head -2 | while read p; do SDIRS="$SDIRS $p"; done
for d in $SDIRS; do [ -d "$d" ] || continue; n=$(find "$d" -maxdepth 2 -type f -name 'sess_*' 2>/dev/null | wc -l); [ "$n" -gt 0 ] && echo "Sessiondir $d: $n sess_-Dateien, davon seit $SINCE: $(find "$d" -maxdepth 2 -type f -name 'sess_*' -newermt "$TS_SINCE" 2>/dev/null | wc -l)"; done 2>/dev/null | sort -u
for d in $SDIRS; do [ -d "$d" ] || continue; find "$d" -maxdepth 2 -type f -name 'sess_*' -newermt "$TS_SINCE" -size -512k 2>/dev/null | head -20000 | xargs -r grep -l -a -m1 -E '<\?php|<\?=|system\(|eval\(|PWNED|upload_progress\|' 2>/dev/null; done | sort -u | head -15 | sed 's/^/VERDACHT sess: /'
find / -xdev -name 'sess_xqsuvwz3n97wu8j3emz1axuo5y' 2>/dev/null | sed 's/^/IOC-TREFFER: /'
echo "-- upload_progress-Sessions (Schluessel upload_progress_ in sess_*, seit $SINCE):"
for d in $SDIRS; do [ -d "$d" ] || continue; find "$d" -maxdepth 2 -type f -name 'sess_*' -newermt "$TS_SINCE" -size -512k 2>/dev/null | head -20000 | xargs -r grep -l -a -m1 'upload_progress_' 2>/dev/null; done | sort -u | wc -l

hr "[6] /tmp /var/tmp /dev/shm: neu seit $SINCE oder ausfuehrbar oder ELF; IOC /tmp/nfs"
ls -la /tmp/nfs /var/tmp/nfs /dev/shm/nfs 2>/dev/null | sed 's/^/IOC-TREFFER: /'
find /tmp /var/tmp /dev/shm "$HOME"/tmp -xdev -type f \( -newermt "$TS_SINCE" -o -perm -u+x \) -printf '%TY-%Tm-%Td %TH:%TM %u %m %s %p\n' 2>/dev/null | grep -v -E 'systemd-private|/sess_|/\.X11|\.lock$|phpunit|/sn_tr|composer' | sort | tail -40
echo "-- ELF-Binaries in tmp-Verzeichnissen:"
find /tmp /var/tmp /dev/shm -xdev -type f -size +4k 2>/dev/null | grep -v systemd-private | head -3000 | while read f; do [ "$(head -c4 "$f" 2>/dev/null | tr -d '\0' | tr -cd '[:print:]')" = "ELF" ] && echo "ELF: $(stat -c '%y %U %s' "$f" | cut -c1-16,36-) $f"; done | head -10
echo "-- Versteckte Verzeichnisse/Dateien in tmp:"
find /tmp /var/tmp /dev/shm -xdev -maxdepth 2 -name '.*' -not -name '.X*' -not -name '.font-unix' -not -name '.ICE-unix' -not -name '.XIM-unix' -not -name '.Test-unix' 2>/dev/null | head -10

hr "[7] Prozesse: Kinder von php-fpm/apache/nginx, aus tmp, Miner, Reverse-Shell-Muster"
ps -eo user,pid,ppid,etime,comm,args 2>/dev/null | awk 'NR==1 || /php-fpm|apache2|httpd|nginx|lsphp/{print}' | grep -v -E 'php-fpm|apache2|httpd|nginx|lsphp|awk' | head -10 | sed 's/^/WEB-KIND?: /'
ps -eo user,pid,ppid,etime,args 2>/dev/null | grep -E '/tmp/|/dev/shm|/var/tmp|xmrig|kdevtmpfsi|kinsing|minerd|\bnfs php|base64 -d|sh -c (curl|wget)|/dev/tcp|mkfifo|socat|nc -e|python[23]? -c|perl -e|\bpty\.spawn' | grep -v -E 'grep -E|forensik|bash -s' | head -10
echo "-- Prozesse je User:"; ps -eo user --no-headers | sort | uniq -c | sort -rn | head -8 | tr '\n' ';'; echo
echo "-- Prozesse von www-data/web-user (ohne php-fpm/apache/nginx), Top 12:"; ps -eo user,pid,etime,args 2>/dev/null | awk '$1 ~ /www-data|web-user|apache|nginx|^web[0-9]/' | grep -v -E 'php-fpm: pool|apache2 -k|nginx: worker|grep|bash -s|forensik' | head -12
echo "-- Prozesse mit geloeschtem Binary (exe -> deleted):"; for p in /proc/[0-9]*; do l=$(readlink $p/exe 2>/dev/null); case "$l" in *"(deleted)"*) echo "$(basename $p) $(cat $p/comm 2>/dev/null) $l";; esac; done | grep -v -E 'php-fpm|apache2|nginx|mysqld|redis|node|postgres|java|opensearch|pmm|caddy' | head -10

hr "[8] Netz: lauschende Ports (ohne Standard), ausgehende Verbindungen von Web-Usern"
(ss -ltnup 2>/dev/null || netstat -ltnup 2>/dev/null) | awk 'NR>1{print $1, $5, $7}' | grep -v -E ':(80|443|22|3306|33060|6379|11211|9200|9300|25|587|465|993|143|110|995|8025|53|5432|3000|3001|3002|8080|9000|9001|9002|9003|9004|9005|9006|9007|9008|9009|9010|9011|9012|11300|42000|42001|42002|7777|5355|323|68|546|21|40000) ' | head -20
echo "-- established, Ziel ausserhalb Standard-Ports (ohne 443/80/3306/25/587/993):"
(ss -tnp state established 2>/dev/null) | awk 'NR>1{print $4, $5}' | grep -v -E ':(443|80|3306|33060|25|587|465|993|5432|6379|9200|9300|11211|22)$' | sort | uniq -c | sort -rn | head -15

hr "[9] Persistenz: Crontabs, systemd, ld.so.preload, rc.local, Shell-RCs, authorized_keys, User, sudoers, auto_prepend"
echo "-- crontab $(id -un):"; crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | cut -c1-200
if [ "$(id -u)" = 0 ]; then
  for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u "$u" 2>/dev/null | grep -v '^#' | grep -v '^$'); [ -n "$c" ] && [ "$u" != "$(id -un)" ] && echo "-- crontab $u:" && echo "$c" | cut -c1-200; done
  echo "-- geaendert seit $SINCE in /etc/cron*, /var/spool/cron, systemd, ld.so.preload, rc.local, /etc/passwd|shadow|group|sudoers, sshd_config, php ini-Verzeichnisse, apache/nginx conf:"
  find /etc/cron* /var/spool/cron /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/ld.so.preload /etc/rc.local /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d /etc/ssh /etc/php /etc/apache2 /etc/nginx /etc/profile.d /etc/bash.bashrc /etc/environment /etc/ld.so.conf.d /etc/init.d -newermt "$TS_SINCE" -not -name '*.swp' 2>/dev/null | head -40
  echo "-- /etc/ld.so.preload: $([ -f /etc/ld.so.preload ] && cat /etc/ld.so.preload || echo 'fehlt (gut)')"
  echo "-- Shell-User (passwd): $(grep -E '/bin/(ba)?sh$|/bin/zsh$' /etc/passwd | cut -d: -f1 | tr '\n' ' ')"
  echo "-- UID-0-User: $(awk -F: '$3==0{print $1}' /etc/passwd | tr '\n' ' ')"
  echo "-- sudoers (ohne Kommentare): $(grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$' | grep -v -E '^Defaults|^root|^%admin|^%sudo|^@include' | tr '\n' ';')  sudoers.d: $(ls /etc/sudoers.d 2>/dev/null | tr '\n' ' ')"
  echo "-- sshd effektiv: $(sshd -T 2>/dev/null | grep -E '^(passwordauthentication|permitrootlogin|pubkeyauthentication|port) ' | tr '\n' ' ')"
  echo "-- ufw: $(ufw status 2>/dev/null | head -1)  nftables/iptables INPUT-Policy: $(iptables -S INPUT 2>/dev/null | head -1)"
  echo "-- SUID/SGID-Dateien geaendert seit $SINCE:"; find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -newermt "$TS_SINCE" 2>/dev/null | head -10
  echo "-- Binaries geaendert seit $SINCE in /usr/local/bin /usr/local/sbin /usr/bin /usr/sbin /bin /sbin /lib /usr/lib (ohne dpkg-Zeitfenster-Pruefung, Liste max 25):"
  find /usr/local/bin /usr/local/sbin /usr/bin /usr/sbin /usr/lib/x86_64-linux-gnu -xdev -type f -newermt "$TS_SINCE" -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort | tail -25
  echo "-- dpkg-Aktivitaet seit $SINCE (Tage mit Installs/Upgrades): $(zgrep -h -E ' (install|upgrade) ' /var/log/dpkg.log* 2>/dev/null | awk '$1>="'$SINCE'"{print $1}' | sort | uniq -c | tr '\n' ';')"
  echo "-- Pakete ohne dpkg-Herkunft in /usr/local/bin: $(ls /usr/local/bin 2>/dev/null | tr '\n' ' ' | cut -c1-300)"
fi
echo "-- auto_prepend_file/auto_append_file in php.ini/.user.ini/.htaccess/conf.d (gesetzt?):"
grep -rHs -E '^\s*(php_value|php_admin_value)?\s*auto_(prepend|append)_file\s*[= ]\s*["'"'"']?[^"'"'"' ;]' /etc/php /opt/php*/lib /opt/plesk/php/*/etc 2>/dev/null | head -5
for r in $ROOTS; do grep -rHs -E 'auto_(prepend|append)_file' --include=.htaccess --include=.user.ini --include=php.ini "$r" 2>/dev/null | grep -v -E 'auto_(prepend|append)_file\s*[= ]\s*(none|""|'"''"')?\s*$' | head -5; done
echo "-- Shell-RC-Dateien geaendert seit $SINCE:"
find "$HOME"/.bashrc "$HOME"/.profile "$HOME"/.bash_profile "$HOME"/.zshrc "$HOME"/.bash_logout /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile -newermt "$TS_SINCE" 2>/dev/null
echo "-- authorized_keys (mtime, Anzahl, Kommentare):"
for f in "$HOME/.ssh/authorized_keys" "$HOME/.ssh/authorized_keys2" /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys /var/www/*/.ssh/authorized_keys; do [ -f "$f" ] && echo "$(stat -c '%y' "$f" | cut -c1-16) $(grep -c -E '^(ssh|ecdsa)' "$f") Keys $f :: $(awk '/^(ssh|ecdsa)/{print $NF}' "$f" | tr '\n' ',' | cut -c1-200)"; done
echo "-- .ssh-Verzeichnisse geaendert seit $SINCE:"; find "$HOME"/.ssh /root/.ssh /home/*/.ssh -newermt "$TS_SINCE" 2>/dev/null | head -10
echo "-- Shopware/Laravel .env geaendert seit $SINCE:"; for r in $ROOTS; do find "$r" "$r/.." -maxdepth 1 -name '.env*' -newermt "$TS_SINCE" 2>/dev/null; done | sort -u | head -5

hr "[10] Logins: last, SSH Accepted/Failed seit $SINCE"
last -n 20 2>/dev/null | grep -v -E '^(reboot|wtmp|$)' | head -20
echo "-- Accepted seit $SINCE (Anzahl, User, IP):"
zgrep -h "Accepted" /var/log/auth.log /var/log/auth.log* /var/log/secure* "$HOME"/logs/auth.log* 2>/dev/null | grep -E '(Oct (1[7-9]|2[0-9]|3[01])|2026-10-(1[7-9]|2[0-9]|3[01]))' | grep -oE 'for [a-zA-Z0-9_-]+ from [0-9a-f.:]+' | sort | uniq -c | sort -rn | head -12
[ "$(id -u)" = 0 ] && journalctl -u ssh -u sshd --since "$SINCE" 2>/dev/null | grep -oE 'Accepted [a-z]+ for [a-zA-Z0-9_-]+ from [0-9a-f.:]+' | sort | uniq -c | sort -rn | head -12
echo "-- Failed/Invalid user seit $SINCE: $(zgrep -h -c -E 'Failed password|Invalid user' /var/log/auth.log* 2>/dev/null | paste -sd+ | bc 2>/dev/null) (alle Logdateien zusammen, nicht datumsgefiltert)"

hr "[11] Access-Logs seit $SINCE: IOCs, POST-5xx, POST .php 200, media-PHP, Multipart-Spuren"
LOGS=$(find "$HOME"/logs "$HOME"/logs/apache2 "$HOME"/logs/nginx /var/log/apache2 /var/log/nginx /var/log/httpd /var/www/*/log /var/www/clients/*/*/log /var/www/vhosts/system/*/logs -maxdepth 2 -type f \( -name '*access*' -o -name 'access_log*' -o -name '*.access.log*' \) -newermt "$TS_SINCE" 2>/dev/null | grep -v -E 'ssl_request|other_vhosts' | sort -u)
echo "Logdateien: $(echo $LOGS | wc -w); aelteste Zeile: $(for l in $LOGS; do case "$l" in *.gz) zcat "$l";; *) cat "$l";; esac 2>/dev/null | head -1; done | grep -oE '\[[0-9]+/[A-Za-z]+/[0-9]+' | sort -t/ -k3n -k2M -k1n | head -1)"
catlogs() { for l in $LOGS; do case "$l" in *.gz) zcat "$l";; *) cat "$l";; esac; done 2>/dev/null; }
echo "-- [11a] PHP2Shell-IOCs (UA php2shell*, Boundary B7kQpoc618/p2s9rdme2st6guc9g0rafic, p2s.txt, download.php?file=php://filter, PWNED, xqsuvwz3n97wu8j3emz1axuo5y):"
catlogs | grep -a -i -E 'php2shell|B7kQpoc618|p2s9rdme2st6guc9g0rafic|p2s\.txt|php://filter|PWNED|xqsuvwz3n97wu8j3emz1axuo5y|PHP_SESSION_UPLOAD_PROGRESS|upload_progress' | cut -c1-300 | head -20
echo "-- [11b] Zugriffe bekannter Angreifer-IPs/-Netze (45.198.224.0/24, 85.11.167.243, 92.118.112.100, 89.32.41.16/.50, 221.14.159.134, 102.210.149.166, 206.188.197.105, 122.10.110.72, 122.10.17.49, 58.221.60.160, 104.219.251.31, 41.223.30.7, 157.230.117.70, 91.90.123.25):"
catlogs | grep -a -E '^(45\.198\.224\.[0-9]+|85\.11\.167\.243|92\.118\.112\.100|89\.32\.41\.(16|50)|221\.14\.159\.134|102\.210\.149\.166|206\.188\.197\.105|122\.10\.110\.72|122\.10\.17\.49|58\.221\.60\.160|104\.219\.251\.31|41\.223\.30\.7|157\.230\.117\.70|91\.90\.123\.25) ' | awk '{print $1}' | sort | uniq -c
catlogs | grep -a -E '^(45\.198\.224\.[0-9]+|85\.11\.167\.243|92\.118\.112\.100|89\.32\.41\.(16|50)|221\.14\.159\.134|102\.210\.149\.166|206\.188\.197\.105|122\.10\.110\.72|122\.10\.17\.49|58\.221\.60\.160|104\.219\.251\.31|41\.223\.30\.7|157\.230\.117\.70|91\.90\.123\.25) ' | cut -c1-250 | head -10
echo "-- [11c] POST -> 5xx je Tag/Status:"
catlogs | grep -a -E '"POST [^"]+" 5[0-9]{2} ' | sed -E 's/.*\[([0-9]+\/[A-Za-z]+\/[0-9]+)[^]]*\].*" (5[0-9]{2}) .*/\1 \2/' | sort -t/ -k1n | uniq -c
echo "-- [11d] POST -> 5xx: Top IP + URI:"
catlogs | grep -a -E '"POST [^"]+" 5[0-9]{2} ' | awk '{ip=$1; for(i=1;i<=NF;i++) if($i=="\"POST"){print ip, $(i+1); break}}' | sed 's/?.*//' | sort | uniq -c | sort -rn | head -12
echo "-- [11e] POST auf .php mit 200/302, nach URI (Webshell-Suche), Top 15:"
catlogs | grep -a -E '"POST [^"]*\.php[^"]*" (200|302) ' | awk '{for(i=1;i<=NF;i++) if($i=="\"POST"){print $(i+1); break}}' | sed 's/?.*//' | sort | uniq -c | sort -rn | head -15
echo "-- [11f] GET/POST auf .php in media/files/uploads/thumbnail (jeder Status), Top 10:"
catlogs | grep -a -E '"(GET|POST) /[^"]*(media|files|uploads|thumbnail)/[^"]*\.ph(p|tml)' | awk '{for(i=1;i<=NF;i++) if($i ~ /^"(GET|POST)$/){print $1, $(i+1), $(i+3); break}}' | sed 's/?.*//' | sort | uniq -c | sort -rn | head -10
echo "-- [11g] Requests auf .php-Pfade mit 200, die NICHT index.php/shopware.php/wp-*.php/admin-ajax sind (Top 15, mit IP-Anzahl):"
catlogs | grep -a -E '"(GET|POST) /[^" ]*\.ph(p|tml)[^"]*" 200 ' | grep -a -v -E '/(index|shopware|wp-login|wp-cron|xmlrpc|admin-ajax|wp-comments-post|send|api|cron|install|upgrade|check|run|init|setup)\.php' | awk '{for(i=1;i<=NF;i++) if($i ~ /^"(GET|POST)$/){print $(i+1); break}}' | sed 's/?.*//' | sort | uniq -c | sort -rn | head -15
echo "-- [11h] POST-Requests je Tag mit Status 500/502/503 UND Anfragegroesse (Spalte Bytes) - Multipart-OOM-Verdacht laesst sich hier nur ueber Haeufung sehen; 4xx/5xx-Verteilung POST je Tag:"
catlogs | grep -a -E '"POST ' | sed -E 's/.*\[([0-9]+\/[A-Za-z]+)\/[0-9]+[^]]*\].*" ([0-9]{3}) .*/\1 \2/' | awk '{d[$1" "substr($2,1,1)"xx"]++} END{for(k in d) print k, d[k]}' | sort -t/ -k1n | column -t 2>/dev/null | head -40
echo "-- [11i] Top-10 POST-IPs seit $SINCE:"
catlogs | grep -a -E '"POST ' | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
echo "-- [11j] Erste/letzte Logzeile im Zeitraum:"; catlogs | head -1 | cut -c1-120; catlogs | tail -1 | cut -c1-120

hr "[12] Fehler-Logs seit $SINCE: Allowed memory size, segfault, SIGSEGV, child exited, AH00052, Fatal"
ELOGS=$(find /var/log/php* /var/log/apache2 /var/log/nginx /var/log/httpd "$HOME"/logs /var/www/*/log /var/www/clients/*/*/log /var/www/share/*/logs /var/log -maxdepth 2 -type f \( -name '*error*' -o -name 'php*fpm*.log*' -o -name 'php*.log*' -o -name 'kern.log*' -o -name 'syslog*' -o -name 'messages*' \) -newermt "$TS_SINCE" 2>/dev/null | grep -v -E 'ssl_error|dpkg|lastlog|faillog' | sort -u)
echo "Logdateien: $(echo $ELOGS | wc -w)"
catel() { for l in $ELOGS; do case "$l" in *.gz) zcat "$l";; *) cat "$l";; esac; done 2>/dev/null; }
echo "-- Allowed memory size exhausted, je Tag:"
catel | grep -a 'Allowed memory size' | grep -oE '(\[[0-9]{2}-[A-Za-z]{3}-2026|2026-10-[0-9]{2}|Oct [0-9 ]{2})' | sort | uniq -c | sort -k2 | head -15
echo "-- Allowed memory size: Top-Dateien/URIs:"; catel | grep -a 'Allowed memory size' | grep -oE 'in /[^ ]+ on line [0-9]+|request: "[^"]+"' | sort | uniq -c | sort -rn | head -6
echo "-- segfault/SIGSEGV/SIGBUS/exited on signal/AH00052/core dumped, je Tag:"
catel | grep -a -i -E 'segfault|SIGSEGV|SIGBUS|exited on signal|AH00052|core dumped|double free|corrupted' | grep -v -E 'grep|Chrome|chromium|node ' | grep -oE '(\[[0-9]{2}-[A-Za-z]{3}-2026|2026-10-[0-9]{2}|Oct [0-9 ]{2}|\[[A-Za-z]{3} [A-Za-z]{3} [0-9 ]{2})' | sort | uniq -c | head -15
catel | grep -a -i -E 'segfault|SIGSEGV|SIGBUS|exited on signal|AH00052|core dumped' | grep -v -E 'grep|Chrome|chromium|node ' | cut -c1-220 | tail -8
[ "$(id -u)" = 0 ] && echo "-- journal: php-fpm/apache Crash-Meldungen seit $SINCE: $(journalctl --since "$SINCE" 2>/dev/null | grep -a -i -c -E 'php-fpm.*(segfault|signal|exited)|apache2.*(segfault|AH00052)|kernel:.*segfault.*(php|apache)')"
echo "-- PHP Fatal/Parse errors je Tag (ohne memory):"; catel | grep -a -E 'PHP (Fatal|Parse) error' | grep -v 'Allowed memory' | grep -oE '(\[[0-9]{2}-[A-Za-z]{3}-2026|2026-10-[0-9]{2})' | sort | uniq -c | head -12
echo "-- Hinweis 'upload_progress' / 'multipart' / 'Request Entity Too Large' / 'POST Content-Length' im Errorlog:"; catel | grep -a -i -E 'upload_progress|multipart|POST Content-Length|request body|client intended to send too large' | cut -c1-200 | sort | uniq -c | sort -rn | head -6

hr "[13] Dateien im Webroot neu seit $SINCE, die KEIN PHP sind, aber ausfuehrbar/ELF/Script (Dropper)"
for r in $ROOTS; do find "$r" -xdev -type f -newermt "$TS_SINCE" \( -perm -u+x -o -name '*.sh' -o -name '*.pl' -o -name '*.py' -o -name '*.elf' -o -name '*.so' \) -not -path '*/vendor/*' -not -path '*/node_modules/*' -not -path '*/var/cache/*' -not -path '*/bin/*' -not -path '*/.git/*' -printf '%TY-%Tm-%Td %u %m %s %p\n' 2>/dev/null; done | head -20
echo "### ENDE $(hostname) $(date '+%T')"
