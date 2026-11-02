# Prüfklassen je Host

Jede Klasse nennt: Angreifer mit niedrigerer Vertrauensstufe, Eingang, erwartete Kontrolle, lesende Befehle, und was ein Befund wäre (gegenüber einer Härtungsnotiz). Die Abschnittsnummern [0] bis [13] verweisen auf `~/.claude/skills/server-security/tools/forensik_remote.sh`. Alle Befehle sind lesend. Auf Shared Hosting (All-Inkl, Strato, Alfahosting) fehlen Root-Rechte, dort gilt: was nicht lesbar ist, wird `blocked` mit Grund, nicht geraten.

Angreifer-Typen: **A1** anonym aus dem Internet, **A2** authentifizierter Shop-/App-Nutzer, **A3** anderer Kunde auf derselben Shared-Kiste, **A4** kompromittierter Webuser (nach erfolgreichem Exploit), **A5** lokaler Unix-User ohne sudo.

## Runtime-Stand

Angreifer A1. Eingang: jeder HTTP-Request. Kontrolle: gepatchte Runtime, Neustart nach Patch.
Befehle: [0] CLI/FPM/mod_php-Versionen, `dpkg-query -W 'php*'`, `apache2ctl -M | grep php`, `zgrep ' upgrade php' /var/log/dpkg.log*`, `systemctl show 'php*-fpm' apache2 nginx -p ActiveEnterTimestamp`, `php -i | grep -E 'auto_prepend|session.upload_progress|disable_functions'`, `[ -f /var/run/reboot-required ]`, `apt list --upgradable 2>/dev/null | wc -l`. Zusätzlich OpenSSH (`sshd -V`), OpenSSL, Kernel (`uname -r` gegen `ls /boot/vmlinuz*`), Webserver-Version.
Befund: Runtime unter der Advisory-Grenze UND erreichbare Oberfläche UND Exploit öffentlich -> `needs_validation` (Patchbeleg vom Hoster fehlt) oder Aktion in Modus A. Patch installiert, Dienst aber seit vorher laufend -> Aktion "Neustart", kein Befund. Nur alte Version ohne Exploit -> Inventar-Abweichung.
Fehlalarme: CLI-Version abweichend von FPM (All-Inkl); Freexian/TuxCare-Backports mit alter Versionsnummer und CVE-Fix (z. B. 7.2.34-66+freexian); Sury-Pakete heißen anders als Ubuntu-Pakete.

## Webshell und IOC

Angreifer A1 bis A4. Eingang: Upload, Exploit, Deploy-Weg. Kontrolle: keine ausführbaren Dateien in Upload-Pfaden, keine fremden PHP-Dateien, keine Sessions mit Code.
Befehle: [2] geänderte PHP/.htaccess/.user.ini seit Stichtag, [3] PHP in media/uploads/files und Doppel-Endungen, Bilddateien mit `<?php`, [4] Signaturen (eval(base64_decode, system($_GET, FilesMan, WSO, c99, preg_replace /e, PWNED::), [5] `sess_*` mit PHP-Tag, [6] /tmp /var/tmp /dev/shm neu oder ausführbar oder ELF, [13] Nicht-PHP-Dateien im Webroot, die ausführbar oder ELF sind.
Befund: Datei mit Shell-Signatur im erreichbaren Webroot, mtime nach Stichtag, nicht durch Deploy erklärbar -> `confirmed` critical (Belege: Pfad, mtime, Owner, erste 3 Zeilen, Access-Log-Treffer auf den Pfad). Datei in `/tmp` mit ELF und Webuser-Owner -> `confirmed` high, wenn Prozess oder Cron darauf zeigt, sonst `needs_validation` (Herkunft).
Fehlalarme: vendor-Dateien nach Composer-Update (Zeitpunkt gegen Deploy-Log halten), `sess_*` mit `upload_progress_` aber ohne PHP-Tag (Technik-Spur, kein Code), Shopware `var/cache` (ausgeschlossen), Theme-Compile-Dateien, Hoster-Monitoring (`/tmp/sn_tr`, systemd-private), eigene Forensik-Dateien.

## Prozesse und Netz

Angreifer A4, A5. Eingang: laufender Prozess. Kontrolle: Webuser startet nur FPM-Kinder, keine Lauscher außer den bekannten Diensten, keine ausgehenden Verbindungen zu fremden Hosts.
Befehle: [7] Kinder von php-fpm/apache/nginx, Prozesse aus /tmp, Miner-Namen (xmrig, kdevtmpfsi, kinsing), Reverse-Shell-Muster (/dev/tcp, mkfifo, nc -e, python -c pty), Prozesse je User; [8] `ss -tulpn` (lauschende Ports ohne Standard), `ss -tnp | grep ESTAB` für Webuser.
Befund: Prozess eines Webusers außerhalb FPM/Apache, Binary aus /tmp oder gelöscht (`/proc/<pid>/exe -> (deleted)`) -> `confirmed` critical. Unbekannter Lauscher auf 0.0.0.0 ohne Dienstdefinition -> `candidate`, nach Zuordnung (`systemctl status <pid>`) confirmed oder rejected. Ausgehende Verbindung eines Webusers zu einer IP ohne bekannten Zweck -> `needs_validation` (Ziel-Zuordnung).
Fehlalarme: Shopware-Message-Consumer (`bin/console messenger:consume`) als Webuser, Node-Prozesse der MCP-Server, Hoster-Agenten (maxcluster: Monitoring), Cron-Kinder zur vollen Minute.

## Persistenz

Angreifer A4, A5. Eingang: Cron, systemd, Shell-RC, Preload, Webserver-Prepend. Kontrolle: nur bekannte Jobs, nur Pakete-Units, kein `ld.so.preload`, keine `auto_prepend_file`.
Befehle: [9] `crontab -l` je User, `/etc/cron*`, `systemctl list-units --type=service --state=running` plus `list-timers`, `cat /etc/ld.so.preload`, `/etc/rc.local`, `.bashrc/.profile/.zshrc` auf curl/wget/base64, `authorized_keys` aller User mit mtime, `/etc/passwd` User mit Shell, `/etc/sudoers*`, `.user.ini`/`.htaccess` mit `auto_prepend_file` oder `php_value`.
Befund: Cron oder Timer, der Code aus /tmp, Webroot oder per curl ausführt -> `confirmed` critical. Neuer SSH-Key in `authorized_keys` ohne Zuordnung zu Betreiber/Mitbetreuer/Hoster -> `candidate`, Zuordnung über Key-Kommentar und Zugangsliste; unerklärt -> `confirmed` high. `auto_prepend_file` auf eine Datei außerhalb des Projekts -> `confirmed` critical.
Fehlalarme: Hoster-Keys (maxcluster, All-Inkl Support), eigene alte Keys mit altem Kommentar, Shopware-Cron (`scheduled-task:run`), Certbot-Timer, eigene Warmup-Skripte.

## Zugänge und Logins

Angreifer A1 (Brute Force), A3. Eingang: sshd, FTP, Panel. Kontrolle: Key-only, kein Root-Login, Fail2ban oder Hoster-Schutz, wenige User.
Befehle: `grep -E '^(PasswordAuthentication|PermitRootLogin|PubkeyAuthentication|AllowUsers)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*` (Root nötig), `sshd -T 2>/dev/null | grep -E 'passwordauthentication|permitrootlogin'`, [10] `last -F -s <Stichtag>`, `journalctl -u ssh --since <Stichtag> | grep -E 'Accepted|Failed'` oder `/var/log/auth.log*`, `systemctl is-active fail2ban`, FTP-Dienste (`ss -tlnp | grep -E ':21 |:990 '`).
Befund: `PasswordAuthentication yes` auf eigener Root-Kiste mit Port 22 offen UND `Accepted password` von fremden IPs -> `confirmed` high (Belegzeilen aus auth.log). Nur `yes` ohne fremde Logins -> `needs_validation`, wenn eine Hoster-Firewall oder IP-Allowlist davor sein könnte, sonst Härtungsnotiz. `Accepted publickey` von unbekannter IP mit bekanntem Key -> Aktion "Betreiber fragen", kein Befund ohne Rückfrage.
Fehlalarme: eigene wechselnde IPs, Mitbetreuer mit eigenem Key, Hoster-Wartungslogins (maxcluster aus 185.88.x.x).

## Logs

Angreifer A1. Eingang: HTTP. Kontrolle: Server antwortet nicht mit 200 auf fremde PHP-Dateien, keine 5xx-Flut aus Botnetz-Ranges, keine Exploit-Muster.
Befehle: [11] Access-Logs seit Stichtag: IOC-Pfade, POST mit 5xx, POST auf .php mit 200 außerhalb bekannter Endpunkte, Requests auf PHP in media/, Multipart-Spuren, UA-Anomalien (`Chrome/120.0.0.0"` ohne AppleWebKit); [12] Fehler-Logs: `Allowed memory size`, segfault, `child exited on signal 11`, AH00052, Fatal; Round-2-Skript für Botnetz-Ranges und Status je Tag.
Befund: POST auf eine nicht zum Projekt gehörende PHP-Datei mit Status 200 -> `candidate`, mit Datei-Beleg aus Webshell-Klasse -> `confirmed` critical, ohne Datei (gelöscht) -> `needs_validation` (Datei-Historie, Backup-Vergleich). Segfault-Serie zur Exploit-Zeit allein -> kein Befund, aber Hinweis auf Versuch; mit Datei-Spur verbinden.
Fehlalarme: Shopware-Endpunkte (`/store-api`, `/api/_action`), bekannte Plugin-Fehler, WordPress-xmlrpc-Scans ohne 200, eigene Warmup-Läufe.

## Web-Konfiguration und exponierte Werkzeuge

Angreifer A1, A3. Eingang: vHost. Kontrolle: Verzeichnislisting aus, Admin-Tools hinter Auth oder IP-Filter, keine Dotfiles ausgeliefert, Hosts getrennt.
Befehle: vHost-Dateien lesen (`/etc/apache2/sites-enabled`, `/etc/nginx/sites-enabled`, Plesk `/var/www/vhosts/system/*/conf`), `.htaccess` im Webroot, `find <webroot> -maxdepth 2 \( -name 'phpmyadmin*' -o -name 'adminer*' -o -name 'phpinfo*' -o -name '*.sql' -o -name '*.sql.gz' -o -name '*.zip' -o -name '*.tar.gz' -o -name '.env' -o -name '.git' \)`, von außen nur HEAD/GET auf eine konkrete URL ohne Payload (`curl -sI https://host/.env`, `curl -sI https://host/adminer.php`), nie Wortlisten.
Befund: `.env`, `.git/config` oder SQL-Dump per HTTP mit 200 abrufbar -> `confirmed` critical/high je Inhalt (Beleg: Statuszeile plus erste Bytes, kein vollständiger Abruf von Secrets). Adminer/phpMyAdmin ohne Auth erreichbar -> `confirmed` high. Verzeichnislisting auf einem Ordner mit Backups -> `confirmed` medium. Fehlende Security-Header -> Härtungsnotiz, kein Befund.
Fehlalarme: Ein Host mit absichtlich installiertem phpMyAdmin (prüfen ob Auth/IP-Filter), 403 statt 404 auf Dotfiles ist ok, Cloudflare vor dem Origin antwortet selbst.

## Secrets und Dateirechte

Angreifer A3, A4, A5. Eingang: Dateisystem. Kontrolle: Secrets 600/640 beim Eigentümer, nicht im Webroot, nicht in Logs, nicht in Shell-History.
Befehle: `stat -c '%a %U %n' <projekt>/.env <projekt>/config/jwt/* <projekt>/.env.local`, `find <webroot> -perm -o+w -type f | head`, `find /home /var/www -maxdepth 3 -name '.env*' -perm -o+r`, `grep -l -E 'APP_SECRET|DATABASE_URL|PASSWORD=' ~/.bash_history ~/.zsh_history 2>/dev/null` (nur Treffer melden, nie Werte), Shopware `config/jwt/private.pem` Rechte, Laravel `storage/logs/*.log` auf `DB_PASSWORD`.
Befund: Secret-Datei weltlesbar auf Shared Hosting mit anderen Kunden -> `confirmed` high. Weltschreibbarer Webroot-Pfad außerhalb media/cache -> `confirmed` medium bis high (abhängig davon, ob PHP dort ausgeführt wird). Secret im Log, Log im Webroot -> `confirmed` high. Secret weltlesbar auf eigener Kiste ohne weitere User -> Härtungsnotiz.
Fehlalarme: maxcluster-Pools laufen je Kunde isoliert (A3 entfällt auf eigener Cluster-Instanz), Shopware `.env` 644 ist Standard, aber Webroot ist `public/`, deshalb nicht erreichbar, erst HTTP-Probe entscheidet.

## Shop- und App-spezifisch

- **Shopware 6**: Admin unter `/admin` erreichbar (Rate-Limit per Config), `APP_ENV=prod`, `APP_DEBUG` nicht 1, `config/packages/*.yaml` auf `storefront.csrf.enabled`, Plugins mit `allow_url_fopen`-Nutzung, `var/log/*` nicht im Webroot, `public/` ist DocumentRoot. Media-Upload-Ordner ohne PHP-Ausführung (`.htaccess` in `public/media`).
- **Shopware 5** (Altinstallationen): `/backend` erreichbar, `config.php` Rechte, `engine/Shopware/Plugins/Community` fremde Plugins, bekannte alte CVEs (SwagImportExport).
- **Laravel**: `APP_DEBUG=false`, `APP_KEY` gesetzt, `storage/` nicht im Webroot, Telescope/Horizon-Routen hinter Auth, `php artisan route:list` nur lesend.
- **WoltLab**: `config.inc.php` Rechte, `acp` erreichbar, Attachments ohne PHP-Ausführung.
- **Kirby/EXYLITE**: `site/config/.license.kart` Rechte, `content/` nicht per HTTP listbar, Panel `/panel` erreichbar (Kirby-Login ist bewusst öffentlich, Härtung über Rate-Limit).
- **Node-Relays/MCP** (DigitalOcean): Port nur über Caddy/nginx mit TLS, kein `0.0.0.0:3000` direkt, Token in `.env` 600, `pm2 list`/`systemctl` zeigt nur bekannte Prozesse.
- **Monitoring (z. B. Observium)**: Web-UI hinter Auth, SNMP-Community nicht `public`, PHP-Cron als eigener User.

Shop-spezifische Treffer werden derselben Verdict-Logik unterworfen: `APP_DEBUG=true` auf Prod mit erreichbarer Fehlerseite, die Stacktrace und Pfade zeigt -> `confirmed` medium (Beleg: Statusseite ohne Payload, eine 404 reicht). `APP_DEBUG=true` ohne erreichbare Fehlerausgabe -> Härtungsnotiz.

## Was nie passiert

Keine Wortlisten, keine Scanner (nikto, nuclei, sqlmap) gegen Produktion, kein Login-Versuch mit geratenen Passwörtern, kein Upload von Testdateien, keine Last. Ein einzelner `curl -sI` auf eine konkret vermutete URL ist die Obergrenze an Außenprobe, und auch der wird im Bericht als Befehl mit Antwort protokolliert.
