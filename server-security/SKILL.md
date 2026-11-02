---
name: server-security
description: "Sicherheitsprüfung aller eigenen und betreuten Server (Managed Hosting wie maxcluster, All-Inkl, Strato, Alfahosting sowie eigene Root-Server bei DigitalOcean, Hetzner, netcup) und Sicherheits-Audit eigener Codebasen (Shopware-Plugins, Laravel, Node). Modus A Sweep (PHP-Versionen, Patchstand, Tagesbericht), Modus B Forensik (Webshells, IOCs, Persistenz, Logs nach einem CVE oder Vorfall), Modus C Vollaudit eines Servers mit Coverage-Ledger und unabhängiger Verifikation, Modus D Code-Audit nach der Cloudflare-security-audit-Methodik. Use for 'Server prüfen', 'alle Server checken', 'PHP-Sweep', 'Patchstand', 'Forensik', 'ist der Server sauber', 'Webshell', 'IOC', 'Sicherheits-Audit', 'Security Audit', 'Pentest', 'Plugin auf Sicherheit prüfen', 'Tagesbericht Server', neue PHP-/Shopware-/OpenSSH-Advisories. NOT for SEO-Audits (/seo-audit), Bot-Traffic-Analyse ohne Sicherheitsbezug (/crawler-check), Deployments oder Fixes am Server (nur mit Freigabe des Betreibers, nicht Teil dieses Skills)."
effort: high
---

# /server-security - Serverprüfung und Sicherheits-Audit

© 2026 David Reuchlein - https://david-reuchlein.de - https://github.com/reuchleindavid

Beantwortet zwei Fragen: **Sind die Server auf Stand und sauber?** und **Hat dieser Code eine echte Schwachstelle?** Die Methodik stammt aus dem Cloudflare-Skill `security-audit` (Referenz in `references/cloudflare-security-audit/`), übertragen auf eine Agentur-Serverlandschaft: Coverage-Ledger statt Bauchgefühl, drei Verdicts (`confirmed`, `needs_validation`, `rejected`), unabhängige Verifikation vor jedem Befund, Severity nur für Bestätigtes.

## Grundregeln (gelten in jedem Modus)

1. **Nur lesen.** Auf Servern laufen ausschließlich lesende Befehle (find, grep, stat, ps, ss, cat, dpkg-query, apache2ctl -M, journalctl, last). Kein Schreiben, kein Neustart, kein apt install, kein Löschen. Fixes sind ein eigener Auftrag mit Freigabe des Betreibers. Kundenserver ohne Schreibfreigabe bleiben strikt lesend. Rechte nie per Schreibtest prüfen.
2. **Inventar zuerst.** `~/server-inventar.md` (Pfad anpassen) ist Host-Liste, Zuständigkeit und Log zugleich. Vor jedem Lauf lesen, nach jedem Lauf eine Log-Zeile anhängen (jüngster Eintrag oben).
3. **Classifier-Block einplanen.** Der Auto-Modus blockt SSH-Lesebefehle auf Kundenserver teils als "Production Reads". Dann den fertigen Befehl als Codeblock mit `! ...` liefern, mehrere Abfragen bündeln, sagen, worauf ich in der Ausgabe schaue. Keys mit Passphrase laufen nur, wenn sie vorher im ssh-agent geladen sind (`ssh-add`).
4. **Kein Befund ohne Grenze und Ergebnis.** Ein Befund braucht: wer (niedrigere Vertrauensstufe), welcher Eingang, welche Kontrolle fehlt oder versagt, welche Ressource betroffen ist, welches konkrete Ergebnis beobachtet oder vom Betreiber beobachtbar ist. Fehlende Best Practice, geratenes Hoster-Verhalten oder ein Flag ohne Auswirkung ist kein Befund, höchstens eine Härtungsnotiz.
5. **Verdicts sauber trennen.** `confirmed` nur mit vollständiger Spur und beobachtetem Ergebnis, bekommt Severity. `needs_validation` nennt den exakten fehlenden Fakt (Hoster-Config, Firewall, Panel-Einstellung) und einen sicheren Prüfplan, bekommt keine Severity. `rejected` hält widerlegte Kandidaten fest, damit sie nicht wiederkommen.
6. **Fresh Eyes vor dem Bericht.** Jeder `confirmed`-Kandidat geht an einen Verifizierer, der ihn nicht gefunden hat und ihn widerlegen soll (`hig-review`, bei critical/high `hig-review-deep`). Bericht erst danach, Prosa und JSON dürfen nicht auseinanderlaufen.
7. **Keine Live-Angriffe.** Keine Exploit-Versuche gegen Produktivsysteme, keine Last, keine fremden Konten, keine Payloads in Shops. Wenn der entscheidende Fakt nur per Angriff zu klären wäre: `needs_validation`.
8. **Text:** einfacher Bindestrich, kein Gedankenstrich, deutsch, Du-Form.

## Werkzeuge

| Skript | Zweck | Aufruf |
|---|---|---|
| `~/.claude/skills/server-security/tools/sweep.sh` | PHP-Versionen (CLI, FPM-Binaries, OS) aller Key-Hosts, 1 Zeile je Host | `! zsh ~/.claude/skills/server-security/tools/sweep.sh` |
| `~/.claude/skills/server-security/tools/patchcheck.sh` | eigene Root-Server: PHP-Quelle (Sury/Ubuntu), installiert vs. verfügbar (apt-get update holt nur Listen) | `! zsh ~/.claude/skills/server-security/tools/patchcheck.sh` |
| `~/.claude/skills/server-security/tools/forensik_run.sh` | Forensik auf allen Key-Hosts parallel (6 gleichzeitig), Ausgabe je Host als Textdatei, reicht `SINCE` an das Remote-Skript durch | `! RUN_DATE=<datum> SINCE=<stichtag> zsh ~/.claude/skills/server-security/tools/forensik_run.sh [host-filter]` |
| `~/.claude/skills/server-security/tools/forensik_remote.sh` | das Remote-Skript dazu, 14 Abschnitte [0] bis [13], Stichtag per `SINCE` | `ssh <host> "SINCE=2026-11-01 bash -s" < forensik_remote.sh` |
| `~/.claude/skills/server-security/tools/forensik_round2_remote.sh` | Log-Nachlese: Botnetz-Ranges, Multipart-POST-Flut, Status je Tag | wie oben |
| `scripts/validate_findings.py` (im Skill) | prüft `findings.json` eines Server-Audits gegen `references/befund-schema.json` | `python3 -I ~/.claude/skills/server-security/scripts/validate_findings.py <findings.json>` |
| `references/cloudflare-security-audit/validate-*.cjs` | Cloudflare-Validatoren für Code-Audits (Modus D), Node 22 vorhanden | `node .../validate-findings.cjs <findings.json>` |

Ausgaben: Forensik nach `~/forensik/<datum>/<host>.txt`, Audits nach `~/forensik/audit-<host>-<datum>/` (Ledger, findings.json, BERICHT.md). Ausgabeordner und Stichtag des Forensik-Laufs per Umgebungsvariable: `RUN_DATE=2026-11-05 SINCE=2026-11-01 zsh ~/.claude/skills/server-security/tools/forensik_run.sh`. Ohne Variablen: Ordner mit heutigem Datum, Stichtag vor 7 Tagen.

Host-Listen: `tools/hosts.txt` (Sweep, Forensik) und `tools/hosts-root.txt` (Patchcheck auf eigenen Root-Servern), eine Zeile je Host genau wie hinter `ssh`, Vorlage `tools/hosts.example`.

Subagenten: `hig-fetch`, `hig-review` und `hig-review-deep` stammen aus dem HiG-Paket. Ohne das Paket `general-purpose` bzw. `Explore` nehmen und die Rolle (Beschaffer, Widerleger) im Prompt festlegen.

Referenzen im Skill:
- `references/methodik.md` - die sechs Phasen, Coverage-Ledger für Server, Prompt-Skelette für Hunter und Verifizierer, Severity-Anker, Anti-Patterns.
- `references/check-klassen.md` - Prüfklassen je Host (Runtime-Stand, Webshell/IOC, Persistenz, Netz, Zugänge, Web-Konfiguration, Secrets, Shop-spezifisch) mit den konkreten lesenden Befehlen und der Frage "was wäre hier ein Befund".
- `references/befund-format.md` + `references/befund-schema.json` - Record-Format und Berichtsaufbau.
- `references/cloudflare-security-audit/` - Original-Skill (MIT) für Code-Audits: `SKILL.md`, `ATTACK-CLASSES.md`, Companions (WEB-PROTOCOL-AND-AUTH, CLOUD-AND-DEPLOYMENT, SUPPLY-CHAIN, AI-AND-LLM usw.), `report-schema.json`, Validatoren.

## Modus-Wahl

0. **Learnings laden:** Falls `~/.claude/skills/_shared/learnings/server-security.md` existiert, lesen (ergänzt, überschreibt nicht).
1. **"Alle Server prüfen", neue PHP-/OpenSSH-/Shopware-Advisory, Tagesbericht** -> Modus A.
2. **Vorfall, CVE mit Exploit im Umlauf, "ist der Server sauber", Botnetz-Spuren** -> Modus B (ggf. nach A).
3. **"Audit", "Pentest", "einmal komplett durchleuchten" für einen oder wenige Hosts** -> Modus C (enthält A und B als Phasen).
4. **Codebasis (Plugin, Laravel-App, Middleware) auf Schwachstellen prüfen** -> Modus D.
5. Unklar zwischen Guidance (eine Frage beantworten) und Vollaudit (Dateien schreiben): eine Rückfrage, dann loslegen. Eine Sicherheitsfrage allein löst nie einen Vollaudit aus.

## Modus A - Sweep und Tagesbericht

Ziel: Für jeden Host im Inventar steht Version, Ziel-Version, Patcher und Status, Abweichungen sind benannt.

1. Inventar lesen, Advisory lesen (php.net/archive, GHSA, Hoster-Mail). Betroffene Versionsgrenzen notieren.
2. Sweep laufen lassen (`php_sweep.sh`, bei eigenen Root-Servern zusätzlich `php_patchcheck.sh`). Blockt der Classifier: Befehl als `!` liefern.
3. Ausgabe gegen Inventar abgleichen. Regeln aus den Learnings 21. bis 27.10.2026:
   - Sweep zeigt die CLI-Version. Bei maxcluster und Alfahosting entspricht das FPM, bei All-Inkl nicht (Version je Domain im KAS).
   - Bei Apache zählt die geladene `libphpX.so` (`apache2ctl -M`, `a2query -m`), nicht `php -v` . ini-Drop-ins im richtigen SAPI-Ordner prüfen.
   - Hosts mit Sury-PPA (ondrej/php) bekommen PHP nicht über unattended-upgrades.
   - Patch gilt erst nach Neustart von FPM/Apache: `systemctl show -p ActiveEnterTimestamp` gegen dpkg.log-Zeitpunkt halten.
   - Nur maxcluster schreibt Mails, alle anderen Hoster patchen still: dort selbst nachsehen.
4. Tabelle je Host: Server | Hoster | Stand | Ziel | Wer patcht | Status | Aktion. Nur Aktionen nennen, die Betreiber oder ein benannter Betreuer ausführen kann.
5. Log-Zeile ins Inventar (Datum, Uhrzeit, was geprüft, Abweichungen). Bei Tagesbericht: drei Sätze an den Betreiber, Tabelle nur bei Änderungen.

## Modus B - Forensik nach CVE oder Vorfall

Ziel: Für jeden Host eine Aussage "keine Spuren" oder eine Liste konkreter Spuren mit Pfad, Zeitstempel und Einordnung, plus Verdict.

1. Stichtag festlegen (erster Exploit-Tag minus Puffer) und als `SINCE` setzen. IOCs der Advisory (Dateinamen, Pfade, Session-IDs, IP-Ranges, UA-Strings) ins Remote-Skript ergänzen, falls neu. Änderungen am Skript nur lesend wirkende Befehle.
2. Forensik-Lauf (`forensik_run.sh`, Ausgabeordner anpassen). Für Hosts mit Passwort-Login Befehle einzeln als `!` liefern.
3. Auswertung delegieren: pro Host-Datei ein `hig-fetch`-Auftrag mit dem Abschnittsschlüssel aus `references/check-klassen.md`, Rückgabe als verdichtete Liste (Abschnitt, Treffer, Pfad, mtime, Einordnung ok/verdächtig/unklar). Kein Urteil im Subagenten. Rohdateien bleiben liegen, der Hauptthread liest nur die Rückgabe. Ab drei Host-Dateien ist die Delegation Pflicht.
4. Jeden verdächtigen Treffer als Kandidaten behandeln: Spur (Datei, Prozess, Log-Zeile) -> was sie beweisen würde -> was sie entkräftet (Deploy-Zeitpunkt, Composer-Update, bekannte Hoster-Datei). Verdict nach `references/methodik.md`. Typische Fehlalarme: `sess_*` mit `upload_progress_` ohne PHP-Tag, vendor-Dateien nach Composer-Lauf, Hoster-Monitoring-Prozesse, eigene Deploys am Stichtag.
5. Bericht je Host: Stand (PHP, Patchzeitpunkt, Neustart), Abschnitte mit Treffern, Verdict, nächste Schritte. Gesamtbild in einer Tabelle. Log-Zeile ins Inventar.

## Modus C - Vollaudit eines Servers

Das ist die Cloudflare-Methodik auf einen Host übertragen, Details in `references/methodik.md`. Nur auf explizite Anforderung ("Audit", "komplett", "Bericht"). Profil wählen: `quick` (eine Welle, ein Verifizierer je Kandidat), `standard`, `deep` (hohe Werte, Kundendaten, eigene Root-Server mit Zahlungsdaten).

1. **Recon:** Host-Steckbrief aus Inventar, Notizen und einem lesenden Lauf: OS, Dienste, Webroots, Anwendungen, Benutzer, Netz-Exposition, wer patcht, was dort an Daten liegt. Max. 600 Wörter in `architektur.md`.
2. **Coverage-Ledger:** je Oberfläche x Grenze x Prüfklasse eine Einheit in `coverage-ledger.json` (Format in `references/methodik.md`). Der Ledger ist die Abdeckungsaussage, nicht der Satz "Server geprüft".
3. **Hunting-Wellen:** je Ledger-Einheit ein Auftrag (lesende Befehle aus `check-klassen.md`), Rückgabe strukturiert: covered / candidate / blocked plus `uncovered` für neue Oberflächen. Danach ein Coverage-Kritiker (`hig-review`) gegen den Ledger: was fehlt, was ist nur behauptet.
4. **Kandidaten-Validierung:** jeder Kandidat an einen frischen Verifizierer (`hig-review`), der ihn widerlegen soll. Ergebnis genau ein Record (`confirmed`, `needs_validation`, `rejected`).
5. **Strukturierte Ausgabe:** `findings.json` nach `references/befund-schema.json`, prüfen mit `scripts/validate_findings.py`.
6. **Zweitprüfung und Bericht:** `confirmed` critical/high an `hig-review-deep`. Dann `BERICHT.md` aus den Records ableiten (Aufbau in `references/befund-format.md`). Ein sauberer Lauf darf null Befunde haben, dann steht das so da, ohne erfundene Lows.

Abbruch nur in zwei Zuständen: alle Artefakte geschrieben und validiert, oder `run_status: incomplete` mit Grund im Bericht. Nie mitten in einer Phase aufhören.

## Modus D - Code-Audit (Cloudflare-Original)

Für Shopware-Plugins, Laravel-Apps, Node-Relays (MCP-Server, Webhook-Relays), Middleware. `references/cloudflare-security-audit/SKILL.md` lesen und befolgen, mit diesen Anpassungen:

- Parent = Hauptthread. `research`-Agent = `hig-fetch` oder `Explore`, `general`-Agent = `general-purpose`, Verifizierer = `hig-review`, bei critical/high `hig-review-deep`. Prompt-Skelett: Ziel, Scope, Befehle, Rückgabeformat, Verbote, Blöcke aus den Companions wörtlich in den Prompt kopieren, nicht verlinken.
- Output-Verzeichnis `~/forensik/code-audit-<repo>-<datum>/`, nie im Repo.
- Sandbox-Regel des Originals gilt: Code des Ziels nur ohne Netz, mit leerer Umgebung, nur Scratch beschreibbar. Kann das nicht garantiert werden, wird nicht ausgeführt und der Fakt landet in `needs_validation`.
- Companions nach Boundary wählen, nicht nach Sprache: Shopware-Plugin mit Storefront-Controller -> `WEB-PROTOCOL-AND-AUTH.md` + `ATTACK-CLASSES.md` (Injection, Access control, Business logic); Middleware mit API-Keys -> API-key-Abschnitt; MCP-Server -> `AI-AND-LLM.md` + `PROTOCOLS-RPC-AND-MESSAGING.md`; Deploy-Skripte -> `SUPPLY-CHAIN-AND-RELEASE.md`.
- `findings.json` und `coverage-ledger.json` mit den Cloudflare-Validatoren prüfen (Node 22 unter nvm vorhanden).
- Bericht auf Deutsch, Records bleiben englisch, weil das Schema englische Enums hat.

## Rückgabe an den Betreiber

- Erste Zeile: Ergebnis (sauber / Abweichungen / Befunde mit Severity).
- Dann Tabelle je Host oder je Befund, maximal eine Zeile Erklärung je Eintrag.
- Aktionen mit Zuständigkeit (Betreiber, Hoster, Kunde, Agentur) und Reihenfolge. Keine Aktion ohne Beleg.
- Was nicht geprüft werden konnte, steht als eigener Punkt mit Grund (Key fehlt, Classifier, Passwort-Host).
- Log-Zeile im Inventar ist Teil der Lieferung. Bei Learnings (neuer Fehlalarm, neue IOC-Quelle, Hoster-Eigenheit) `~/.claude/skills/_shared/learnings/server-security.md` ergänzen.

## Anti-Patterns

1. Checklisten-Abweichung als Schwachstelle verkaufen (fehlender Header ohne betroffene Ressource).
2. Hoster-Verhalten raten (maxcluster patcht "sicher bald").
3. Fund aus einer Logzeile ohne Datei- oder Prozessbeleg als bestätigt melden.
4. Severity an `needs_validation` hängen.
5. Bericht vor der Verifikation schreiben.
6. Erledigtes erneut vorschlagen: vorher Inventar-Log und STAND des Projekts lesen.
7. Beim Classifier-Block aufgeben oder den Block umgehen statt den `!`-Befehl zu liefern.
