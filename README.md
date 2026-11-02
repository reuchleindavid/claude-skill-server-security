# /server-security - Claude-Code-Skill für Server-Sicherheit

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Claude Code Skill](https://img.shields.io/badge/Claude%20Code-Skill-8A63D2)
![nur lesend](https://img.shields.io/badge/Server-nur%20lesend-blue)

Ein [Claude-Code](https://claude.com/claude-code)-Skill für Agenturen und Freelancer, die viele Kundenserver betreuen: Shopware, WordPress, Laravel, Node, verteilt auf Managed Hosting und eigene Root-Server.

Er beantwortet zwei Fragen:

1. **Sind alle Server auf Stand und sauber?**
2. **Hat dieser Code eine echte Schwachstelle?**

Entstanden beim PHP-RCE im Oktober 2026 (CVE-2026-109618/109619), als ich über 20 Server gleichzeitig auf Patchstand und Einbruchsspuren prüfen musste.

## Was er kann

| Modus | Wofür | Ergebnis |
|---|---|---|
| **A - Sweep** | neue PHP-/OpenSSH-/Shopware-Advisory, Tagesbericht | Tabelle je Server: Stand, Ziel-Version, wer patcht, Status |
| **B - Forensik** | CVE mit Exploit im Umlauf, "ist der Server sauber?" | je Server: Webshells, geänderte PHP-Dateien, Cron/Keys/systemd, Prozesse, Access- und Error-Logs ab Stichtag |
| **C - Vollaudit** | einen Server komplett durchleuchten | Coverage-Ledger, `findings.json`, Bericht |
| **D - Code-Audit** | Shopware-Plugin, Laravel-App, Node-Relay | Befunde nach der Methodik des [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill) |

## Prinzipien

- **Nur lesend.** Auf Servern laufen ausschließlich `find`, `grep`, `stat`, `ps`, `ss`, `cat`, `dpkg-query` und Co. Fixes sind ein eigener Auftrag.
- **Kein Befund ohne Beleg.** Ein fehlender Header ist eine Härtungsnotiz, keine Schwachstelle. Ein Befund braucht Angreifer, Eingang, versagende Kontrolle, betroffene Ressource und beobachtetes Ergebnis.
- **Drei Verdicts:** `confirmed` (mit Severity), `needs_validation` (mit dem exakt fehlenden Fakt), `rejected` (damit widerlegte Kandidaten nicht wiederkommen).
- **Fresh Eyes:** Jeder Fund geht vor dem Bericht an einen zweiten Agenten, der ihn widerlegen soll.
- **Bekannte Fehlalarme sind dokumentiert:** Freexian-/TuxCare-Backports mit alter Versionsnummer, CLI- vs. FPM-Version bei Shared Hostern, `mod_php` vs. `php -v`, Hoster-Monitoring-Prozesse, Composer-Läufe.

## Installation

```bash
git clone https://github.com/reuchleindavid/claude-skill-server-security.git
cp -R claude-skill-server-security/server-security ~/.claude/skills/
cd ~/.claude/skills/server-security/tools
cp hosts.example hosts.txt        # eigene Server eintragen
```

`hosts.txt` enthält eine Zeile je Server, genau so, wie sie hinter `ssh` stehen würde:

```
mein-shop
-4 -i ~/.ssh/kunde_a root@203.0.113.10
-i ~/.ssh/managed_key web-user@198.51.100.20
```

Für eigene Root-Server zusätzlich `hosts-root.txt` (Patchcheck gegen das Paket-Repo). Beide Dateien sind per `.gitignore` ausgeschlossen.

Optional eine Inventar-Datei anlegen, z. B. `~/server-inventar.md` mit Server, Hoster, PHP-Stand, wer patcht und einem Log. Der Skill liest sie vor jedem Lauf und schreibt danach eine Log-Zeile.

## Benutzung

In Claude Code einfach fragen:

```
/server-security
Prüf mal lesend alle Server
Ist der Shop-Server nach der neuen PHP-Advisory sauber?
Audit für das Plugin in ~/code/mein-plugin
```

Die Werkzeuge laufen auch ohne Claude:

```bash
zsh tools/sweep.sh                                         # PHP-Stand aller Server, eine Zeile je Host
zsh tools/patchcheck.sh                                    # installiert vs. verfügbar auf Root-Servern
RUN_DATE=2026-11-02 SINCE=2026-10-27 zsh tools/forensik_run.sh   # Forensik parallel, Ausgabe nach ~/forensik/<datum>/
```

## Gut zu wissen

- **Auto-Modus:** Claude Code blockt SSH auf Produktivserver gern als "Production Reads". Der Skill liefert dann den fertigen Befehl als `! ...` zum Selbst-Ausführen.
- **Keys mit Passphrase** vorher per `ssh-add` laden, die Skripte laufen mit `BatchMode`.
- **IOC-Liste:** Die Angreifer-IPs und Muster im Forensik-Skript stammen aus dem PHP-RCE 10/2026. Bei neuen Advisories ergänzen.
- **Subagenten:** Der Skill nutzt `hig-fetch`, `hig-review` und `hig-review-deep` aus dem HiG-Paket. Ohne das Paket nimmt man `general-purpose` bzw. `Explore`.

## Aufbau

```
server-security/
├── SKILL.md                         Modi, Grundregeln, Ablauf
├── references/
│   ├── methodik.md                  Phasen, Coverage-Ledger, Prompt-Skelette, Severity
│   ├── check-klassen.md             Prüfklassen mit lesenden Befehlen und Fehlalarmen
│   ├── befund-format.md             Record-Format und Berichtsaufbau
│   ├── befund-schema.json           JSON-Schema für findings.json
│   └── cloudflare-security-audit/   Original-Skill von Cloudflare (MIT)
├── scripts/validate_findings.py     prüft findings.json gegen das Schema
└── tools/                           Sweep, Patchcheck, Forensik-Runner und Remote-Skripte
```

## Lizenz und Autor

MIT, siehe [LICENSE](LICENSE). Die Dateien unter `references/cloudflare-security-audit/` stammen von Cloudflare und stehen unter deren MIT-Lizenz.

© 2026 **David Reuchlein** - Shopware- und Shopify-Entwicklung aus Würzburg
[david-reuchlein.de](https://david-reuchlein.de) · [github.com/reuchleindavid](https://github.com/reuchleindavid)

Keine Gewähr: Der Skill ersetzt keinen professionellen Penetrationstest. Nur auf Servern einsetzen, für die du berechtigt bist.
