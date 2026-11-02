# Methodik: Cloudflare security-audit auf Server übertragen

Quelle: `cloudflare-security-audit/SKILL.md`, `RECONNAISSANCE.md`, `HUNTING.md`, `VALIDATION-AND-REPORTING.md` (MIT, Stand 31.10.2026). Dort geht es um Quellcode-Repositories. Hier steht, wie dieselben Prinzipien auf einen laufenden Server angewendet werden, auf den wir nur lesend per SSH kommen.

## Übersetzungstabelle

| Cloudflare (Repo) | server-security (Host) |
|---|---|
| Target = Repository-Root | Target = ein Host (SSH-Alias, Inventarzeile) |
| Source ref = Commit | Snapshot = Datum/Uhrzeit des Lesedurchlaufs plus Paketstand (`dpkg -l`-Hash oder Sweep-Zeile) |
| repository-relative path:line | absoluter Pfad plus mtime, oder Befehl plus Ausgabe-Zeile, oder Logdatei plus Zeitstempel |
| Entry surface (Route, CLI, Parser) | Dienst/Port, vHost/Webroot, Cron, SSH-Login, Panel, Deploy-Weg |
| Trust boundary (authz-Funktion) | Unix-User-Trennung, Firewall, Webserver-Config, PHP-Pool, Sudo, Hoster-Panel |
| Attack class | Prüfklasse aus `check-klassen.md` |
| Sandboxed local execution | entfällt. Wir führen keinen Zielcode aus. Nur lesen. Was nur durch Ausführen klärbar wäre, ist `needs_validation` |
| `research`-Agent | `hig-fetch` (Beschaffung) oder `Explore` (Suche in lokalen Kopien) |
| `general`-Agent | `general-purpose` |
| Candidate verifier (fresh) | `hig-review`, bei critical/high `hig-review-deep` |
| Parent | Hauptthread, einziger Schreiber der gemeinsamen Dateien |

## Die sechs Phasen

### Phase 1 Recon

Lesen, nicht raten. Quellen in dieser Reihenfolge: Inventar (`server-inventar.md`), Zugangsliste, Projektnotizen, ein lesender Durchlauf (Abschnitt [0], [1], [8], [9] des Forensik-Skripts oder die Recon-Befehle in `check-klassen.md`).

Ergebnis `architektur.md`, max. 600 Wörter:
1. Was läuft dort (Shop, App, Monitoring, Relay), für wen, welche Daten (Kunden, Zahlungen, Zugangsdaten).
2. Betriebsmodell: Managed (maxcluster, All-Inkl, Alfahosting, Strato) oder eigene Kiste (DigitalOcean, Hetzner, netcup). Wer patcht, wer darf schreiben.
3. Oberflächen: offene Ports, vHosts und Webroots, Cron, SSH-User, Panels (Plesk, KAS, phpMyAdmin, Adminer), Deploy-Wege (rsync, git pull, FTP).
4. Grenzen und die stärkste sichtbare Kontrolle je Grenze (Firewall-Regel, Pool-User, Basic-Auth, Key-only-SSH).
5. Was aus Sicht des Hosts nicht sichtbar ist (Hoster-Firewall, Cloudflare-Regeln, Panel-Settings) und deshalb später `needs_validation` wird.
6. Frühere Läufe: welche Befunde und Ledger-Einheiten gibt es, was hat sich seitdem geändert (Paketstand, Deploys).

### Phase 2 Coverage-Ledger und Hunting

`coverage-ledger.json` ist ein JSON-Array, eine Einheit je Kombination Oberfläche x Grenze x Prüfklasse. Felder (vereinfacht gegenüber dem Original, dieselbe Zustandslogik):

```json
{
  "coverage_id": "host/app-server::surface/sshd:22::boundary/sshd_config::class/zugaenge",
  "host": "app-server",
  "surface": "sshd Port 22",
  "boundary": "sshd_config (PasswordAuthentication, PermitRootLogin), authorized_keys",
  "check_class": "check-klassen.md#Zugaenge und Logins",
  "commands": ["grep -E '^(PasswordAuthentication|PermitRootLogin)' /etc/ssh/sshd_config", "..."],
  "prior_status": "none",
  "wave": 1,
  "status": "planned",
  "agent_id": null,
  "reviewed": [],
  "result_fingerprints": [],
  "unresolved": []
}
```

Zustände wie im Original: `planned` (leer), `in_progress` (Owner, sonst leer), `covered` (Owner, `reviewed` nicht leer, keine Fingerprints), `candidate` (Owner, `reviewed` und `result_fingerprints` nicht leer), `blocked` (Owner, Teilbeleg, `unresolved` nennt den Blocker, typisch: Classifier, kein Root, Key fehlt), `deferred`/`out_of_scope`/`not_applicable` (kein Owner, `unresolved` nennt den Grund). `coverage_id` ist stabil über Läufe hinweg: Host, Oberfläche, Grenze, Klasse, nie Welle, Agent oder Severity.

Hunter-Auftrag (ein Auftrag je Einheit oder je Host-Datei, Skelett: Ziel, Scope, Befehle, Rückgabeformat, Verbote):

```text
Objective: Strukturierte Prüfung der Ledger-Einheiten <IDs> auf Host <host> anhand der
beigefügten Ausgabe <datei> bzw. der genannten lesenden Befehle. Rückgabe genau ein
JSON-Objekt (Format unten), keine Prosa drumherum.

Kontext: <architektur.md wörtlich>. Prüfklasse wörtlich: <Block aus check-klassen.md>.
Grenzen: Nur lesen. Keine Befehle außer den genannten. Keine Fixes, keine Vorschläge
zur Härtung in den Kandidaten (Härtung separat unter "hardening"). Kein Urteil über
Severity. Nicht raten, was der Hoster oder Cloudflare davor tut: fehlt der Fakt,
"blocked" mit genau diesem Fakt.

Vorgehen: Für jede Einheit: 1. Wer ist der Angreifer mit niedrigerer Vertrauensstufe
(anonym im Netz, Webuser, anderer Kunde auf Shared Hosting, lokaler User)? 2. Welcher
Eingang? 3. Welche Kontrolle sollte greifen? 4. Was zeigt die Ausgabe tatsächlich
(Pfad, mtime, Zeile zitieren)? 5. Welche Ressource wäre betroffen? Gibt es alle fünf
Antworten mit Beleg: candidate. Sauber: covered. Unklar wegen fehlendem Zugriff:
blocked. Neue Oberfläche ohne Einheit: uncovered.

Output: {"units":[{"coverage_id":"...","status":"covered|candidate|blocked",
"reviewed":["Befehl oder Pfad"],"evidence":["zitierte Zeile mit Quelle"],
"candidates":[{"fingerprint":"<host>:<klasse>:<kurz>","title":"...",
"principal":"...","entry":"...","missing_control":"...","resource":"...",
"observed":"...","evidence":["..."]}],"blocker":"..."}],
"uncovered":[{"surface":"...","why":"..."}],"hardening":["..."]}
Budget: 1.500 Token.
```

Coverage-Kritiker (`hig-review`) nach jeder Welle: bekommt Ledger und `architektur.md`, prüft ob jede `covered`-Einheit ihre Belege wirklich enthält, ob Oberflächen aus Recon ohne Einheit sind, ob `blocked` echte Blocker sind. Rückgabe: Liste von Einheiten zum Wiedereröffnen mit Grund, neue Einheiten. Bei `standard`/`deep` Wellen bis der Kritiker nichts mehr findet, bei `quick` genau einmal.

### Phase 3 Kandidaten-Validierung

Jeder Kandidat an einen frischen Verifizierer, der ihn nicht gefunden hat. Auftrag:

```text
Objective: Diesen Kandidaten widerlegen. Rückgabe genau ein JSON-Objekt
{"decision":"confirmed|needs_validation|rejected","record":{...}} nach dem beigefügten
Schema (befund-schema.json, Branch je decision wörtlich beigefügt).

Kontext: Kandidat <JSON>. Belege <zitierte Ausgaben>. Architektur <wörtlich>. Nur
lesen, keine neuen Befehle außer den beigefügten Ausgaben, kein Kontakt zum Host.

Vorgehen: 1. Jeden Beleg gegen die Ausgabe prüfen: steht die Zeile so da, gehört der
Pfad zu dieser Grenze? 2. Die stärkste sichtbare Gegenkontrolle rekonstruieren
(Pool-User, Firewall-Zeile, Basic-Auth, Dateirechte). 3. Gibt es eine harmlose
Erklärung (Deploy am Stichtag, Composer-Lauf, Hoster-Tool, bekannte Datei)? Dann
rejected mit Grund. 4. Fehlt ein entscheidender Fakt außerhalb des Hosts (Hoster-
Firewall, Cloudflare-WAF, Panel-Setting)? Dann needs_validation mit genau diesem Fakt
und einem Prüfplan, den der Betreiber ohne Angriff ausführen kann. 5. Nur wenn Spur
und Ergebnis vollständig belegt sind: confirmed mit Severity nach den Ankern.
Fingerprint beibehalten, außer es ist eine andere Ursache.
```

Fehlerhafte oder in Prosa gewickelte Rückgaben werden verworfen und mit einem frischen Verifizierer wiederholt, nicht repariert.

### Phase 4 Strukturierte Ausgabe

`findings.json` nach `befund-schema.json`, sortiert nach Fingerprint, dann `python3 -I scripts/validate_findings.py findings.json`. Jeder Fehler wird behoben, bevor es weitergeht. Validator-OK beweist nur Format.

### Phase 5 Zweitprüfung

Jeder finale `confirmed`- und `needs_validation`-Record an einen weiteren frischen Prüfer (`hig-review`, bei critical/high `hig-review-deep`). Er prüft den Record, nicht den Hunter-Text: Belege real, Grenze real, Severity nicht über dem gezeigten Schaden, Fix greift an der letzten vertrauenswürdigen Stelle. Rückgabe `verified` oder `replace` mit Record. Eine Ersetzung, die den Verdict verstärkt oder Ursache/Ergebnis/Severity wesentlich ändert, geht nochmal an einen neuen Prüfer. Bei `quick` fallen Phase 3 und 5 zusammen (ein Prüfer je Kandidat), aber nie null.

### Phase 6 Bericht

`BERICHT.md` nur aus den finalen Records und dem Ledger (Aufbau in `befund-format.md`). Prosa ändert keinen Verdict, keine Severity, keinen Blocker. Abgelehnte Kandidaten sind keine Befunde, ihre Fingerprints erscheinen nur, wenn sie eine Entscheidung erklären.

## Severity-Anker (nur für confirmed)

- **critical**: unauthentifiziert Code-Ausführung, voller Datenbankzugriff oder Übernahme beliebiger Konten. Beispiel: Webshell im Webroot, erreichbar; Adminer/phpMyAdmin ohne Auth mit gültigen Credentials in Reichweite; `.env` mit DB-Passwort per HTTP abrufbar.
- **high**: eine explizite Kontrolle vollständig ausgehebelt mit echten Folgen: Auth-Bypass, Zugriff auf Daten eines anderen Kunden auf Shared Hosting, authentifizierte Code-Ausführung, unauthentifizierter Stopp eines geteilten Dienstes. Beispiel: Passwort-SSH mit schwachem Passwort aktiv und von außen erreichbar; Cron-Skript als root, das Dateien aus dem Webroot ausführt.
- **medium**: echte Grenzverletzung mit kleinem Radius oder seltenen Voraussetzungen. Beispiel: Backup-Archiv mit Kundendaten im Webroot, aber Verzeichnislisting aus und Name nicht erratbar; Session-Dateien weltlesbar auf Shared Hosting ohne andere Kunden auf der Kiste.
- **low**: Preisgabe nicht geheimer Interna oder viel Aufwand für wenig Gewinn. Beispiel: PHP-Version im Header, phpinfo in einem Verzeichnis mit Basic-Auth.
- **informational**: bestätigt, minimaler Effekt, Baustein in einer größeren Kette.

Diskriminator high/medium: Hebelt das gezeigte Ergebnis eine Kontrolle vollständig aus, mit echten Folgen, oder schwächt es sie nur? Wer den konkreten Schaden nicht in einem Satz nennen kann, liegt niedriger als es sich anfühlt. Veraltete PHP-Version allein ist kein confirmed-Befund mit Severity, sondern eine Inventar-Abweichung mit Aktion (Modus A). Sie wird zum Befund, wenn eine erreichbare Oberfläche und ein konkreter CVE mit Exploit zusammenkommen, dann als `needs_validation` (Patch-Beleg fehlt) oder `confirmed` (Spuren gefunden, Modus B).

## Profile und Budget

- `quick`: eine Hunter-Welle, ein Kritiker, ein Prüfer je Kandidat (Phase 3 und 5 zusammen). Für Re-Runs und kleine Hosts (Node-Relays, Monitoring).
- `standard`: wie beschrieben.
- `deep`: Einheiten zusätzlich je Anwendung und Lebenszyklus (Deploy, Cron, Backup, Restore), Kritiker bis sauber, Phase 3 und 5 getrennt, zweiter Durchgang für `prior_covered_same_source`. Für Shops mit Zahlungs- und Kundendaten und eigene Root-Server.

Budget als maximale Anzahl Subagent-Aufrufe in `run-metadata.json`. Reihenfolge: Recon, Kritiker-Reserve, Prüfer-Reserve (etwa 30 % des Rests), dann Hunter. Reicht das Budget nicht für Recon plus Reserven, startet kein Agent, und Betreiber bekommt die Frage nach engerem Scope oder kleinerem Profil. Ein stilles Dünnen der Beweislage gibt es nicht.

## Anti-Patterns (aus dem Original, ergänzt)

1. Checklisten-Abweichung als Schwachstelle.
2. Härtungstipp ohne erreichbare Grenzverletzung als Befund.
3. Live-Test gegen Produktion, wo ein Lesebefehl reicht.
4. Hoster-, Proxy-, WAF- oder Panel-Verhalten raten.
5. Eigene Rechte (Betreiber ist root) als Grenzverletzung werten.
6. Aus einer Logzeile ein stärkeres Ergebnis ableiten als beobachtet.
7. Prosa-Rückgaben, die sich nicht deduplizieren oder prüfen lassen.
8. Alte bestätigte Befunde als Vorlage für die Jagd verwenden (verzerrt).
9. Severity an `needs_validation`.
10. Bericht vor der Zweitprüfung, oder Prosa und JSON uneins.
11. Neu: Fund melden, der im Inventar-Log schon als erledigt steht.
