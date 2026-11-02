# Befund-Format und Bericht

## Records (`findings.json`)

Array von Records, sortiert nach `fingerprint`, Schema in `befund-schema.json`, Prüfung mit `scripts/validate_findings.py`. Drei Branches mit disjunkten Feldern, damit ein Record nie halb bestätigt aussieht:

| Feld | confirmed | needs_validation | rejected |
|---|---|---|---|
| fingerprint, verdict, title, description, host, check_class, evidence | Pflicht | Pflicht | Pflicht |
| principal, entry, resource | Pflicht | Pflicht | optional |
| missing_control, observed_result | Pflicht | verboten | verboten |
| remediation {smallest_fix, owner, regression_check} | Pflicht | verboten | verboten |
| severity {likelihood, impact, overall} | Pflicht, overall <= impact | verboten | verboten |
| confidence (medium, high) | Pflicht | verboten | verboten |
| claimed_root_cause | verboten | Pflicht | Pflicht |
| blockers [] | verboten | Pflicht, min. 1 | verboten |
| validation_plan {readonly, operator} | verboten | Pflicht, min. ein Feld | verboten |
| reason | verboten | verboten | Pflicht |
| conditions [] | optional | optional | optional |

Regeln:
- `fingerprint` = `<host>:<klasse-kurz>:<ursache-kurz>`, klein, ohne Leerzeichen, stabil über Läufe. Gleicher Fingerprint = gleiche Ursache, auch wenn der Verdict wechselt.
- `evidence[].source` ist ein Befehl, ein absoluter Pfad mit mtime oder eine Logdatei mit Zeitstempel. `quote` ist die wörtliche Zeile, Secrets maskiert (`DB_PASSWORD=***`).
- `principal` beginnt mit dem Angreifer-Typ A1 bis A5 aus `check-klassen.md`.
- `remediation.owner` ist Betreiber, Mitbetreuer, Hoster, Kunde oder Agentur. Keine Aktion ohne Zuständigen.
- `validation_plan.readonly` ist ein weiterer lesender Befehl, `operator` ist ein Blick ins Panel oder eine Rückfrage. Nie ein Angriff, nie Last.
- `rejected` bleibt in der Datei, damit der nächste Lauf den Fehlalarm nicht wiederholt.

## Coverage-Ledger (`coverage-ledger.json`)

Format in `methodik.md`. Der Ledger ist die einzige Abdeckungsaussage. Ein Bericht ohne Ledger darf nicht "geprüft" sagen, nur "angesehen".

## `run-metadata.json`

```json
{"run_id":"audit-app-server-2026-10-31","host":"app-server","snapshot":"2026-10-31 14:20 CET, dpkg-Stand aus [0]","profile":"standard","scope":"ganzer Host","budget":12,"agents_used":0,"prior_runs":[],"run_status":"in_progress","incomplete_reason":null}
```

## `BERICHT.md`

Nur aus den finalen Records, dem Ledger und den Härtungsnotizen der Hunter ableiten. Reihenfolge:

1. **Kopf**: Host, Snapshot, Profil, Scope, Budget (genutzt/geplant), frühere Läufe, Satz "nur lesende Prüfung, keine Ausführung von Zielcode, keine Live-Tests". Bei `quick`, Scope oder `incomplete`: ausdrücklich "Teilprüfung" plus Lücke.
2. **Lage in drei Sätzen**: sauber, Abweichungen oder Befunde, höchste Severity, dringendste Aktion mit Zuständigem.
3. **Tabelle bestätigte Befunde**: Severity | Titel | Grenze | beobachtetes Ergebnis (ein Satz) | Zuständig.
4. **Je bestätigter Befund**: Belege (Pfad, mtime, Logzeile), Angreifer, Eingang, fehlende Kontrolle, Bedingungen, Auswirkung, warum diese Severity, kleinster Fix, Regressions-Check.
5. **Tabelle offen (needs_validation)**: Titel | Spur | exakter Blocker | lesender nächster Schritt | Blick des Betreibers. Keine Severity, kein "wahrscheinlich kritisch".
6. **Härtungsnotizen und was gut ist**: getrennt von Befunden. Fehlende Header, alte aber ungefährliche Pakete, Empfehlungen. Positives benennen (Key-only-SSH, Pools getrennt, Patch am selben Tag).
7. **Abdeckung aus dem Ledger**: Anzahl covered, candidate, blocked, deferred, out_of_scope; welche Oberflächen nicht erreichbar waren und warum (Classifier, kein Root, Key fehlt); Ergebnis des letzten Kritiker-Durchlaufs.
8. **Inventar-Log-Zeile**, die ins `server-inventar.md` übernommen wurde.

Abgelehnte Kandidaten tauchen im Bericht nicht als Befunde auf. Ein Lauf ohne Befunde endet mit "keine bestätigten Befunde" und der Abdeckungsaussage, nicht mit erfundenen Lows.

## Rückgabe im Chat (Kurzform für Modus A und B)

Eine Zeile Ergebnis, dann Tabelle je Host (Server | Stand | Ziel | Wer patcht | Status | Aktion), dann maximal fünf Aufzählungspunkte mit Aktionen in Reihenfolge, dann ein Punkt "nicht geprüft" mit Grund. Fertig. Keine Wiederholung, kein Angebot am Ende.
