#!/usr/bin/env python3
"""Prueft eine findings.json eines Server-Audits gegen references/befund-schema.json.

Nur Standardbibliothek. Prueft Struktur, Verdict-Branches, Severity-Regel
(overall nie ueber impact), Fingerprint-Eindeutigkeit und Sortierung.
Aufruf: python3 -I validate_findings.py <findings.json>
Exit 0 = ok, 1 = Fehler (Liste auf stdout), 2 = Aufruffehler.
"""
import json
import re
import sys

SEV = ["informational", "low", "medium", "high", "critical"]
LIKELIHOOD = {"low", "medium", "high"}
VERDICTS = {"confirmed", "needs_validation", "rejected"}
OWNERS = {"Betreiber", "Mitbetreuer", "Hoster", "Kunde", "Agentur"}
FP_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,120}$")
CLASS_RE = re.compile(r"^check-klassen\.md#.+")

COMMON = {"fingerprint", "verdict", "title", "description", "host", "check_class", "evidence"}
OPTIONAL_ALL = {"conditions"}
BRANCH = {
    "confirmed": {
        "required": {"principal", "entry", "missing_control", "resource", "observed_result",
                     "remediation", "severity", "confidence"},
        "forbidden": {"claimed_root_cause", "blockers", "validation_plan", "reason"},
    },
    "needs_validation": {
        "required": {"claimed_root_cause", "principal", "entry", "resource", "blockers", "validation_plan"},
        "forbidden": {"severity", "observed_result", "remediation", "reason", "confidence", "missing_control"},
    },
    "rejected": {
        "required": {"claimed_root_cause", "reason"},
        "forbidden": {"severity", "observed_result", "remediation", "blockers", "validation_plan", "confidence"},
    },
}
KNOWN = COMMON | OPTIONAL_ALL | {"principal", "entry", "missing_control", "resource", "observed_result",
                                 "remediation", "severity", "confidence", "claimed_root_cause", "blockers",
                                 "validation_plan", "reason"}


def nonempty_str(v, minlen=1):
    return isinstance(v, str) and len(v.strip()) >= minlen


def check_record(i, r, errors):
    p = f"[{i}]"
    if not isinstance(r, dict):
        errors.append(f"{p} ist kein Objekt")
        return None
    fp = r.get("fingerprint")
    p = f"[{i} {fp}]" if isinstance(fp, str) else p
    for k in COMMON:
        if k not in r:
            errors.append(f"{p} Pflichtfeld fehlt: {k}")
    for k in r:
        if k not in KNOWN:
            errors.append(f"{p} unbekanntes Feld: {k}")
    if not (isinstance(fp, str) and FP_RE.match(fp)):
        errors.append(f"{p} fingerprint ungueltig (erwartet <host>:<klasse>:<kurz>, klein, ohne Leerzeichen)")
    v = r.get("verdict")
    if v not in VERDICTS:
        errors.append(f"{p} verdict muss confirmed|needs_validation|rejected sein")
        return fp
    if not nonempty_str(r.get("title"), 5):
        errors.append(f"{p} title zu kurz")
    if not nonempty_str(r.get("description"), 20):
        errors.append(f"{p} description zu kurz (min 20 Zeichen)")
    if not nonempty_str(r.get("host")):
        errors.append(f"{p} host fehlt")
    cc = r.get("check_class")
    if not (isinstance(cc, str) and CLASS_RE.match(cc)):
        errors.append(f"{p} check_class muss 'check-klassen.md#<Klasse>' sein")
    ev = r.get("evidence")
    if not (isinstance(ev, list) and ev):
        errors.append(f"{p} evidence muss eine nicht leere Liste sein")
    else:
        for j, e in enumerate(ev):
            if not isinstance(e, dict) or set(e) != {"source", "quote"}:
                errors.append(f"{p} evidence[{j}] braucht genau source und quote")
            elif not (nonempty_str(e["source"]) and nonempty_str(e["quote"])):
                errors.append(f"{p} evidence[{j}] source/quote leer")
    b = BRANCH[v]
    for k in b["required"]:
        if k not in r:
            errors.append(f"{p} {v}: Pflichtfeld fehlt: {k}")
    for k in b["forbidden"]:
        if k in r:
            errors.append(f"{p} {v}: Feld nicht erlaubt: {k}")
    if "conditions" in r and not (isinstance(r["conditions"], list) and all(nonempty_str(c) for c in r["conditions"])):
        errors.append(f"{p} conditions muss Liste nicht leerer Strings sein")
    if v == "confirmed":
        sev = r.get("severity")
        if isinstance(sev, dict):
            if set(sev) != {"likelihood", "impact", "overall"}:
                errors.append(f"{p} severity braucht genau likelihood, impact, overall")
            else:
                if sev["likelihood"] not in LIKELIHOOD:
                    errors.append(f"{p} severity.likelihood ungueltig")
                if sev["impact"] not in SEV or sev["overall"] not in SEV:
                    errors.append(f"{p} severity.impact/overall ungueltig")
                elif SEV.index(sev["overall"]) > SEV.index(sev["impact"]):
                    errors.append(f"{p} severity.overall ({sev['overall']}) darf impact ({sev['impact']}) nicht uebersteigen")
        elif "severity" in r:
            errors.append(f"{p} severity muss Objekt sein")
        rem = r.get("remediation")
        if isinstance(rem, dict):
            if not nonempty_str(rem.get("smallest_fix")):
                errors.append(f"{p} remediation.smallest_fix fehlt")
            if rem.get("owner") not in OWNERS:
                errors.append(f"{p} remediation.owner muss einer von {sorted(OWNERS)} sein")
            extra = set(rem) - {"smallest_fix", "owner", "regression_check"}
            if extra:
                errors.append(f"{p} remediation: unbekannte Felder {sorted(extra)}")
        elif "remediation" in r:
            errors.append(f"{p} remediation muss Objekt sein")
        if r.get("confidence") not in {"medium", "high"} and "confidence" in r:
            errors.append(f"{p} confidence muss medium|high sein")
        for k in ("principal", "entry", "missing_control", "resource", "observed_result"):
            if k in r and not nonempty_str(r[k]):
                errors.append(f"{p} {k} leer")
    if v == "needs_validation":
        bl = r.get("blockers")
        if "blockers" in r and not (isinstance(bl, list) and bl and all(nonempty_str(x) for x in bl)):
            errors.append(f"{p} blockers muss nicht leere Liste von Strings sein")
        vp = r.get("validation_plan")
        if "validation_plan" in r:
            if not isinstance(vp, dict) or set(vp) - {"readonly", "operator"}:
                errors.append(f"{p} validation_plan erlaubt nur readonly und operator")
            elif not any(nonempty_str(vp.get(k)) for k in ("readonly", "operator")):
                errors.append(f"{p} validation_plan braucht readonly oder operator")
    if v in ("needs_validation", "rejected") and "claimed_root_cause" in r and not nonempty_str(r["claimed_root_cause"]):
        errors.append(f"{p} claimed_root_cause leer")
    if v == "rejected" and "reason" in r and not nonempty_str(r["reason"], 10):
        errors.append(f"{p} reason zu kurz")
    return fp


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    try:
        with open(sys.argv[1], encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Datei nicht lesbar oder kein JSON: {exc}")
        return 2
    errors = []
    if not isinstance(data, list):
        print("Top-Level muss ein Array von Records sein")
        return 1
    fps = []
    for i, rec in enumerate(data):
        fp = check_record(i, rec, errors)
        if isinstance(fp, str):
            fps.append(fp)
    dup = {f for f in fps if fps.count(f) > 1}
    if dup:
        errors.append(f"doppelte fingerprints: {sorted(dup)}")
    if fps != sorted(fps):
        errors.append("Records sind nicht nach fingerprint sortiert")
    counts = {v: sum(1 for r in data if isinstance(r, dict) and r.get("verdict") == v) for v in sorted(VERDICTS)}
    if errors:
        print(f"{len(errors)} Fehler:")
        for e in errors[:100]:
            print(" -", e)
        return 1
    print(f"ok: {len(data)} Records, {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
