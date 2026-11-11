#!/usr/bin/env python3
"""
steckbrief.py  -  Statischer Steckbrief-Generator fuer PowerShell-Skripte

Zweck (Masterarbeit, Incident-Response-Kontext):
  Erzeugt pro Skript einen forensischen Steckbrief in DREI definierten Stufen.
  Jede Stufe entspricht EINER festgelegten statischen Analyse-Technik. Dadurch
  ist der Detailgrad reproduzierbar und nicht vom Ermessen des Analysten
  abhaengig (zentrale unabhaengige Variable der Arbeit).

  Stufe 1 (extract)  : Ausgabe eines String- und Encoding-Extraktors.
  Stufe 2 (features) : Stufe 1 + Ausgabe eines statischen Muster-/IOC-Scanners.
  Stufe 3 (structure): Stufe 2 + leichte Deobfuskation und beobachtete Abfolge.

WICHTIG: Der Steckbrief enthaelt KEIN Urteil (kein "boesartig", kein
Schweregrad, keine Empfehlung). Die Bewertung ist Aufgabe des LLM im Experiment.
Das Skript FUEHRT NICHTS AUS. Es liest Text und wendet Regex/Base64 an.

Aufruf:
  python3 steckbrief.py <datei_oder_ordner> --out <ausgabeordner> [--label <text>]
"""

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Sehr grosse Dateien (stark obfuskierte Blobs) nur bis zu dieser Grenze
# analysieren, damit die Steckbriefe lesbar und die Laufzeit begrenzt bleiben.
MAX_ANALYZE_BYTES = 200_000

# ---------------------------------------------------------------------------
# Regeln fuer Stufe 2. Jede Regel ist eine benannte statische Erkennung.
# Es sind neutrale Beobachtungen ("dieses Token kommt vor"), keine Wertung.
SUSPICIOUS_TOKENS = {
    "invoke_expression":   r"\b(?:IEX|Invoke-Expression)\b",
    "encodedcommand":      r"-[eE]nc(?:odedCommand)?\b",
    "downloadstring":      r"\bDownloadString\b",
    "downloadfile":        r"\bDownloadFile\b",
    "webclient":           r"New-Object\s+Net\.WebClient",
    "invoke_webrequest":   r"\bInvoke-WebRequest\b|\biwr\b|\bwget\b|\bcurl\b",
    "frombase64":          r"\bFromBase64String\b",
    "executionpolicy_bypass": r"-[eE]x(?:ecutionPolicy)?\s+Bypass",
    "window_hidden":       r"-[wW](?:indowStyle)?\s+[Hh]idden",
    "noprofile":           r"-[nN]o[pP](?:rofile)?\b",
    "start_process":       r"\bStart-Process\b",
    "reflection_assembly": r"\[Reflection\.Assembly\]|System\.Reflection",
    "add_type":            r"\bAdd-Type\b",
    "set_mppreference":    r"\bSet-MpPreference\b",   # AMSI/Defender tampering
    "amsi":                r"amsi(?:InitFailed|Context|Utils)?",
    "registry_run":        r"CurrentVersion\\Run|HKCU:|HKLM:",
    "scheduled_task":      r"\bSchedule\.Service\b|\bRegister-ScheduledTask\b",
    "char_array":          r"\[char\](?:\s*\d+|\[int\])",
}

CMDLET_RE = re.compile(r"\b([A-Z][a-z]+)-([A-Z][a-zA-Z]+)\b")
URL_RE    = re.compile(r"https?://[^\s'\"\\)>}]+", re.IGNORECASE)
IPV4_RE   = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
PATH_RE   = re.compile(r"(?:[A-Za-z]:\\[^\s'\"<>|]+|\$env:[A-Za-z]+(?:\\[^\s'\"<>|]+)?|%[A-Za-z]+%[^\s'\"<>|]*)")
B64_RE    = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
STR_RE    = re.compile(r"'([^']{3,})'|\"([^\"]{3,})\"")


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def try_b64_decode(blob: str):
    """Dekodiert einen Base64-Block, wenn das Ergebnis weitgehend Text ist."""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except Exception:
        return None
    # UTF-16LE ist bei -EncodedCommand ueblich
    for enc in ("utf-16-le", "utf-8"):
        try:
            txt = raw.decode(enc)
        except Exception:
            continue
        printable = sum(c.isprintable() or c in "\r\n\t" for c in txt)
        if txt and printable / len(txt) > 0.85:
            return txt.strip()
    return None


def stufe1_extract(text: str) -> dict:
    """Reiner String- und Encoding-Extraktor."""
    strings = []
    for m in STR_RE.finditer(text):
        s = m.group(1) or m.group(2)
        if s:
            strings.append(s)
    # Deduplizieren, Reihenfolge erhalten, begrenzen
    seen, uniq = set(), []
    for s in strings:
        if s not in seen:
            seen.add(s); uniq.append(s)
    decoded = []
    for blob in B64_RE.findall(text):
        d = try_b64_decode(blob)
        if d:
            decoded.append({"laenge": len(blob), "dekodiert": d[:1500]})
    return {
        "strings": uniq[:60],
        "string_anzahl_gesamt": len(strings),
        "base64_bloecke_dekodiert": decoded[:10],
        "base64_bloecke_gesamt": len(B64_RE.findall(text)),
    }


def stufe2_features(text: str) -> dict:
    """Statischer Muster- und IOC-Scanner (zusaetzlich zu Stufe 1)."""
    tokens = {}
    for name, pat in SUSPICIOUS_TOKENS.items():
        hits = re.findall(pat, text)
        if hits:
            tokens[name] = len(hits)
    cmdlets = sorted({f"{v}-{n}" for v, n in CMDLET_RE.findall(text)})
    urls  = sorted(set(URL_RE.findall(text)))
    ips   = sorted(set(IPV4_RE.findall(text)))
    paths = sorted(set(PATH_RE.findall(text)))
    return {
        "beobachtete_cmdlets": cmdlets[:40],
        "auffaellige_tokens": tokens,       # name -> Anzahl Vorkommen
        "iocs": {
            "urls": urls[:30],
            "ipv4": ips[:30],
            "pfade": paths[:30],
        },
    }


def stufe3_structure(text: str, s2: dict) -> dict:
    """Leichte Deobfuskation und beobachtete Operationsabfolge."""
    deob = text
    # Ticks (Backtick-Obfuskation) entfernen
    deob = deob.replace("`", "")
    # Simple String-Konkatenation 'a'+'b' aufloesen
    deob = re.sub(r"'([^']*)'\s*\+\s*'([^']*)'", lambda m: "'" + m.group(1) + m.group(2) + "'", deob)
    # -EncodedCommand Bloecke ersetzen durch dekodierten Inhalt
    decoded_cmds = []
    for blob in B64_RE.findall(text):
        d = try_b64_decode(blob)
        if d:
            decoded_cmds.append(d)

    # Beobachtete Abfolge aus der Reihenfolge der Treffer im Quelltext ableiten.
    order_rules = [
        ("frombase64",       "Base64-Inhalt dekodieren"),
        ("encodedcommand",   "kodierten Befehl ausfuehren"),
        ("downloadstring",   "Inhalt von URL laden"),
        ("downloadfile",     "Datei von URL herunterladen"),
        ("invoke_webrequest","Web-Anfrage senden"),
        ("webclient",        "WebClient erstellen"),
        ("invoke_expression","Zeichenkette als Code ausfuehren"),
        ("start_process",    "Prozess starten"),
        ("registry_run",     "Registry-Autostart beruehren"),
        ("scheduled_task",   "geplante Aufgabe anlegen"),
        ("set_mppreference", "Defender-Einstellung aendern"),
    ]
    positions = []
    for key, beschreibung in order_rules:
        pat = SUSPICIOUS_TOKENS.get(key)
        if not pat:
            continue
        m = re.search(pat, text)
        if m:
            positions.append((m.start(), beschreibung))
    positions.sort()
    abfolge = [b for _, b in positions]

    return {
        "deobfuskiert_auszug": deob[:2000],
        "dekodierte_befehle": [d[:1000] for d in decoded_cmds[:5]],
        "beobachtete_abfolge": abfolge,
    }


def build_steckbrief(path: Path, label: str) -> dict:
    data = path.read_bytes()
    text_full = data.decode("utf-8", errors="replace")
    truncated = len(data) > MAX_ANALYZE_BYTES
    text = text_full[:MAX_ANALYZE_BYTES]

    meta = {
        "quelldatei": path.name,
        "sha256": sha256_of(data),
        "groesse_bytes": len(data),
        "zeilen": text_full.count("\n") + 1,
        "ground_truth_label": label,     # aus Ordner, nur fuer Auswertung
        "analyse_gekuerzt": truncated,
        "hinweis": "Kein Urteil enthalten. Bewertung erfolgt durch das LLM.",
    }
    s1 = stufe1_extract(text)
    s2 = stufe2_features(text)
    s3 = stufe3_structure(text, s2)
    return {
        "meta": meta,
        "stufe1_extract": s1,
        "stufe2_features": {**s1, **s2},
        "stufe3_structure": {**s1, **s2, **s3},
    }


def to_markdown(sb: dict) -> str:
    m = sb["meta"]
    out = []
    out.append(f"# Steckbrief: {m['quelldatei']}")
    out.append("")
    out.append(f"- SHA256: `{m['sha256']}`")
    out.append(f"- Groesse: {m['groesse_bytes']} Bytes, {m['zeilen']} Zeilen")
    out.append(f"- Ground-Truth-Label (aus Ordner): **{m['ground_truth_label']}**")
    if m["analyse_gekuerzt"]:
        out.append(f"- Hinweis: Analyse auf erste {MAX_ANALYZE_BYTES} Bytes begrenzt")
    out.append(f"- {m['hinweis']}")
    out.append("")

    s1 = sb["stufe1_extract"]
    out.append("## Stufe 1 - Reine Extraktion")
    out.append(f"- Strings gesamt: {s1['string_anzahl_gesamt']} (Auszug unten)")
    out.append(f"- Base64-Bloecke gesamt: {s1['base64_bloecke_gesamt']}, davon dekodierbar: {len(s1['base64_bloecke_dekodiert'])}")
    if s1["strings"]:
        out.append("- Strings (Auszug):")
        for s in s1["strings"][:15]:
            out.append(f"  - `{s[:120]}`")
    for d in s1["base64_bloecke_dekodiert"][:3]:
        out.append(f"- Dekodierter Base64-Block (Laenge {d['laenge']}):")
        out.append(f"  ```\n  {d['dekodiert'][:400]}\n  ```")
    out.append("")

    s2 = sb["stufe2_features"]
    out.append("## Stufe 2 - Statische Merkmale (zusaetzlich)")
    if s2["auffaellige_tokens"]:
        out.append("- Auffaellige Tokens (Name: Vorkommen):")
        for k, v in s2["auffaellige_tokens"].items():
            out.append(f"  - {k}: {v}")
    if s2["iocs"]["urls"]:
        out.append("- URLs: " + ", ".join(f"`{u}`" for u in s2["iocs"]["urls"][:8]))
    if s2["iocs"]["ipv4"]:
        out.append("- IPv4: " + ", ".join(f"`{i}`" for i in s2["iocs"]["ipv4"][:8]))
    if s2["iocs"]["pfade"]:
        out.append("- Pfade: " + ", ".join(f"`{p}`" for p in s2["iocs"]["pfade"][:8]))
    if s2["beobachtete_cmdlets"]:
        out.append("- Cmdlets: " + ", ".join(s2["beobachtete_cmdlets"][:20]))
    out.append("")

    s3 = sb["stufe3_structure"]
    out.append("## Stufe 3 - Struktur (zusaetzlich)")
    if s3["beobachtete_abfolge"]:
        out.append("- Beobachtete Abfolge:")
        for i, step in enumerate(s3["beobachtete_abfolge"], 1):
            out.append(f"  {i}. {step}")
    if s3["dekodierte_befehle"]:
        out.append("- Dekodierte Befehle (Auszug):")
        for d in s3["dekodierte_befehle"][:2]:
            out.append(f"  ```\n  {d[:400]}\n  ```")
    out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Statischer Steckbrief-Generator")
    ap.add_argument("eingang", help="Datei oder Ordner mit .ps1-Skripten")
    ap.add_argument("--out", required=True, help="Ausgabeordner")
    ap.add_argument("--label", default="unbekannt", help="Ground-Truth-Label (benign/malicious)")
    ap.add_argument("--limit", type=int, default=0, help="max. Anzahl Dateien (0 = alle)")
    args = ap.parse_args()

    eingang = Path(args.eingang)
    out = Path(args.out)
    (out / "json").mkdir(parents=True, exist_ok=True)
    (out / "md").mkdir(parents=True, exist_ok=True)

    if eingang.is_file():
        dateien = [eingang]
    else:
        dateien = sorted(p for p in eingang.rglob("*.ps1") if p.is_file())
    if args.limit:
        dateien = dateien[:args.limit]

    manifest = []
    for i, p in enumerate(dateien, 1):
        try:
            sb = build_steckbrief(p, args.label)
        except Exception as e:
            print(f"  FEHLER bei {p.name}: {e}", file=sys.stderr)
            continue
        stem = f"{args.label}_{i:04d}_{sb['meta']['sha256'][:10]}"
        (out / "json" / f"{stem}.json").write_text(json.dumps(sb, ensure_ascii=False, indent=2))
        (out / "md" / f"{stem}.md").write_text(to_markdown(sb))
        manifest.append({
            "id": stem,
            "quelldatei": sb["meta"]["quelldatei"],
            "sha256": sb["meta"]["sha256"],
            "label": args.label,
            "groesse_bytes": sb["meta"]["groesse_bytes"],
        })
    (out / f"manifest_{args.label}.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    print(f"{len(manifest)} Steckbriefe erzeugt -> {out}")


if __name__ == "__main__":
    main()
