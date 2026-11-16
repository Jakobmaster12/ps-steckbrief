#!/usr/bin/env python3
"""
query.py - schickt jeden Fall in den Eingaben A, B und C an ein Sprachmodell

  A = nur Rohcode
  B = nur Steckbrief
  C = Rohcode und Steckbrief

Spricht eine OpenAI-kompatible Schnittstelle an (/v1/chat/completions). Die
bieten vLLM, Ollama, LM Studio, LiteLLM und die meisten Uni-Server. Es werden
keine Zusatzpakete gebraucht.

Jede Anfrage und jede Antwort wird als eigene JSON-Datei gespeichert. Ein
abgebrochener Lauf wird beim naechsten Start fortgesetzt.

Das Label, der Dateiname und der Hash gehen NIE an das Modell: Die Funktion
baue_material() bekommt nur den Skripttext und den Steckbrief-Text ohne Meta.

Zwei Schritte:
  1) Fallliste bauen (einmal):
     python3 src/query.py faelle --ordner scripts/benign=benign scripts/malicious=malicious --out faelle.csv
  2) Abfragen:
     export LLM_API_KEY=...        # falls der Server einen Schluessel verlangt
     python3 src/query.py lauf --faelle faelle.csv --basis-url http://SERVER:8000/v1 \\
         --modell MODELLNAME --lauf laeufe/pilot --wiederholungen 3
"""

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import steckbrief as S  # noqa: E402

WURZEL = Path(__file__).resolve().parent.parent
PROMPT_DATEI = WURZEL / "prompts" / "analyse_prompt.txt"
KOPF_CODE = "=== ROHCODE DES SKRIPTS ===\n"
KOPF_SB = "=== STECKBRIEF (automatisch berechnete Fakten, kein Urteil) ===\n"
VARIANTEN = ("A", "B", "C")
EINSTUFUNGEN = ("boesartig", "gutartig", "unklar")
ENDUNGEN = (".ps1", ".psm1", ".txt")


# ---------------------------------------------------------------------------
def baue_material(variante: str, rohcode: str, steckbrief_text: str, max_code: int):
    """Baut den Text, den das Modell sieht. Bekommt absichtlich keine Metadaten."""
    code = rohcode[:max_code]
    gekuerzt = len(rohcode) > max_code
    if gekuerzt:
        code += "\n[... Rohcode nach %d Zeichen gekürzt ...]" % max_code
    if variante == "A":
        return KOPF_CODE + code + "\n", gekuerzt
    if variante == "B":
        return KOPF_SB + steckbrief_text, False
    if variante == "C":
        return KOPF_CODE + code + "\n\n" + KOPF_SB + steckbrief_text, gekuerzt
    raise ValueError("unbekannte Variante " + variante)


def lies_antwort(text: str):
    """Holt das JSON-Objekt aus der Modellantwort und prueft die Form.
    Gibt (objekt, fehler) zurueck. Genau eines von beiden ist None."""
    if not isinstance(text, str) or not text.strip():
        return None, "leere Antwort"
    t = re.sub(r"<think>.*?</think>", "", text, flags=re.S)        # Denkbloecke mancher Modelle
    a, e = t.find("{"), t.rfind("}")
    if a < 0 or e <= a:
        return None, "kein JSON-Objekt gefunden"
    try:
        obj = json.loads(t[a:e + 1])
    except json.JSONDecodeError as err:
        return None, "JSON nicht lesbar: %s" % err.msg
    if not isinstance(obj, dict):
        return None, "kein JSON-Objekt"
    ein = str(obj.get("einstufung", "")).strip().lower().replace("ö", "oe")
    if ein not in EINSTUFUNGEN:
        return None, "einstufung fehlt oder ungültig: %r" % obj.get("einstufung")
    befunde = []
    for b in obj.get("befunde") or []:
        if isinstance(b, dict) and str(b.get("aussage", "")).strip():
            befunde.append({"aussage": str(b.get("aussage", "")).strip(),
                            "art": str(b.get("art", "")).strip().lower(),
                            "beleg": str(b.get("beleg", "")).strip()})
    iocs_roh = obj.get("iocs") if isinstance(obj.get("iocs"), dict) else {}
    iocs = {}
    for k in ("urls", "ips", "pfade", "registry"):
        v = iocs_roh.get(k) or []
        iocs[k] = [str(x).strip() for x in v if str(x).strip()] if isinstance(v, list) else []
    try:
        sicherheit = max(0, min(100, int(float(obj.get("sicherheit")))))
    except (TypeError, ValueError):
        sicherheit = None
    return {"einstufung": ein, "sicherheit": sicherheit,
            "begruendung": str(obj.get("begruendung", "")).strip(), "befunde": befunde, "iocs": iocs}, None


def frage_modell(basis_url: str, modell: str, system: str, material: str, args):
    """Eine Anfrage. Gibt (antworttext, rohantwort, fehler) zurueck."""
    body = {
        "model": modell,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": material}],
        "temperature": args.temperatur,
        "max_tokens": args.max_tokens,
    }
    if args.seed is not None:
        body["seed"] = args.seed
    if args.json_modus:
        body["response_format"] = {"type": "json_object"}
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("LLM_API_KEY", "")
    if key:
        headers["Authorization"] = "Bearer " + key
    req = urllib.request.Request(basis_url.rstrip("/") + "/chat/completions",
                                 data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    letzter = ""
    for versuch in range(args.versuche):
        try:
            with urllib.request.urlopen(req, timeout=args.timeout) as r:
                roh = json.loads(r.read().decode("utf-8"))
            return roh["choices"][0]["message"].get("content") or "", roh, None
        except urllib.error.HTTPError as e:
            letzter = "HTTP %d: %s" % (e.code, e.read().decode("utf-8", "replace")[:300])
            if e.code in (400, 401, 403, 404, 422):       # liegt an der Anfrage, Wiederholen hilft nicht
                break
        except Exception as e:                            # noqa: BLE001 - Netz, Timeout, kaputte Antwort
            letzter = repr(e)[:300]
        time.sleep(min(2 ** versuch, 30))
    return None, None, letzter


# ---------------------------------------------------------------------------
def cmd_faelle(args):
    zeilen, gesehen = [], set()
    for eintrag in args.ordner:
        if "=" not in eintrag:
            sys.exit("Format: ORDNER=LABEL, z.B. scripts/benign=benign")
        ordner, label = eintrag.rsplit("=", 1)
        dateien = sorted(p for p in Path(ordner).rglob("*") if p.is_file() and p.suffix.lower() in ENDUNGEN)
        for p in dateien:
            sha = hashlib.sha256(p.read_bytes()).hexdigest()
            if sha in gesehen:                            # identische Datei nur einmal
                continue
            gesehen.add(sha)
            zeilen.append({"id": sha[:12], "pfad": str(p), "label": label, "sha256": sha})
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "pfad", "label", "sha256"])
        w.writeheader()
        w.writerows(zeilen)
    print("%d Fälle -> %s" % (len(zeilen), args.out))


def lies_faelle(pfad):
    with open(pfad, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def cmd_lauf(args):
    system = PROMPT_DATEI.read_text(encoding="utf-8")
    prompt_sha = hashlib.sha256(system.encode("utf-8")).hexdigest()
    faelle = lies_faelle(args.faelle)
    if args.limit:
        faelle = faelle[:args.limit]
    varianten = [v for v in args.varianten.upper() if v in VARIANTEN]
    lauf = Path(args.lauf)
    (lauf / "antworten").mkdir(parents=True, exist_ok=True)
    modell_datei = re.sub(r"[^A-Za-z0-9._-]+", "_", args.modell)
    konfig = {"modell": args.modell, "basis_url": args.basis_url, "temperatur": args.temperatur,
              "seed": args.seed, "max_tokens": args.max_tokens, "max_zeichen_code": args.max_zeichen_code,
              "wiederholungen": args.wiederholungen, "varianten": varianten, "prompt_sha256": prompt_sha,
              "extraktor_version": S.VERSION, "json_modus": args.json_modus}
    (lauf / ("konfig_%s.json" % modell_datei)).write_text(json.dumps(konfig, ensure_ascii=False, indent=2), encoding="utf-8")
    (lauf / "prompt.txt").write_text(system, encoding="utf-8")

    gesamt = len(faelle) * len(varianten) * args.wiederholungen
    fertig = neu = fehler = 0
    for fall in faelle:
        try:
            daten = Path(fall["pfad"]).read_bytes()
        except OSError as e:
            print("  FEHLT: %s (%s)" % (fall["pfad"], e), file=sys.stderr)
            fehler += len(varianten) * args.wiederholungen
            continue
        sb = S.build_steckbrief(Path(fall["pfad"]).name, daten, fall["label"])
        rohcode, sb_text = S.decode_file(daten), S.llm_text(sb)
        for v in varianten:
            material, gekuerzt = baue_material(v, rohcode, sb_text, args.max_zeichen_code)
            for r in range(1, args.wiederholungen + 1):
                ziel = lauf / "antworten" / ("%s__%s__%s__r%d.json" % (fall["id"], modell_datei, v, r))
                fertig += 1
                if ziel.exists():
                    continue
                if args.nur_zeigen:
                    print("würde senden: %s Variante %s Wiederholung %d (%d Zeichen)" % (fall["id"], v, r, len(material)))
                    continue
                t0 = time.time()
                text, roh, err = frage_modell(args.basis_url, args.modell, system, material, args)
                obj, parse_err = (None, None) if err else lies_antwort(text)
                status = "anfrage_fehler" if err else ("ungueltig" if parse_err else "ok")
                if err:
                    fehler += 1
                    print("  FEHLER %s %s r%d: %s" % (fall["id"], v, r, err), file=sys.stderr)
                    continue                             # nichts speichern, damit der naechste Lauf es erneut versucht
                ziel.write_text(json.dumps({
                    "fall": fall["id"], "variante": v, "wiederholung": r, "modell": args.modell,
                    "status": status, "fehler": parse_err, "dauer_s": round(time.time() - t0, 2),
                    "code_gekuerzt": gekuerzt, "material_zeichen": len(material),
                    "material_sha256": hashlib.sha256(material.encode("utf-8")).hexdigest(),
                    "prompt_sha256": prompt_sha, "extraktor_version": S.VERSION,
                    "material": material, "antwort_text": text, "antwort": obj,
                    "usage": (roh or {}).get("usage"), "modell_laut_server": (roh or {}).get("model"),
                }, ensure_ascii=False, indent=2), encoding="utf-8")
                neu += 1
                if neu % 10 == 0 or fertig == gesamt:
                    print("  %d/%d (neu: %d, Fehler: %d)" % (fertig, gesamt, neu, fehler))
    print("Fertig. %d neue Antworten, %d Fehler, Ordner: %s" % (neu, fehler, lauf))
    if fehler:
        print("Fehlgeschlagene Anfragen wurden nicht gespeichert. Derselbe Befehl versucht sie erneut.")


def main():
    ap = argparse.ArgumentParser(description="LLM-Abfragen für die Eingaben A, B und C")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("faelle", help="Fallliste aus Ordnern bauen")
    f.add_argument("--ordner", nargs="+", required=True, help="ORDNER=LABEL, mehrere möglich")
    f.add_argument("--out", default="faelle.csv")
    f.set_defaults(func=cmd_faelle)
    l = sub.add_parser("lauf", help="Abfragen durchführen")
    l.add_argument("--faelle", required=True)
    l.add_argument("--basis-url", required=True, help="z.B. http://server:8000/v1")
    l.add_argument("--modell", required=True)
    l.add_argument("--lauf", required=True, help="Ausgabeordner, z.B. laeufe/pilot")
    l.add_argument("--varianten", default="ABC")
    l.add_argument("--wiederholungen", type=int, default=1)
    l.add_argument("--temperatur", type=float, default=0.0)
    l.add_argument("--seed", type=int, default=None)
    l.add_argument("--max-tokens", type=int, default=1500)
    l.add_argument("--max-zeichen-code", type=int, default=60000, help="Rohcode wird danach gekürzt")
    l.add_argument("--timeout", type=int, default=300)
    l.add_argument("--versuche", type=int, default=4)
    l.add_argument("--limit", type=int, default=0, help="nur die ersten N Fälle")
    l.add_argument("--json-modus", action="store_true", help="response_format=json_object mitsenden")
    l.add_argument("--nur-zeigen", action="store_true", help="nichts senden, nur auflisten")
    l.set_defaults(func=cmd_lauf)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
