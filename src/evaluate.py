#!/usr/bin/env python3
"""
evaluate.py - wertet einen Lauf von query.py aus

Rechnet automatisch:
  - Einstufung je Modell und Eingabe (A, B, C): Treffer, Fehlalarme, Übersehene,
    "unklar", ungültige Antworten, Precision/Recall/F1 für "boesartig"
  - Stabilität über Wiederholungen
  - paarweiser Vergleich der Eingaben am selben Fall (exakter McNemar-Test)
  - Belegprüfung: Steht das Zitat eines Befunds wörtlich im gezeigten Material?
  - IOC-Prüfung: im Material sichtbar / vom Extraktor bestätigt / unbestätigt,
    und gegen die Referenzannotation, wenn es eine gibt
  - Vergleich ohne LLM: einfache Regel über die Funde des Extraktors

Bereitet vor, was nur ein Mensch bewerten kann:
  - aussagen.csv: jede Aussage jedes Modells in einer Zeile, mit leeren Spalten
    "bewertung" und "referenz_befund". Ausgefüllt wieder einlesen mit --bewertung.

Aufruf:
  python3 src/evaluate.py --faelle faelle.csv --lauf laeufe/pilot
  python3 src/evaluate.py --faelle faelle.csv --lauf laeufe/pilot --bewertung laeufe/pilot/auswertung/aussagen_bewertet.csv
"""

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from math import comb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import steckbrief as S  # noqa: E402

SOLL = {"malicious": "boesartig", "benign": "gutartig"}
BEWERTUNGEN = ("belegt", "richtig_unbelegt", "unbelegt", "falsch")
RE_WS = re.compile(r"\s+")


def norm(s: str) -> str:
    return RE_WS.sub(" ", s).strip()


def beleg_im_material(beleg: str, material_norm: str) -> bool:
    """Wörtlich enthalten (Leerraum egal). Auslassungen mit ... oder […] sind erlaubt,
    wenn alle Teile in dieser Reihenfolge vorkommen."""
    b = norm(beleg).strip("`'\"“”„ ")
    if len(b) < 3:
        return False
    teile = [t.strip() for t in re.split(r"\.\.\.|…|\[\.\.\.\]|\[…\]", b) if len(t.strip()) >= 3]
    if not teile:
        return False
    pos = 0
    for t in teile:
        i = material_norm.find(t, pos)
        if i < 0:
            return False
        pos = i + len(t)
    return True


def ioc_norm(s: str) -> str:
    return s.strip().strip("`'\"").rstrip(".,;:)]}").lower()


def mcnemar_exakt(b: int, c: int) -> float:
    """Zweiseitiger exakter Test. b, c = Fälle, in denen genau eine Eingabe richtig lag."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * p)


def quote(z, n):
    return "" if not n else "%.1f" % (100.0 * z / n)


def baseline_regel(sb: dict) -> str:
    """Vergleich ohne LLM: 'boesartig', wenn ein starkes Token vorkommt oder ein
    dekodierter Blob eine Datei-/Shellcode-Kennung trägt. Sonst 'gutartig'."""
    namen = {t["name"] for t in sb["befunde"]["tokens"] if t["sichtbar_in"] != "kommentar"}
    if namen & set(S.STARKE_TOKENS):
        return "boesartig"
    if any(s["art"] == "binaer" and s["kennung"] for s in sb["schichten"]):
        return "boesartig"
    return "gutartig"


class Zaehler:
    def __init__(self):
        self.c = Counter()

    def einstufung(self, soll, ist):
        self.c["gueltig"] += 1
        self.c["ist_" + ist] += 1
        if soll is None:
            return
        self.c["mit_label"] += 1
        self.c["soll_" + soll] += 1
        if ist == soll:
            self.c["treffer"] += 1
        if ist == "unklar":
            self.c["unklar"] += 1
        if soll == "gutartig" and ist == "boesartig":
            self.c["fehlalarm"] += 1
        if soll == "boesartig" and ist == "gutartig":
            self.c["uebersehen"] += 1
        if soll == "boesartig" and ist == "boesartig":
            self.c["tp"] += 1

    def zeile(self):
        c = self.c
        prec = c["tp"] / c["ist_boesartig"] if c["ist_boesartig"] else None
        rec = c["tp"] / c["soll_boesartig"] if c["soll_boesartig"] else None
        f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
        fmt = lambda x: "" if x is None else "%.1f" % (100 * x)  # noqa: E731
        return {
            "antworten": c["antworten"], "ungueltig_prozent": quote(c["antworten"] - c["gueltig"], c["antworten"]),
            "mit_label": c["mit_label"], "treffer_prozent": quote(c["treffer"], c["mit_label"]),
            "unklar_prozent": quote(c["unklar"], c["mit_label"]),
            "fehlalarm_prozent": quote(c["fehlalarm"], c["soll_gutartig"]),
            "uebersehen_prozent": quote(c["uebersehen"], c["soll_boesartig"]),
            "precision": fmt(prec), "recall": fmt(rec), "f1": fmt(f1),
            "befunde_je_antwort": "" if not c["gueltig"] else "%.2f" % (c["befunde"] / c["gueltig"]),
            "beleg_im_material_prozent": quote(c["beleg_ok"], c["befunde"]),
            "iocs": c["iocs"], "ioc_im_material_prozent": quote(c["ioc_material"], c["iocs"]),
            "ioc_vom_extraktor_bestaetigt_prozent": quote(c["ioc_extraktor"], c["iocs"]),
            "ioc_unbestaetigt_prozent": quote(c["ioc_unbestaetigt"], c["iocs"]),
            "stabil_prozent": quote(c["stabil"], c["stabil_n"]),
        }


def main():
    ap = argparse.ArgumentParser(description="Auswertung eines Laufs")
    ap.add_argument("--faelle", required=True)
    ap.add_argument("--lauf", required=True)
    ap.add_argument("--annotationen", default=str(Path(__file__).resolve().parent.parent / "annotationen"))
    ap.add_argument("--bewertung", help="ausgefüllte aussagen.csv mit den Spalten bewertung und referenz_befund")
    ap.add_argument("--out", help="Ausgabeordner (Standard: <lauf>/auswertung)")
    args = ap.parse_args()

    lauf = Path(args.lauf)
    out = Path(args.out) if args.out else lauf / "auswertung"
    out.mkdir(parents=True, exist_ok=True)
    with open(args.faelle, newline="", encoding="utf-8") as f:
        faelle = {z["id"]: z for z in csv.DictReader(f)}
    antworten = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((lauf / "antworten").glob("*.json"))]
    if not antworten:
        sys.exit("Keine Antworten in %s/antworten" % lauf)

    # Steckbriefe der Fälle (für die Regel ohne LLM und die IOC-Bestätigung)
    sbs, extraktor_iocs = {}, {}
    for fid, fall in faelle.items():
        try:
            sb = S.build_steckbrief(Path(fall["pfad"]).name, Path(fall["pfad"]).read_bytes(), fall["label"])
        except OSError:
            continue
        sbs[fid] = sb
        extraktor_iocs[fid] = {ioc_norm(x["wert"]) for k in ("urls", "ipv4", "pfade", "registry") for x in sb["befunde"][k]}
    annot = {}
    for p in Path(args.annotationen).glob("*.json"):
        try:
            a = json.loads(p.read_text(encoding="utf-8"))
            if a.get("id") in faelle:
                annot[a["id"]] = a
        except (json.JSONDecodeError, OSError):
            print("Annotation nicht lesbar: %s" % p, file=sys.stderr)

    z = defaultdict(Zaehler)                       # (modell, variante)
    je_fall = defaultdict(list)                    # (modell, variante, fall) -> [einstufungen]
    aussagen, ioc_zeilen = [], []
    for a in antworten:
        key = (a["modell"], a["variante"])
        z[key].c["antworten"] += 1
        fall = faelle.get(a["fall"])
        if a["status"] != "ok" or fall is None:
            continue
        soll = SOLL.get(fall["label"])
        obj = a["antwort"]
        z[key].einstufung(soll, obj["einstufung"])
        je_fall[key + (a["fall"],)].append(obj["einstufung"])
        mat = norm(a["material"])
        mat_low = mat.lower()
        for i, b in enumerate(obj["befunde"], 1):
            ok = beleg_im_material(b["beleg"], mat)
            z[key].c["befunde"] += 1
            z[key].c["beleg_ok"] += ok
            aussagen.append({"aussage_id": "%s|%s|%s|r%d|%d" % (a["fall"], a["modell"], a["variante"], a["wiederholung"], i),
                             "fall": a["fall"], "modell": a["modell"], "variante": a["variante"],
                             "wiederholung": a["wiederholung"], "einstufung": obj["einstufung"], "art": b["art"],
                             "aussage": b["aussage"], "beleg": b["beleg"], "beleg_im_material": "ja" if ok else "nein",
                             "bewertung": "", "referenz_befund": "", "kommentar": ""})
        ref = annot.get(a["fall"], {}).get("iocs")
        ref_set = {ioc_norm(x) for k in ("urls", "ips", "pfade", "registry") for x in (ref or {}).get(k, [])}
        genannt = set()
        for typ in ("urls", "ips", "pfade", "registry"):
            for wert in obj["iocs"][typ]:
                w = ioc_norm(wert)
                if not w or w in genannt:
                    continue
                genannt.add(w)
                if w in mat_low:
                    klasse = "im_material"
                    z[key].c["ioc_material"] += 1
                elif w in extraktor_iocs.get(a["fall"], set()):
                    klasse = "vom_extraktor_bestaetigt"
                    z[key].c["ioc_extraktor"] += 1
                else:
                    klasse = "unbestaetigt"
                    z[key].c["ioc_unbestaetigt"] += 1
                z[key].c["iocs"] += 1
                ioc_zeilen.append({"fall": a["fall"], "modell": a["modell"], "variante": a["variante"],
                                   "wiederholung": a["wiederholung"], "typ": typ, "wert": wert, "klasse": klasse,
                                   "in_referenz": "" if ref is None else ("ja" if w in ref_set else "nein")})
        if ref is not None:
            z[key].c["ref_iocs"] += len(ref_set)
            z[key].c["ref_iocs_gefunden"] += len(ref_set & genannt)
            z[key].c["ref_genannt"] += len(genannt)
            z[key].c["ref_genannt_richtig"] += len(ref_set & genannt)

    # Stabilität und Mehrheitsentscheid je Fall
    mehrheit = {}
    for (modell, variante, fid), werte in je_fall.items():
        key = (modell, variante)
        if len(werte) > 1:
            z[key].c["stabil_n"] += 1
            z[key].c["stabil"] += len(set(werte)) == 1
        haeufig = Counter(werte).most_common()
        mehrheit[(modell, variante, fid)] = haeufig[0][0] if len(haeufig) == 1 or haeufig[0][1] > haeufig[1][1] else "unklar"

    # Regel ohne LLM
    basis = Zaehler()
    for fid, sb in sbs.items():
        basis.c["antworten"] += 1
        basis.einstufung(SOLL.get(faelle[fid]["label"]), baseline_regel(sb))

    # Dateien schreiben
    zeilen = []
    for (modell, variante), zz in sorted(z.items()):
        d = {"modell": modell, "eingabe": variante}
        d.update(zz.zeile())
        c = zz.c
        d["ioc_recall_referenz"] = quote(c["ref_iocs_gefunden"], c["ref_iocs"])
        d["ioc_precision_referenz"] = quote(c["ref_genannt_richtig"], c["ref_genannt"])
        zeilen.append(d)
    d = {"modell": "(Regel ohne LLM)", "eingabe": "-"}
    d.update(basis.zeile())
    d["ioc_recall_referenz"] = d["ioc_precision_referenz"] = ""
    zeilen.append(d)
    with open(out / "metriken.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(zeilen[0].keys()))
        w.writeheader()
        w.writerows(zeilen)
    for name, daten in (("aussagen.csv", aussagen), ("iocs.csv", ioc_zeilen)):
        if daten:
            with open(out / name, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(daten[0].keys()))
                w.writeheader()
                w.writerows(daten)

    # Paarvergleich
    paare = []
    for modell in sorted({m for m, _ in z}):
        for x, y in (("A", "B"), ("A", "C"), ("B", "C")):
            b = c = beide = 0
            for fid, fall in faelle.items():
                soll = SOLL.get(fall["label"])
                ex, ey = mehrheit.get((modell, x, fid)), mehrheit.get((modell, y, fid))
                if soll is None or ex is None or ey is None:
                    continue
                beide += 1
                b += ex == soll and ey != soll
                c += ex != soll and ey == soll
            if beide:
                paare.append((modell, x, y, beide, b, c, mcnemar_exakt(b, c)))

    # Handbewertung einlesen
    hand = defaultdict(Counter)
    ref_gefunden = defaultdict(set)
    if args.bewertung:
        with open(args.bewertung, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                bw = r.get("bewertung", "").strip().lower()
                if bw in BEWERTUNGEN:
                    hand[(r["modell"], r["variante"])][bw] += 1
                    if r.get("referenz_befund", "").strip():
                        ref_gefunden[(r["modell"], r["variante"], r["fall"], r["wiederholung"])].add(r["referenz_befund"].strip())

    md = ["# Auswertung: %s" % lauf, ""]
    if any("mock" in a["modell"].lower() for a in antworten):
        md += ["**Achtung: Dieser Lauf enthält Antworten eines Test-Modells (Mock). Die Zahlen prüfen nur die Technik und sagen nichts über echte Modelle.**", ""]
    md += ["%d Antworten, %d Fälle in der Fallliste, %d mit Referenzannotation. Extraktor %s."
           % (len(antworten), len(faelle), len(annot), S.VERSION), ""]
    md += ["## Einstufung", "", "Alle Werte in Prozent. Wiederholungen zählen einzeln. Eine ungültige Antwort ist eine, aus der sich kein JSON in der geforderten Form lesen ließ. Treffer, unklar, Fehlalarm und übersehen beziehen sich auf die gültigen Antworten.", "",
           "| Modell | Eingabe | Antworten | ungültig | Treffer | unklar | Fehlalarm | übersehen | Precision | Recall | F1 | stabil |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for d in zeilen:
        md.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            d["modell"], d["eingabe"], d["antworten"], d["ungueltig_prozent"], d["treffer_prozent"], d["unklar_prozent"],
            d["fehlalarm_prozent"], d["uebersehen_prozent"], d["precision"], d["recall"], d["f1"], d["stabil_prozent"]))
    md += ["", "Fehlalarm = gutartiges Skript als bösartig eingestuft. Übersehen = bösartiges als gutartig. Stabil = alle Wiederholungen eines Falls gleich.", ""]
    if paare:
        md += ["## Vergleich der Eingaben am selben Fall", "",
               "Mehrheitsentscheid über die Wiederholungen, exakter McNemar-Test.", "",
               "| Modell | Vergleich | Fälle | nur erste richtig | nur zweite richtig | p |", "|---|---|---|---|---|---|"]
        for modell, x, y, n, b, c, p in paare:
            md.append("| %s | %s gegen %s | %d | %d | %d | %.3f |" % (modell, x, y, n, b, c, p))
        md.append("")
    md += ["## Belege und IOCs (automatisch geprüft)", "",
           "| Modell | Eingabe | Befunde je Antwort | Zitat steht im Material | IOCs | im Material | vom Extraktor bestätigt | unbestätigt | IOC-Recall (Referenz) | IOC-Precision (Referenz) |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for d in zeilen[:-1]:
        md.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            d["modell"], d["eingabe"], d["befunde_je_antwort"], d["beleg_im_material_prozent"], d["iocs"],
            d["ioc_im_material_prozent"], d["ioc_vom_extraktor_bestaetigt_prozent"], d["ioc_unbestaetigt_prozent"],
            d["ioc_recall_referenz"], d["ioc_precision_referenz"]))
    md += ["", "Ein IOC, der nicht wörtlich im Material steht, kann trotzdem stimmen (das Modell hat selbst dekodiert). "
           "\"Vom Extraktor bestätigt\" heißt: Der Extraktor hat denselben Wert errechnet. \"Unbestätigt\" muss von Hand geprüft werden und ist der Kandidat für Halluzination.", ""]
    if hand:
        md += ["## Handbewertung der Aussagen", "", "| Modell | Eingabe | bewertet | belegt | richtig, aber unbelegt | unbelegt | falsch | Referenzbefunde gefunden |", "|---|---|---|---|---|---|---|---|"]
        for (modell, variante), c in sorted(hand.items()):
            n = sum(c.values())
            gef = ges = 0
            for (m, v, fid, r), menge in ref_gefunden.items():
                if (m, v) == (modell, variante) and fid in annot:
                    gef += len(menge & {b["id"] for b in annot[fid].get("befunde", [])})
            for (m, v, fid), werte in je_fall.items():
                if (m, v) == (modell, variante) and fid in annot:
                    ges += len(annot[fid].get("befunde", [])) * len(werte)
            md.append("| %s | %s | %d | %s | %s | %s | %s | %s |" % (
                modell, variante, n, quote(c["belegt"], n), quote(c["richtig_unbelegt"], n), quote(c["unbelegt"], n),
                quote(c["falsch"], n), ("%d von %d" % (gef, ges)) if ges else ""))
        md.append("")
    else:
        md += ["## Handbewertung der Aussagen", "",
               "Noch nicht eingelesen. `aussagen.csv` öffnen, die Spalten `bewertung` (%s) und `referenz_befund` ausfüllen, "
               "unter anderem Namen speichern und mit `--bewertung` erneut auswerten. Regeln: `docs/bewertungsregeln.md`." % ", ".join(BEWERTUNGEN), ""]
    (out / "zusammenfassung.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))
    print("\nGeschrieben: %s" % ", ".join(str(out / n) for n in ("zusammenfassung.md", "metriken.csv", "aussagen.csv", "iocs.csv")))


if __name__ == "__main__":
    main()
