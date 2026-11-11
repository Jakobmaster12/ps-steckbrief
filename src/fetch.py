#!/usr/bin/env python3
"""
fetch.py  -  Datensatz-Beschaffung fuer die Masterarbeit

Holt die Skript-Quellen per git clone und sortiert sie in:
    scripts/benign/      gutartige Kontrollgruppe
    scripts/malicious/   boesartige Skripte
    scripts/techniques/  Technik-Demonstrationen

Schreibt sources.json mit Herkunft, Commit-Stand und Lizenz-Status, damit
der Datensatz reproduzierbar und zitierbar ist.

WARNUNG: 'malicious' enthaelt echte boesartige PowerShell-Skripte.
Nur in einer isolierten Umgebung (VM ohne Netz zum Host) ausfuehren.
Dieses Skript fuehrt die Samples NICHT aus, es kopiert nur Text.

Aufruf:
    python3 fetch.py --out ../scripts
    python3 fetch.py --out ../scripts --only benign   # nur eine Gruppe
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

# Quellen. Begruendung je Quelle im README.
SOURCES = {
    "benign": {
        "repo": "https://github.com/fleschutz/PowerShell",
        "subdir": "scripts",          # nur den Skript-Ordner uebernehmen
        "glob": "*.ps1",
        "lizenz": "CC0-1.0 (LICENSE im Repo)",
        "zweck": "Gutartige, legitime Admin-Skripte als Kontrollgruppe.",
    },
    "malicious": {
        "repo": "https://github.com/Fa2y/Malicious-PowerShell-Dataset",
        "subdir": "",                 # ganzes Repo nach .ps1 durchsuchen
        "glob": "*.ps1",
        "lizenz": "keine LICENSE-Datei im Repo (vor Nutzung klaeren)",
        "zweck": "Boesartige PowerShell-Skripte, u.a. aus Triage/Bazaar/Hybrid-Analysis.",
    },
    "techniques": {
        "repo": "https://github.com/calinux-py/PowerShell",
        "subdir": "",
        "glob": "*.ps1",
        "lizenz": "keine LICENSE-Datei im Repo (vor Nutzung klaeren)",
        "zweck": "Demonstrationen einzelner Angriffstechniken, gut lesbar.",
    },
}


def run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def clone_group(name: str, conf: dict, out_root: Path) -> dict:
    ziel = out_root / name
    ziel.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        print(f"[{name}] clone {conf['repo']} ...")
        run(["git", "clone", "--depth", "1", conf["repo"], tmp])
        commit = run(["git", "-C", tmp, "rev-parse", "HEAD"]).stdout.strip()
        basis = Path(tmp) / conf["subdir"] if conf["subdir"] else Path(tmp)
        n = 0
        for src in basis.rglob(conf["glob"]):
            if ".git" in src.parts or not src.is_file():
                continue
            # flacher, kollisionsfreier Zielname
            ziel_name = f"{name}_{n:05d}_{src.name}"
            shutil.copy2(src, ziel / ziel_name)
            n += 1
        print(f"[{name}] {n} Dateien -> {ziel}")
    return {
        "repo": conf["repo"],
        "commit": commit,
        "dateien": n,
        "lizenz": conf["lizenz"],
        "zweck": conf["zweck"],
    }


def main():
    ap = argparse.ArgumentParser(description="Datensatz-Beschaffung")
    ap.add_argument("--out", required=True, help="Zielordner fuer scripts/")
    ap.add_argument("--only", choices=list(SOURCES), help="nur diese Gruppe holen")
    args = ap.parse_args()

    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    gruppen = [args.only] if args.only else list(SOURCES)

    sources_info = {"erstellt_am": str(date.today()), "quellen": {}}
    for g in gruppen:
        try:
            sources_info["quellen"][g] = clone_group(g, SOURCES[g], out_root)
        except subprocess.CalledProcessError as e:
            print(f"[{g}] FEHLER: {e.stderr}", file=sys.stderr)

    (out_root / "sources.json").write_text(json.dumps(sources_info, ensure_ascii=False, indent=2))
    print(f"\nFertig. Herkunft dokumentiert in {out_root/'sources.json'}")
    print("Naechster Schritt: Steckbriefe erzeugen mit src/steckbrief.py")


if __name__ == "__main__":
    main()
