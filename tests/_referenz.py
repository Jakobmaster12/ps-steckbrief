#!/usr/bin/env python3
"""Hilfsskript für vergleich_browser.js: gibt die Python-Ergebnisse als JSON aus."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import steckbrief as S  # noqa: E402

out = {}
for p in sorted(Path(sys.argv[1]).rglob("*")):
    if p.is_file():
        sb = S.build_steckbrief(p.name, p.read_bytes(), "x")
        out[str(p)] = {"json": S.to_json(sb), "md": S.to_markdown(sb), "txt": S.llm_text(sb)}
json.dump(out, sys.stdout)
