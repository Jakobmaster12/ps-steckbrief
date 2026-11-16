#!/usr/bin/env python3
"""
mock_server.py - Test-Modell mit OpenAI-kompatibler Schnittstelle

Dient NUR dazu, die Pipeline ohne echten Server zu prüfen. Die Antworten
kommen aus einer simplen Stichwortregel und sagen nichts über echte Modelle.
Absichtlich eingebaut: gelegentlich ein Serverfehler, eine Antwort ohne JSON,
ein erfundener IOC und ein Zitat, das nicht im Material steht.

Aufruf:  python3 tests/mock_server.py [PORT]      (Standard 8765)
Dann:    --basis-url http://127.0.0.1:8765/v1 --modell mock-modell
"""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STICHWORTE = ("downloadstring", "invoke-expression", "iex ", "frombase64string", "-enc", "invoke-webrequest")
zaehler = {"n": 0}


def antwort_fuer(material: str) -> str:
    low = material.lower()
    treffer = [w for w in STICHWORTE if w in low]
    zaehler["n"] += 1
    n = zaehler["n"]
    if n % 11 == 0:
        return "Das Skript wirkt verdächtig, aber ich antworte hier absichtlich ohne JSON."
    befunde = []
    for w in treffer[:3]:
        i = low.find(w)
        zeile = material[max(material.rfind("\n", 0, i) + 1, i - 40):i + 60].split("\n")[0].strip()
        befunde.append({"aussage": "Das Skript sieht die Verwendung von %s vor." % w.strip(), "art": "technik", "beleg": zeile})
    urls = re.findall(r"https?://[^\s'\"`)]+", material)[:3]
    if n % 5 == 0:
        befunde.append({"aussage": "Das Skript hat eine Verbindung aufgebaut.", "art": "verhalten", "beleg": "Verbindung erfolgreich hergestellt"})
        urls.append("http://erfunden.example/nicht-im-material")
    obj = {"einstufung": "boesartig" if len(treffer) >= 2 else ("unklar" if treffer else "gutartig"),
           "sicherheit": 55 + 10 * min(len(treffer), 4), "begruendung": "Stichwortregel des Test-Modells.",
           "befunde": befunde, "iocs": {"urls": urls, "ips": [], "pfade": [], "registry": []}}
    text = json.dumps(obj, ensure_ascii=False)
    return "```json\n" + text + "\n```" if n % 3 == 0 else text


class Handler(BaseHTTPRequestHandler):
    fehler_gesendet = set()

    def log_message(self, *a):  # still
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        material = body["messages"][-1]["content"]
        key = hash(material)
        if key % 7 == 0 and key not in Handler.fehler_gesendet:      # einmaliger Serverfehler, testet das Wiederholen
            Handler.fehler_gesendet.add(key)
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"absichtlicher Testfehler")
            return
        out = {"model": "mock-modell", "choices": [{"message": {"role": "assistant", "content": antwort_fuer(material)}}],
               "usage": {"prompt_tokens": len(material) // 4, "completion_tokens": 100}}
        data = json.dumps(out).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def starte(port=8765):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    print("Test-Modell läuft auf http://127.0.0.1:%d/v1  (Strg+C beendet)" % port)
    starte(port).serve_forever()
