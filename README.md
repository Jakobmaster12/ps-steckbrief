# ps-steckbrief

Werkzeuge zur Masterarbeit "Wann hilft ein Steckbrief? Statische Vorverarbeitung
für die LLM-gestützte Analyse von PowerShell-Skripten" 

## Idee in drei Sätzen

Schadskripte sind oft kodiert oder gepackt. Ein Sprachmodell kann das nicht
ausrechnen, es rät. Der **Extraktor** rechnet es aus und schreibt die Fakten in
einen **Steckbrief**. Die Arbeit misst, ob ein Modell ein Skript damit besser
beurteilt als mit dem Rohcode allein.

Jedes Skript geht in drei Eingaben an dasselbe Modell:

| Eingabe | Das Modell sieht |
|---|---|
| A | nur den Rohcode |
| B | nur den Steckbrief |
| C | Rohcode und Steckbrief |

## Was der Extraktor macht

Er rechnet, er urteilt nicht, und er führt nichts aus.

- trennt Kommentare, Code und String-Literale
- löst Verschleierung auf: Backticks, Konkatenation, `[char]`-Codes,
  Format-Operator `-f`, `.Replace()` und `-replace`, `-join`, umgedrehte Strings
- packt Schichten aus: Base64, Hex, Byte-Listen, gzip, zlib, Deflate, XOR mit
  einem im Skript sichtbaren Schlüssel, auch ineinander verschachtelt
- listet URLs, IPv4, Pfade, Registry-Schlüssel, Cmdlets und auffällige Tokens
- hält bei jedem Fund fest, **ab wann er sichtbar ist**: im Original, nur in
  einem Kommentar, erst nach Deobfuskation oder erst in einer Schicht
- zeigt auffällige Zeilen mit ihren Parametern, misst Entropie und erkennt
  Kennungen in Blobs (zum Beispiel eine PE-Datei)

Grenzen: keine Variablenverfolgung, keine Verschlüsselung mit unbekanntem
Schlüssel, keine Ausführung. Was er nicht auflösen kann, meldet er als Blob
mit Länge und Entropie.

## Aufbau

```
src/steckbrief.py     Extraktor (maßgeblich für den Versuch)
src/fetch.py          holt die Skripte und dokumentiert die Herkunft
src/query.py          schickt die Fälle in den Eingaben A, B, C an ein Modell
src/evaluate.py       wertet einen Lauf aus
tool/steckbrief-werkbank.html   Oberfläche für den Browser, läuft offline
prompts/analyse_prompt.txt      die Aufgabe an das Modell
annotationen/         Vorlage und Beispiel für Referenzannotationen
docs/bewertungsregeln.md        Regeln für die Handbewertung (Entwurf)
tests/                Tests und Test-Modell
sources.json          Herkunft und Commit-Stand der Datenquellen
```

Rohskripte, Steckbriefe, Falllisten und Läufe liegen nicht im Repository. Sie
entstehen lokal mit den Befehlen unten.

## Ablauf

Nur in einer isolierten VM arbeiten. Python 3.10 oder neuer, keine Zusatzpakete.

```bash
# 1. Skripte holen
python3 src/fetch.py --out ./scripts
cat scripts/sources.json

# 2. Fallliste bauen (Label kommt aus dem Ordner)
python3 src/query.py faelle --ordner scripts/benign=benign scripts/malicious=malicious --out faelle.csv
head -5 faelle.csv

# 3. Optional: Steckbriefe als Dateien ansehen
python3 src/steckbrief.py scripts/malicious --out steckbriefe/malicious --label malicious
ls steckbriefe/malicious/llm | head

# 4. Abfragen (OpenAI-kompatible Schnittstelle)
export LLM_API_KEY=...          # nur wenn der Server einen Schlüssel verlangt
python3 src/query.py lauf --faelle faelle.csv --basis-url http://SERVER:8000/v1 \
    --modell MODELLNAME --lauf laeufe/pilot --wiederholungen 3 --limit 12

# 5. Auswerten
python3 src/evaluate.py --faelle faelle.csv --lauf laeufe/pilot
cat laeufe/pilot/auswertung/zusammenfassung.md
```

Ein abgebrochener Lauf wird mit demselben Befehl fortgesetzt. Mehrere Modelle
schreiben in denselben Lauf-Ordner, die Auswertung trennt sie.

### Ohne Server ausprobieren

```bash
python3 tests/mock_server.py 8765 &
python3 src/query.py lauf --faelle faelle.csv --basis-url http://127.0.0.1:8765/v1 \
    --modell mock-modell --lauf laeufe/probe --limit 5
python3 src/evaluate.py --faelle faelle.csv --lauf laeufe/probe
```

Das Test-Modell antwortet nach einer Stichwortregel. Seine Zahlen prüfen nur
die Technik.

## Was nie an das Modell geht

Label, Dateiname und Hash. `query.py` baut das Material nur aus dem Skripttext
und dem Steckbrief ohne Metadaten. `tests/test_pipeline.py` prüft das bei jedem
Lauf.

## Reproduzierbarkeit

- Der Extraktor ist deterministisch. Seine Version steht in jedem Steckbrief
  und in jeder gespeicherten Antwort (`extraktor_version`).
- Der Stand für den Versuch ist als Tag markiert (`extraktor-v2.0.0`). Wird der
  Extraktor danach geändert, steigt die Versionsnummer und alle Läufe sind neu
  zu machen.
- Jede Antwort wird mit Material, Prompt-Hash, Modellname und Einstellungen
  gespeichert. Temperatur ist 0. Wiederholungen messen die Restschwankung.

## Tests

```bash
python3 tests/test_extraktor.py            # 21 Fälle mit bekannter Lösung
python3 tests/test_pipeline.py             # ganzer Durchlauf gegen das Test-Modell
node tests/vergleich_browser.js scripts/   # Browser-Fassung gegen Python, Byte für Byte
```

## Sicherheit

- Schadskripte nur in einer isolierten VM, ohne geteilte Ordner zum Host.
- Kein Werkzeug hier führt ein Skript aus.
- Schadskripte können Text enthalten, der ein Sprachmodell lenken soll. Der
  Prompt weist das Modell an, Anweisungen im Material nicht zu befolgen. Ob es
  sich daran hält, ist Teil der Beobachtung.

## Datenquellen und offene Punkte

| Gruppe | Quelle | Lizenz |
|---|---|---|
| gutartig | github.com/fleschutz/PowerShell | CC0-1.0 |
| bösartig | github.com/Fa2y/Malicious-PowerShell-Dataset | keine Lizenzdatei, vor Veröffentlichung klären |
| Technik-Demos | github.com/calinux-py/PowerShell | keine Lizenzdatei, vor Veröffentlichung klären |

Offen: Labels der bösartigen Skripte stichprobenweise prüfen, Zugang zu den
FH-Modellen, Referenzannotationen für die Detailfälle.
