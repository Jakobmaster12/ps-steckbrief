# Grundgeruest Masterarbeit - LLM-gestuetzte Analyse von PowerShell-Skripten

Stand: 2026-11-03. Ersteller: Jakob Weilhartner.

## Worum geht es

Das Grundgeruest liefert zwei Dinge:

1. **Einen Datensatz** aus PowerShell-Skripten in drei Gruppen (gutartig,
   boesartig, Technik-Demos), reproduzierbar beschafft mit Herkunftsnachweis.
2. **Einen Steckbrief-Generator**, der aus jedem Skript einen forensischen
   Steckbrief in drei definierten Stufen erzeugt. Diese Steckbriefe sind der
   geplante Eingang fuer das LLM-Experiment.

Die Grundidee der Arbeit: Nicht der rohe (ggf. obfuskierte) Code geht ins
LLM, sondern ein statisch erzeugter Steckbrief. Der **Detailgrad des
Steckbriefs** ist die zentrale, kontrollierte Variable. Gemessen wird, wie
gut das LLM auf Basis welcher Stufe eine Einschaetzung trifft.

## Projektstruktur

```
src/fetch.py          Datensatz-Beschaffung (git clone + sortieren)
src/steckbrief.py     Steckbrief-Generator (statisch, drei Stufen)
scripts/benign/       gutartige Rohskripte (Sample)
scripts/techniques/   Technik-Demonstrationen (Rohskripte)
steckbriefe/benign/     Steckbriefe gutartig  (json + md)
steckbriefe/techniques/ Steckbriefe Technik-Demos (json + md)
steckbriefe/malicious/  Steckbriefe boesartig (json + md)
sources.json          Herkunft, Commit-Stand, Lizenzstatus je Quelle
manifest.csv          alle Samples mit Label und SHA256
```

Hinweis: Die **rohen boesartigen Skripte** sind in diesem Paket absichtlich
nicht enthalten, nur ihre Steckbriefe (reine Analyse-Artefakte, ungefaehrlich).
Den vollstaendigen boesartigen Satz holst du selbst mit `fetch.py` in deiner
isolierten VM (siehe unten). So bleibt die Beschaffung reproduzierbar und
nachvollziehbar, und es wird kein Schadcode ueber den Chat verteilt.

## Die drei Quellen und warum

| Gruppe | Quelle | Begruendung | Lizenz |
|---|---|---|---|
| gutartig | github.com/fleschutz/PowerShell | grosse Sammlung legitimer Admin-Skripte, Kontrollgruppe fuer Fehlalarme | CC0-1.0 |
| boesartig | github.com/Fa2y/Malicious-PowerShell-Dataset | echte boesartige Skripte (Triage, Bazaar, Hybrid-Analysis), vom PSStrikes-Paper referenziert | keine LICENSE-Datei, vor Nutzung klaeren |
| Technik-Demos | github.com/calinux-py/PowerShell | gut lesbare Demonstrationen einzelner Techniken (Base64, Exfiltration, Obfuskation) | keine LICENSE-Datei, vor Nutzung klaeren |

Bewusst **nicht** verwendet: vollstaendige, scharfe Malware-Binaries (z.B. von
MalwareBazaar als EXE). Fuer die statische Skript-Analyse nicht noetig und
unnoetiges Risiko. Die akademisch sauberste Alternative fuer die boesartige
Seite ist `mkmeher/powershell-malware-dataset` (Nature-Paper, VirusTotal-
validiert, gelabelt). Deren Rohskripte liegen in git-LFS und brauchen eigenen
GitHub-Zugang, daher hier als Option, nicht als Default.

## Die drei Steckbrief-Stufen (= drei Techniken)

Jede Stufe entspricht genau einer statischen Analyse-Technik. Dadurch ist der
Detailgrad reproduzierbar und nicht vom Ermessen des Analysten abhaengig.
Das beantwortet die Frage "wann ist genug Forensik drin": nicht nach
Bauchgefuehl, sondern definiert durch die Technik.

- **Stufe 1 (extract):** Ausgabe eines String- und Encoding-Extraktors.
  Enthaelt Strings und dekodierte Base64-Bloecke. Keine Interpretation.
- **Stufe 2 (features):** Stufe 1 plus statischer Muster- und IOC-Scanner.
  Enthaelt beobachtete Cmdlets, auffaellige Tokens, URLs, IPs, Pfade.
- **Stufe 3 (structure):** Stufe 2 plus leichte Deobfuskation und die
  beobachtete Operationsabfolge.

Wichtig: Kein Steckbrief enthaelt ein Urteil (kein "boesartig", kein
Schweregrad, keine Empfehlung). Die Bewertung ist Aufgabe des LLM im
Experiment. Das Ground-Truth-Label steht nur in den Metadaten, fuer die
spaetere Auswertung, nicht im Analyse-Teil.

## Datensatz selbst beschaffen (vollstaendig)

Nur in einer isolierten Umgebung ausfuehren (VM ohne Netzverbindung zum Host).

```bash
# alle drei Gruppen holen
python3 src/fetch.py --out ./scripts

# nur die boesartige Gruppe
python3 src/fetch.py --out ./scripts --only malicious

# danach Steckbriefe erzeugen, je Gruppe
python3 src/steckbrief.py ./scripts/malicious --out ./steckbriefe/malicious --label malicious
```

`fetch.py` schreibt `sources.json` mit Commit-Stand je Quelle, damit der
Datensatz exakt nachgebaut werden kann.

## Sicherheit

- Der Steckbrief-Generator **fuehrt nichts aus**. Er liest Text und wendet
  Regex und Base64-Dekodierung an.
- Trotzdem gehoeren die boesartigen Rohskripte in eine isolierte VM.
- Sehr grosse, stark obfuskierte Dateien werden nur bis 200 KB analysiert
  (im Steckbrief als `analyse_gekuerzt` vermerkt).

## Offene Punkte (fuer die Besprechung)

- **Lizenz** von Fa2y und calinux ist ungeklaert. Vor Veroeffentlichung des
  Datensatzes klaeren, oder auf `mkmeher` (gelabelt, Paper) ausweichen.
- **FH-Modelle:** welche drei LLMs laufen auf dem FH-Server, wie ist der Zugriff.
- **Umfang:** wie viele Samples je Gruppe, wie viele Durchlaeufe je Sample.
- **Kriterienkatalog** fuer die Bewertung der LLM-Einschaetzung (angelehnt an
  NIST SP 800-61), noch festzulegen.
- **Obfuskationsstufen:** optional zusaetzlich zur Steckbrief-Tiefe variieren
  (mit Invoke-Obfuscation), falls gewuenscht.

## Oberflaeche (tool/)

`tool/steckbrief-werkbank.html` ist eine einzelne HTML-Datei, die offline im Browser
laeuft (Doppelklick). Sie erzeugt Steckbriefe nach denselben Regeln wie
`src/steckbrief.py`, mit Verlauf und Export. Fuer den Stapellauf ueber alle
Samples bleibt `src/steckbrief.py` massgeblich.

## Nicht im Repo

Der Ordner `scripts/` (Rohskripte) ist per `.gitignore` ausgeschlossen. Er entsteht
mit `python3 src/fetch.py --out ./scripts`.
