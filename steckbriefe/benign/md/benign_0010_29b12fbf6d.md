# Steckbrief: benign_009_cd-docs.ps1

- SHA256: `29b12fbf6d24c6d62c3baf01e7f9c1cb95e987f9566797bee1c022c25b454ff7`
- Groesse: 1036 Bytes, 34 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 9 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `~/Documents`
  - `No 'Documents' folder in your home directory (yet)`
  - `MyDocuments`
  - `$path`
  - `The path to documents folder '$path' doesn't exist (yet)`
  - `📂$path entered, has $($files.Count) files and $($folders.Count) folders.`
  - `⚠️ ERROR: $($Error[0])`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\Users\Markus\Documents`
- Cmdlets: Get-ChildItem, Resolve-Path, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
