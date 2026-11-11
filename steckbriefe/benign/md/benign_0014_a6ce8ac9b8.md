# Steckbrief: benign_013_cd-fonts.ps1

- SHA256: `a6ce8ac9b87c778809568604cb4937da05f3de8bc499b4acd239eabcad964462`
- Groesse: 694 Bytes, 30 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 6 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Fonts`
  - `$path`
  - `No fonts folder at: $path`
  - `📂$path entered, has $($files.Count) font files.`
  - `⚠️ Error: $($Error[0])`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\Windows\Fonts`
- Cmdlets: Get-ChildItem, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
