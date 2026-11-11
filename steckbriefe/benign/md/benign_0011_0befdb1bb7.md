# Steckbrief: benign_010_cd-downloads.ps1

- SHA256: `0befdb1bb7348d44f513bf8e8a821ec66758abc1e5217cee8e1636847060d79f`
- Groesse: 1090 Bytes, 35 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 9 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `s downloads folder
.DESCRIPTION
	This PowerShell script changes the working directory to the user`
  - `~/Downloads`
  - `No 'Downloads' folder in your home directory (yet)`
  - `shell:Downloads`
  - `$path`
  - `The path to downloads folder '$path' doesn't exist (yet)`
  - `📂$path entered, has $($files.Count) files and $($folders.Count) folders.`
  - `⚠️ Error: $($Error[0])`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\Users\Markus\Downloads`
- Cmdlets: Get-ChildItem, New-Object, Resolve-Path, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
