# Steckbrief: benign_011_cd-dropbox.ps1

- SHA256: `c6f179af3b566530fb77cb1703d03c6cb1a6fcb8b8aa553ae3036a86d77d8734`
- Groesse: 839 Bytes, 31 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 7 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `s Dropbox folder
.DESCRIPTION
	This PowerShell script changes the working directory to the user`
  - `~/Dropbox`
  - `No 'Dropbox' folder in your home directory - Please install Dropbox.`
  - `$path`
  - `📂$path entered, has $($files.Count) files and $($folders.Count) folders.`
  - `⚠️ ERROR: $($Error[0])`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\Users\Markus\Dropbox`
- Cmdlets: Get-ChildItem, Resolve-Path, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
