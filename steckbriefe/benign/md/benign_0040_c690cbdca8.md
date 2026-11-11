# Steckbrief: benign_039_cd-videos.ps1

- SHA256: `c690cbdca8c4d964ca656bcd164d161449067a39615e95c764d020e3a0ea7d22`
- Groesse: 1026 Bytes, 34 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 10 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `s videos folder
.DESCRIPTION
	This PowerShell script changes the working directory to the user`
  - `~/Videos`
  - `No 'Videos' folder in your home directory (yet)`
  - `MyVideos`
  - `$path`
  - `The path to video folder '$path' doesn't exist (yet)`
  - `📂$path entered, has $($files.Count) files and $($folders.Count) folders.`
  - `⚠️ ERROR: $($Error[0])`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\Users\Markus\Videos`
- Cmdlets: Get-ChildItem, Resolve-Path, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
