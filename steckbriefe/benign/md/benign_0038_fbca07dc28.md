# Steckbrief: benign_037_cd-up4.ps1

- SHA256: `fbca07dc285271c6124740b4ea33531b750fd2c4252ae0180e869c2182ddd01a`
- Groesse: 576 Bytes, 27 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 6 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `../../../..`
  - `$path`
  - `Folder at 📂$path doesn't exist (yet)`
  - `📂$path`
  - `⚠️ ERROR: $($Error[0])`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Cmdlets: Resolve-Path, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
