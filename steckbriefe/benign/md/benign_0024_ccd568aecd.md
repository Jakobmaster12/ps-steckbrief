# Steckbrief: benign_023_cd-recycle-bin.ps1

- SHA256: `ccd568aecd9bb553a48ec7d39fe4e12c73c3c8a3acc782ebaca49e727ae5ac45`
- Groesse: 1128 Bytes, 41 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 7 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `~/.local/share/Trash/`
  - `C:\`$Recycle.Bin\$(GetCurrentUserSID)`
  - `$path`
  - `No recycle bin folder at $path`
  - `📂$path entered, has $($files.Count) files and $($folders.Count) folders.`
  - `⚠️ ERROR: $($Error[0])`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - add_type: 1
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\$Recycle.Bin\S-1-5-21-123404-23309-294260-1001`, `C:\`$Recycle.Bin\$(GetCurrentUserSID)`
- Cmdlets: Add-Type, Get-ChildItem, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
