# Steckbrief: benign_021_cd-public.ps1

- SHA256: `2ad2d57cc1a9bf3f89fdf92eea70d36c3dd69abeeee14ee6f41ce3dafcb04338`
- Groesse: 963 Bytes, 38 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 9 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `~/Public`
  - `No 'Public' folder in your home directory yet`
  - `~/../Public`
  - `No 'Public' folder yet`
  - `$path`
  - `📂$path entered, has $($files.Count) files and $($folders.Count) folders.`
  - `⚠️ ERROR: $($Error[0])`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\Users\Public`
- Cmdlets: Get-ChildItem, Resolve-Path, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
