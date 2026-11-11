# Steckbrief: 05daac7bbab4f98d298036f05b6ca784a38ac23f3a2b40fe764fdf5a13b89949.ps1

- SHA256: `05daac7bbab4f98d298036f05b6ca784a38ac23f3a2b40fe764fdf5a13b89949`
- Groesse: 260030 Bytes, 83 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Hinweis: Analyse auf erste 200000 Bytes begrenzt
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 4 (Auszug unten)
- Base64-Bloecke gesamt: 2, davon dekodierbar: 0
- Strings (Auszug):
  - `C:\ProgramData\WD`
  - `
function go {
param($WD)$WD = $WD -split `
  - ` | ? { $_ }

ForEach ($chrome in $WD){[Convert]::ToInt32($chrome,16)}}
[byte[]] $MyS  = go(`
  - `)
[byte[]] $RNP  = go(`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Pfade: `C:\ProgramData\WD`
- Cmdlets: New-Item, Start-Sleep

## Stufe 3 - Struktur (zusaetzlich)
