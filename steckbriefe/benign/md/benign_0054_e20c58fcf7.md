# Steckbrief: benign_053_check-easter-sunday.ps1

- SHA256: `e20c58fcf7be5e9588511e44888635c65339a428e16b8fb2b66247a23e08a5d0`
- Groesse: 756 Bytes, 29 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 6 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `04/17/2022`
  - `$PSScriptRoot/speak-english.ps1`
  - `Easter Sunday on April 17 is in $($Diff.Days) days.`
  - `Easter Sunday on April 17 was $($Diff.Days) days ago.`
  - `⚠️ ERROR: $($Error[0]) (at line $($_.InvocationInfo.ScriptLineNumber))`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`

## Stufe 3 - Struktur (zusaetzlich)
