# Steckbrief: tech_025_Encrypt-AES.ps1

- SHA256: `83d7a0e04553eceb5dfcc051a779c195e15183a796c00bbbf60840d7fa88d4bd`
- Groesse: 1113 Bytes, 36 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 5 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `File not found: $plainTextFile`
  - `$plainTextFile.aes`
  - `key.txt`
  - `iv.txt`
  - `path/to/the/file`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Cmdlets: Clear-RecycleBin, Encrypt-AES, Get-Content, Join-Path, New-Object, Remove-Item, Set-Content, Split-Path, Test-Path, Write-Error

## Stufe 3 - Struktur (zusaetzlich)
