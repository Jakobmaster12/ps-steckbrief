# Steckbrief: tech_023_Decrypt-AES-shortened.ps1

- SHA256: `47ac6a44c36efeb0a2a69b2fbe0fce25b765e570cba68d2a5f49024ae9a4877d`
- Groesse: 1384 Bytes, 40 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 5 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `The specified file path does not exist: $encryptedFilePath`
  - `key.txt`
  - `iv.txt`
  - `Either the key file or the IV file is missing.`
  - `path/to/file`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Cmdlets: Clear-RecycleBin, Get-Content, New-Object, Remove-Item, Set-Content, Test-Path, Write-Error

## Stufe 3 - Struktur (zusaetzlich)
