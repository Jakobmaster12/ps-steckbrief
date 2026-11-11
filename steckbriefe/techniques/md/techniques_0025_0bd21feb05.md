# Steckbrief: tech_024_Decrypt-AES.ps1

- SHA256: `0bd21feb0520565ea424b5d294b736fb971c954942b27d48f85436c13db71546`
- Groesse: 1400 Bytes, 40 Zeilen
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
- Cmdlets: Clear-RecycleBin, Decrypt-AES, Get-Content, New-Object, Remove-Item, Set-Content, Test-Path, Write-Error

## Stufe 3 - Struktur (zusaetzlich)
