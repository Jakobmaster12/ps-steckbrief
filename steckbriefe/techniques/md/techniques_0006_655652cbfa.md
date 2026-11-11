# Steckbrief: tech_005_Get-AppInfo.ps1

- SHA256: `655652cbfa8b2a16b0cf6f9eac0eca51277382c44af200e4e6d36c66bcfe0948`
- Groesse: 802 Bytes, 31 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 7 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `CaliAppLoot.txt`
  - `App information saved to: $outputFile`
  - `Application/Json`
  - `username`
  - `content`
  - `YOUR WEBHOOK HERE`
  - `$env:TEMP\CaliAppLoot.txt`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - webclient: 1
- Pfade: `$env:TEMP\CaliAppLoot.txt`, `$env:username`
- Cmdlets: Get-AppInfo, Get-AppxPackage, Get-AppxSetting, Invoke-RestMethod, Join-Path, New-Object, Out-Null, Upload-Discord, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. WebClient erstellen
