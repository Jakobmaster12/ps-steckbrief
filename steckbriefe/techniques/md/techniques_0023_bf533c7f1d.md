# Steckbrief: tech_022_Get-EmailInfo.ps1

- SHA256: `bf533c7f1ddb15700db34140abe4e90ca1b867e32183aa27b9d181e2ef4246ac`
- Groesse: 1483 Bytes, 48 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 7 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `https://myaccount.google.com/personal-info?hl=en`
  - `{DOWN 8}`
  - `CaliShot.png`
  - `Application/Json`
  - `username`
  - `content`
  - `YOUR DISCORD WEBHOOK HERE`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - webclient: 1
  - start_process: 1
  - add_type: 2
- URLs: `https://myaccount.google.com/personal-info?hl=en`
- Pfade: `$env:username`
- Cmdlets: Add-Type, Get-EmailInfo, Invoke-RestMethod, New-Object, Out-Null, Remove-Item, Start-Process, Start-Sleep, Upload-Discord

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Prozess starten
  2. WebClient erstellen
