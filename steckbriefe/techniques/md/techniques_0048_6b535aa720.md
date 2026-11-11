# Steckbrief: tech_047_phish.ps1

- SHA256: `6b535aa720d7b2798ddd6520754a2b8c2e8c7b8a534d3da179e364b7d6835a65`
- Groesse: 2125 Bytes, 59 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 9 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Edge Browser Update`
  - `CenterScreen`
  - `Important Update Available. Click 'Update' to install.`n`n`
  - `Browser: Edge Browser`nVerified Published: Edge`n`nNecessary measures: Click 'Install' to update.`
  - `Install`
  - `Exit`
  - `$env:USERPROFILE\Desktop\update.ps1`
  - `msedge`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_expression: 1
  - add_type: 1
- Pfade: `$env:USERPROFILE\Desktop\update.ps1`
- Cmdlets: Add-Type, Get-Process, Invoke-Expression, New-Object, Start-Sleep, Stop-Process

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Zeichenkette als Code ausfuehren
