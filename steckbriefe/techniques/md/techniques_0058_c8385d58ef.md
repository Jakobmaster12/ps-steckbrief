# Steckbrief: tech_057_Run_on_BOOT.ps1

- SHA256: `c8385d58ef735dd36c72f70f50c2576bb1d3841733a626320ea62522e120f4fd`
- Groesse: 1047 Bytes, 30 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 7 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `wallpaper_AUTO-cali.ps1`
  - `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
  - `Wallpaper Engine`
  - `Registry entry added for auto-run at boot: $filePath`
  - `Press Enter to continue`
  - `File not found: $fileName`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - registry_run: 2
- Pfade: `U:\Software\Microsoft\Windows\CurrentVersion\Run`
- Cmdlets: Get-ChildItem, Read-Host, Select-Object, Set-ItemProperty, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Registry-Autostart beruehren
