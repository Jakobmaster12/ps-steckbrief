# Steckbrief: tech_019_DisableUAC.ps1

- SHA256: `b3f8e9b57c86c8fcc9ea7f70dd08562fd0a1e568a02a5534261e9d519bfd0f2b`
- Groesse: 568 Bytes, 12 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 4 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Administrator`
  - `Please run this script as an Administrator!`
  - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
  - `EnableLUA`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - registry_run: 1
- Pfade: `M:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
- Cmdlets: Set-ItemProperty, Write-Warning

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Registry-Autostart beruehren
