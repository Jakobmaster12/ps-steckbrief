# Steckbrief: 0bd3097c6dbfeac3baa66f96668c4330c1fa22fb8b650e8d3635381c6813ed74.ps1

- SHA256: `0bd3097c6dbfeac3baa66f96668c4330c1fa22fb8b650e8d3635381c6813ed74`
- Groesse: 2050 Bytes, 1 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 2 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 0
- Strings (Auszug):
  - `C:\WINDOWS\syswow64\WindowsPowerShell\v1.0\powershell.exe`
  - `H4sIAAPtN2ECA7VWaW/bOBD9nAD5D0JhQBLqWPLRIwEKLCWfrQ/ZSnzWKBiJlhhToitRcZxu//sObTlNt2nRLrCCD3I4M5x58zjUKos9QXms4IHy5ez0xMEJ`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 1
  - window_hidden: 1
  - noprofile: 1
- Pfade: `C:\WINDOWS\syswow64\WindowsPowerShell\v1.0\powershell.exe`
- Cmdlets: New-Object

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
