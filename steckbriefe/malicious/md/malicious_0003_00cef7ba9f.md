# Steckbrief: 00cef7ba9fa500deee68eafd286aa841d3e46443322958d8f8844c9aaa3949b2.ps1

- SHA256: `00cef7ba9fa500deee68eafd286aa841d3e46443322958d8f8844c9aaa3949b2`
- Groesse: 145 Bytes, 1 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 1 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `HKCU:\Software\AppDataLow\Software\Microsoft\BBE2C839-DEF8-A50A-C01F-F2A9F4C346ED`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - registry_run: 1
- Pfade: `U:\Software\AppDataLow\Software\Microsoft\BBE2C839-DEF8-A50A-C01F-F2A9F4C346ED`

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Registry-Autostart beruehren
