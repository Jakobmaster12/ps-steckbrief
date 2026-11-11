# Steckbrief: tech_009_test.ps1

- SHA256: `eed3911e0d5b662b6552cb2becd2d11fade50e300a3eeb36288117cd92f91728`
- Groesse: 72 Bytes, 3 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 1 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `https://www.youtube.com/watch?v=Td9ZiR0onpk`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - start_process: 1
- URLs: `https://www.youtube.com/watch?v=Td9ZiR0onpk`
- Cmdlets: Start-Process

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Prozess starten
