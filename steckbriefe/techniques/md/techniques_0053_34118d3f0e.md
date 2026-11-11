# Steckbrief: tech_052_CreatePassword.ps1

- SHA256: `34118d3f0e88fa36fe9b744de6303bd9b0396c23f3485486c98b9dca0ebbebba`
- Groesse: 191 Bytes, 3 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 1 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Enter your password`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Pfade: `C:\Users\$env:USERNAME\Documents\WindowsPowerShell\yeet.txt`
- Cmdlets: Read-Host, Set-Content

## Stufe 3 - Struktur (zusaetzlich)
