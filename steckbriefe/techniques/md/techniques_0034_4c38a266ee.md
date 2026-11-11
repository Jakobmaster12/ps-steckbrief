# Steckbrief: tech_033_Get-PublicIP(not_encoded).ps1

- SHA256: `4c38a266ee9e53599a4ff6ca8bf59c35b74de55b2771edda93420c42d51f9610`
- Groesse: 186 Bytes, 3 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 2 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `your webhook here`
  - `application/json`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_webrequest: 1

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Web-Anfrage senden
