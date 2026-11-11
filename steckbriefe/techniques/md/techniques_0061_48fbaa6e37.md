# Steckbrief: tech_060_runit.ps1

- SHA256: `48fbaa6e37674ea8ee78fedd39e90b7b7d778639f6e5d2f51cf01273ae14cc39`
- Groesse: 9732 Bytes, 490 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 407 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `https://site address here`
  - `/.env`
  - `/.env.local`
  - `/.env.development`
  - `/.env.production`
  - `/.env.staging`
  - `/.env.test`
  - `/.env.backup`
  - `/.env.example`
  - `/.env.sample`
  - `/config.ini`
  - `/config.php`
  - `/config.json`
  - `/config.yaml`
  - `/config.yml`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_webrequest: 1
- URLs: `https://site`
- Cmdlets: Invoke-WebRequest, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Web-Anfrage senden
