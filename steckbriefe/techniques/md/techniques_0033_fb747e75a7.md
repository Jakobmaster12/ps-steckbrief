# Steckbrief: tech_032_Get-PKey.ps1

- SHA256: `fb747e75a7d4baba101ac605f60b7ae8589f5c008a987cacd2ac0d2ca71c7799`
- Groesse: 639 Bytes, 27 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 3 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `application/json`
  - `Product Key: $ProductKey`
  - `DISCORD WEBHOOK`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Cmdlets: Get-PKey, Invoke-RestMethod, Select-Object, Send-DiscordWebhookMessage

## Stufe 3 - Struktur (zusaetzlich)
