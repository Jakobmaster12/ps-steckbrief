# Steckbrief: 0dead736f60366e0ef43b755d6d3a775220f73bd2971012c77e4cac81da658e3.ps1

- SHA256: `0dead736f60366e0ef43b755d6d3a775220f73bd2971012c77e4cac81da658e3`
- Groesse: 4839 Bytes, 11 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 3 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `55155155,51555151,51115515,51115515,51151111,51115515,51555551,51155511,51115155,51151551,51151111,51151115,51515555,511`
  - `)|IEX) | %{ [System.Text.Encoding]::UTF8.GetString([System.Convert]::ToInt32($_,2)) }

$o00=[char]105 + `
  - `;sal P $o00;([system.String]::Join(`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_expression: 1
  - char_array: 1

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Zeichenkette als Code ausfuehren
