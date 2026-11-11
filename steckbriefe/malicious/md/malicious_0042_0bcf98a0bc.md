# Steckbrief: 0bcf98a0bc82f88141cba86f3a583be951d9b05c9e9af2b1d454c291c15922de.ps1

- SHA256: `0bcf98a0bc82f88141cba86f3a583be951d9b05c9e9af2b1d454c291c15922de`
- Groesse: 568 Bytes, 17 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 8 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `C:\Users\`
  - `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
  - `C:\Users\Public\`
  - `https://ia801503.us.archive.org/13/items/startup_20210219/Startup.txt`
  - `Run.hta`
  - `http://ahmedadel.work/cairo/Server.txt`
  - `Microsoft.ps1`
  - `C:\Users\Public\Microsoft.ps1`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_expression: 1
  - downloadfile: 2
- URLs: `http://ahmedadel.work/cairo/Server.txt`, `https://ia801503.us.archive.org/13/items/startup_20210219/Startup.txt`
- Pfade: `$env:UserName`, `C:\Users\`, `C:\Users\Public\`, `C:\Users\Public\Microsoft.ps1`
- Cmdlets: New-Object

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Datei von URL herunterladen
  2. Zeichenkette als Code ausfuehren
