# Steckbrief: benign_002_brew-coffee.ps1

- SHA256: `5d1637ffda6a2b5a3732642d966ac679c4ccfd570234a54b51698306c8b19bc4`
- Groesse: 1552 Bytes, 69 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 18 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `                 `
  - `       )(   )(   `
  - `      (  ) (  )  `
  - `      _________   `
  - `  ###|         |  `
  - ` |   |         |  `
  - ` |   | B O S S |  `
  - `  ###|_________|  `
  - `     \_________/  `
  - `⚠️ ERROR: $($Error[0]) (at line $($_.InvocationInfo.ScriptLineNumber))`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Cmdlets: Clear-Host, Start-CoffeeCupAnimation, Start-Sleep, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
