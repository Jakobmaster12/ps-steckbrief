# Steckbrief: tech_059_Get-Weather.ps1

- SHA256: `362fd045c07088b90e0e7b23a91658b880a3a0c3176911b1f730607ecfbc680c`
- Groesse: 319 Bytes, 10 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 4 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `https://wttr.in/`
  - ` # ?M or ?m for metric options - RUX
    $location = `
  - ` # Replace `
  - ` with your desired location

    $wttrUrl = `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://wttr.in/`
- Cmdlets: Get-Weather, Invoke-RestMethod, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
