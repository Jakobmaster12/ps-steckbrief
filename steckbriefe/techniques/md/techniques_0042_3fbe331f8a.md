# Steckbrief: tech_041_Obfuscate.ps1

- SHA256: `3fbe331f8aa2139338a3990b3030110cbc0842aede5237665f156f88c3599c47`
- Groesse: 16040 Bytes, 351 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 116 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 0
- Strings (Auszug):
  - `--help`
  - `--h`
  - `
Obfuscate Script Help:

Description:
    This script obfuscates a PowerShell script file by removing comments and e`
  - `Enter the path to the file to Obfuscate`
  - `File not found: $FilePath`
  - `(?m)^\s*#.*$`
  - `
        $scriptContent = $scriptContent -replace `
  - `

        $aliases = @{
            `
  - `            = `
  - `
            `
  - `           = `
  - `         = `
  - `     = `
  - `          = `
  - `              = `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 3
  - start_process: 1
- Pfade: `C:\Programming\#Powershell\!`, `C:\path\to\script.ps1`
- Cmdlets: Clear-Content, Compare-Object, Copy-Item, Get-ChildItem, Get-CimInstance, Get-Content, Get-Date, Get-Location, Get-NetIPConfiguration, Get-PSDrive, Get-Process, Get-Random, Get-RandomName, Get-Service, Get-WmiObject, Invoke-RestMethod, Move-Item, New-Item, New-Object, Read-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Prozess starten
  2. Base64-Inhalt dekodieren
