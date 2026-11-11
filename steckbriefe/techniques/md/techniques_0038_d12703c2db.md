# Steckbrief: tech_037_MOAR.ps1

- SHA256: `d12703c2db4632c51beab288db2df82f962d18d8bb11e2728fc40ca012dc55fa`
- Groesse: 9554 Bytes, 236 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 55 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `http://ip-api.com/json`
  - `$env:TEMP\AR.txt`
  - `$env:TEMP\BrowserData.txt`
  - `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
  - `(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?`
  - `history`
  - `http`
  - `chrome`
  - `$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History`
  - `edge`
  - `$Env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\History`
  - `firefox`
  - `$Env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\places.sqlite`
  - ` : `
  - `)[1]).Trim()
        }
        $WLANProfileObjects = @()

        Foreach ($WLANProfileName in $WLANProfileNames) {`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - webclient: 1
- URLs: `http://ip-api.com/json`
- Pfade: `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`, `$env:TEMP`, `$env:TEMP\$FolderName\Powershell-History.txt`, `$env:TEMP\$FolderName\tree.txt`, `$env:TEMP\$additionalFolder\Powershell-History.txt`, `$env:TEMP\$additionalFolder\tree.txt`, `$env:TEMP\*`, `$env:TEMP\AR.txt`
- Cmdlets: Add-Member, Clear-RecycleBin, Compress-Archive, Copy-Item, Format-Table, Get-AdditionalData, Get-AppxPackage, Get-BrowserData, Get-ChildItem, Get-CimInstance, Get-ComputerInfo, Get-Content, Get-NetFirewallProfile, Get-Networks, Get-PSreadlineOption, Get-Process, Get-WmiObject, Invoke-RestMethod, New-Item, New-Object

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. WebClient erstellen
