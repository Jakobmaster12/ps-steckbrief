# Steckbrief: tech_027_Get-Geo.ps1

- SHA256: `881dd7433b5b02503ee6ec7c579cb158c210434bebcaae3fca72614e743f3d67`
- Groesse: 1412 Bytes, 35 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 19 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `http://ip-api.com/json`
  - `success`
  - `          = $response.query
                `
  - `     = $response.country
                `
  - `      = $response.regionName
                `
  - `        = $response.city
                `
  - `    = $response.lat
                `
  - `   = $response.lon
                `
  - `    = $response.timezone
                `
  - `IP Address    : $($geoLocation.IP)`
  - `Country       : $($geoLocation.Country)`
  - `Region        : $($geoLocation.Region)`
  - `City          : $($geoLocation.City)`
  - `Latitude      : $($geoLocation.Latitude)`
  - `Longitude     : $($geoLocation.Longitude)`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `http://ip-api.com/json`
- Cmdlets: Get-Geo, Invoke-RestMethod, New-Object, Write-Error, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
