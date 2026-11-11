# Steckbrief: tech_029_Get-MicrosoftOSINT.ps1

- SHA256: `0ac2c05590b4948c796251d71a3395e4ecfe7299ae6aa543bbe58f2d194a4e7e`
- Groesse: 8772 Bytes, 181 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 62 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Enter the domain to investigate`
  - `Domain cannot be empty`
  - ``n=== Microsoft OSINT for Domain: $Domain ===`
  - `Checking if domain is hosted on Microsoft...`
  - ``n[0] Performing initial domain check...`
  - `https://login.microsoftonline.com/getuserrealm.srf?login=user@$Domain`
  - `Unknown`
  - `  ✗ Domain is NOT hosted on Microsoft/Office 365`
  - ``n=== SUMMARY ===`
  - `Domain '$Domain' is not a Microsoft/Office 365 tenant.`
  - `This domain may be hosted elsewhere or does not exist.`
  - ``n=== END REPORT ===`
  - `  ✓ Domain IS hosted on Microsoft/Office 365`
  - `  Proceeding with detailed information gathering...`
  - `  ✗ Unable to determine if domain is hosted on Microsoft`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://$($Results.Endpoints.GraphHost`, `https://login.microsoftonline.com/$Domain/v2.0/.well-known/openid-configuration`, `https://login.microsoftonline.com/getuserrealm.srf?login=user@$Domain`
- Cmdlets: Get-MicrosoftOSINT, Invoke-RestMethod, Read-Host, Write-Error, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
