# Steckbrief: tech_017_DNScrypt.ps1

- SHA256: `c5cc9c48849dba22bcb5cdfd39625a45c6524b5e0d6c84600d07f790108bf942`
- Groesse: 1499 Bytes, 39 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 5 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `This script needs to be run as an administrator. Please restart the script with administrative privileges.`
  - `Press any key to exit...`
  - `dnscrypt-proxy`
  - `C:\dnscrypt-proxy-win64-2.1.5\win64`
  - ` }
    Set-DnsClientServerAddress -InterfaceIndex $interface.ifIndex -ServerAddresses "127.0.0.1"

} else {
    # If`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- IPv4: `127.0.0.1`
- Pfade: `C:\dnscrypt-proxy-win64-2.1.5\win64`
- Cmdlets: Get-NetAdapter, Get-Process, Read-Host, Set-DnsClientServerAddress, Set-Location, Where-Object, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
