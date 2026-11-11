# Steckbrief: tech_031_Get-Pic.ps1

- SHA256: `f953a69facadf83d2f23bb0720e99a721caec96348c195d3759f7530fa3e8222`
- Groesse: 2381 Bytes, 50 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 22 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `snapshot.png`
  - `Integrated Camera`
  - `*Wi-Fi*`
  - `http://ipinfo.io/ip`
  - `0.0.0.0/0`
  - `*Ethernet*`
  - `Hostname: $hostname, WiFi Private IP: $wifiIPAddress, WiFi Public IP: $wifiPublicIPAddress, WiFi Default Gateway: $wifiG`
  - `multipart/form-data; boundary=$boundary`
  - `--$boundary`r`n`
  - `Content-Disposition: form-data; name=``
  - ``r`n`r`n`
  - `{ ``
  - `: ``
  - ` }`r`n`
  - `; filename=``

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `http://ipinfo.io/ip`
- IPv4: `0.0.0.0`
- Pfade: `$env:COMPUTERNAME`
- Cmdlets: Clear-RecycleBin, Content-Disposition, Content-Type, Get-NetAdapter, Get-NetIPAddress, Get-NetRoute, Get-Pic, Invoke-RestMethod, Join-Path, Remove-Item, Where-Object, Wi-Fi

## Stufe 3 - Struktur (zusaetzlich)
