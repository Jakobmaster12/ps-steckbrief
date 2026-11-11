# Steckbrief: benign_056_check-firewall.ps1

- SHA256: `1a84dae9d21e776938a5508f8017d64e7a88099b45c02e1f42f1afc53fde2721`
- Groesse: 780 Bytes, 32 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 5 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `✅ Firewall `
  - `HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`
  - `✅ Local firewall enabled`
  - `⚠️ Local firewall disabled!`
  - `⚠️ ERROR: $($Error[0]) (at line $($_.InvocationInfo.ScriptLineNumber))`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - registry_run: 1
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `M:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`
- Cmdlets: Get-ItemProperty, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Registry-Autostart beruehren
