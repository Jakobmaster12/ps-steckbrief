# Steckbrief: tech_014_Check-Pass.ps1

- SHA256: `9315587cdfe6ad9418757ab8896020439615feacf042d42a4a1399147726bf2f`
- Groesse: 1333 Bytes, 28 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 7 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - ``nEnter the password to check its security status at haveibeenpwned.com`
  - `).ToLower()
    $hashPrefix = $sha1Hash.Substring(0, 5)
    $hashSuffix = $sha1Hash.Substring(5)

    $response = In`
  - ` -UseBasicParsing -Headers @{`
  - `true`
  - ``r`n`
  - `
        if ($hashParts[0].Equals($hashSuffix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $found = $`
  - ` -ForegroundColor Red
            break
        }
    }

    if (-not $found) {
        Write-Host `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_webrequest: 1
- URLs: `https://api.pwnedpasswords.com/range/$hashPrefix`
- Cmdlets: Add-Padding, Check-Pass, Invoke-WebRequest, Read-Host, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Web-Anfrage senden
