# Steckbrief: benign_045_check-bios.ps1

- SHA256: `ea6dd88cca36adbad432bb0da19fc15563adbcf0a23f1c2dcd2c5fb9447dd04c`
- Groesse: 1416 Bytes, 42 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 17 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `$model`
  - `) { exit 0 } # no information
		Write-Progress `
  - `
		$version = (sudo dmidecode -s bios-version)
		$releaseDate = (sudo dmidecode -s bios-release-date)
		$manufacturer = `
  - `
	} else {
		$details = Get-CimInstance -ClassName Win32_BIOS
		$model = $details.Name.Trim()
		$version = $details.Vers`
  - `) { $model = `
  - ` }
	if ($version -eq `
  - `) { $version = `
  - ` }
	if (`
  - ` -ne `
  - `) { $releaseDate = `
  - ` -eq `
  - `) { $serial = `
  - ` }
	if ($serial -eq `
  - ` }
	Write-Host `
  - `
	exit 0 # success
} catch {
	`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Cmdlets: Get-CimInstance, Write-Host, Write-Progress

## Stufe 3 - Struktur (zusaetzlich)
