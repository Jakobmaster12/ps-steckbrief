# Steckbrief: benign_019_cd-onedrive.ps1

- SHA256: `9158bcb7dac58e6e2f6f7ca3a53d93fa06815e65dddbfcd80a0da15c672ae68f`
- Groesse: 843 Bytes, 31 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 5 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `s OneDrive folder.
.EXAMPLE
	PS> ./cd-onedrive.ps1
	📂C:\Users\Markus\OneDrive entered, has 2 files and 0 folders.
.LINK
`
  - `
	}
	$path = Resolve-Path `
  - `
	Set-Location `
  - `
	$files = Get-ChildItem $path -attributes !Directory
	$folders = Get-ChildItem $path -attributes Directory
	`
  - `
	exit 0 # success
} catch {
	`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\Users\Markus\OneDrive`
- Cmdlets: Get-ChildItem, Resolve-Path, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
