# Steckbrief: benign_014_cd-home.ps1

- SHA256: `3ecfe3e4343a662bb888f4fd707ccbbc2ae6f65c7dc7e5f2096c28c03a6db919`
- Groesse: 796 Bytes, 29 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 7 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `s home folder
.DESCRIPTION
	This PowerShell script changes the working directory to the user`
  - ` -pathType container)) { throw `
  - `$path`
  - ` }
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
- Pfade: `C:\Users\Markus`
- Cmdlets: Get-ChildItem, Resolve-Path, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
