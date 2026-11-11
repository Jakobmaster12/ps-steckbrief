# Steckbrief: benign_029_cd-ssh.ps1

- SHA256: `343ea9aa7a09176b3785c4864bd99d20a15fd04f6d769ee490c32f25cc2fd5ac`
- Groesse: 747 Bytes, 31 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 5 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `s secure shell (SSH) folder.
.EXAMPLE
	PS> ./cd-ssh.ps1
	📂C:\Users\Markus\.ssh entered, has 4 files.
.LINK
	https://gith`
  - `
	}
	$path = Resolve-Path `
  - `
	Set-Location `
  - `
	$files = Get-ChildItem $path -attributes !Directory
	`
  - `
	exit 0 # success
} catch {
	`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\Users\Markus\.ssh`
- Cmdlets: Get-ChildItem, Resolve-Path, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
