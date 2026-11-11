# Steckbrief: benign_048_check-day.ps1

- SHA256: `b0bba4a15114e3a70a8f27eb205303e6e1328003c011ea482972f6111695bef5`
- Groesse: 601 Bytes, 24 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 2 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `s Sunday.
.LINK
	https://github.com/fleschutz/PowerShell
.NOTES
	Author: Markus Fleschutz | License: CC0
#>

try {
	[sys`
  - `
	exit 0 # success
} catch {
	`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Cmdlets: Get-Date

## Stufe 3 - Struktur (zusaetzlich)
