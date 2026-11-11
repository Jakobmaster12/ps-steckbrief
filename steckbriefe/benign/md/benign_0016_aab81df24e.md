# Steckbrief: benign_015_cd-jenkins.ps1

- SHA256: `aab81df24eae30efab7ae176fa0fe482c2541e088048c1daeb4039270c48dce2`
- Groesse: 904 Bytes, 34 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 8 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `~/.jenkins`
  - `/var/snap/jenkins`
  - `No Jenkins home directory found - Please install Jenkins`
  - `$path`
  - `📂$path entered, has $($files.Count) files and $($folders.Count) folders.`
  - `⚠️ ERROR: $($Error[0])`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\Users\Markus\.jenkins`
- Cmdlets: Get-ChildItem, Set-Location, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
