# Steckbrief: 10882cb1fc5cfdf37b2bb6ea6ea9189f39ae8f0889eac96866cb72e3ea4e4b3c.ps1

- SHA256: `10882cb1fc5cfdf37b2bb6ea6ea9189f39ae8f0889eac96866cb72e3ea4e4b3c`
- Groesse: 231940 Bytes, 87 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Hinweis: Analyse auf erste 200000 Bytes begrenzt
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 18 (Auszug unten)
- Base64-Bloecke gesamt: 2, davon dekodierbar: 0
- Strings (Auszug):
  - `C:\ProgramData\PDF`
  - `

try 
{
&`
  - `/create`
  - `/sc`
  - `minute`
  - `/mo`
  - `/tn`
  - `PDF`
  - `/tr`
  - `C:\ProgramData\PDF\PDF.vbs`
  - `@
[IO.File]::WriteAllText("C:\ProgramData\PDF\x.ps1", $Content)



$Content = @`
  - `WScript.Shell`
  - `C:\ProgramData\PDF\1.bat`
  - `@
[IO.File]::WriteAllText("C:\ProgramData\PDF\PDF.vbs", $Content)




$Content = @`
  - `C:\ProgramData\PDF\PDF.ps1`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Pfade: `C:\ProgramData\PDF`, `C:\ProgramData\PDF\1.bat`, `C:\ProgramData\PDF\PDF.ps1`, `C:\ProgramData\PDF\PDF.vbs`, `C:\ProgramData\PDF\x.ps1`
- Cmdlets: New-Item

## Stufe 3 - Struktur (zusaetzlich)
