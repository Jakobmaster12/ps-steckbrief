# Steckbrief: 054ca3d10e6696769835c8db9ba3bd09142237d21b5bddb013598053f6e0230a.ps1

- SHA256: `054ca3d10e6696769835c8db9ba3bd09142237d21b5bddb013598053f6e0230a`
- Groesse: 2097 Bytes, 58 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 25 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `C:\ProgramData\Document\`
  - `
on error resume next
On Error Resume Next
Dim syncCmd
syncCmd = "$BLNLS=`
  - `;$T=`
  - `;IEx([<#1#>IO.File<#1#>]::$BLNLS($T))"
Dim psCmd
psCmd = "powershell.exe -NonInteractive -WindowStyle Hidden -Executio`
  - `C:\ProgramData\Document\servicing.vbs`
  - `GOOGLE CHRAME`
  - `C/:/\P/r/o/g/ra/m/D/at/a\D/oc/um/ent\`
  - `)
$mcAfee = 'C:/\Pr/o/g/ra/m Fi/les/\Co/mm/o/n F/i/le/s\/M/c/A/f/e/e\P/l/a/t/f/o/r/m\/M/cU/IC/nt/.e/x/e'.Replace(`
  - `)
$nort = 'C:/\Pr/og/ra/m Fil/es\No/r/to/n S/ecu/rit/y\i/so/l/at/e./i/n/i'.Replace(`
  - `)

if([System.IO.File]::Exists($mcAfee)){

if((New-Object `
  - ``D`o`w`N`l`o`A`d`F`i`l`e`
  - `https://makkahmart.org/.POP/.M1.jpg`
  - `Documents.ps1`
  - ``N`e`T`.`W`e`B`C`l`i`e`N`T`
  - `https://makkahmart.org/.POP/.N1.jpg`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_expression: 1
  - window_hidden: 1
  - scheduled_task: 1
- URLs: `https://makkahmart.org/.POP/.D1.jpg`, `https://makkahmart.org/.POP/.M1.jpg`, `https://makkahmart.org/.POP/.N1.jpg`
- Pfade: `C:\ProgramData\Document\`, `C:\ProgramData\Document\Documents.ps1`, `C:\ProgramData\Document\servicing.vbs`
- Cmdlets: Get-Date, New-Object, New-ScheduledTaskAction, New-ScheduledTaskTrigger, New-TimeSpan, Register-ScheduledTask

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. geplante Aufgabe anlegen
  2. Zeichenkette als Code ausfuehren
