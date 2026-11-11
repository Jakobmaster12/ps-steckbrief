# Steckbrief: 0c7c90cb43fd9c1f00523028b2112e9d27e08233fb9374956df0496ff4415192.ps1

- SHA256: `0c7c90cb43fd9c1f00523028b2112e9d27e08233fb9374956df0496ff4415192`
- Groesse: 1132383 Bytes, 163 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Hinweis: Analyse auf erste 200000 Bytes begrenzt
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 15 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 0
- Strings (Auszug):
  - `C:\ProgramData\holatyrimakachola`
  - `
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command C:\ProgramData\holatyrimakachola\GOLGAPORA.PS1
`
  - `C:\ProgramData\holatyrimakachola\JIGIJIGI.bat`
  - `
on error resume next
on error resume next
on error resume next
on error resume next
WScript.Sleep(1000)
With Crea`
  - `C:\ProgramData\holatyrimakachola\JIGIJIGI.vbs`
  - `
on error resume next
on error resume next
on error resume next
WScript.Sleep(1000)
With CreateObject("WScript.Shel`
  - `C:\ProgramData\holatyrimakachola\helloitsindian.vbs`
  - `
on error resume next
on error resume next
on error resume next
WScript.Sleep(1000)
If Not WScript.Arguments.Named.`
  - `t Beat my Brain
`
  - `A.I Can`
  - `Master Xaviar


`
  - `C:\ProgramData\holatyrimakachola\ChromeExtentionUpdate.vbs`
  - `
try 
{
Stop-Process -Name "msbuild"
Stop-Process -Name "CasPol"
Stop-Process -Name "jsc"
Stop-Process -Name "cmst`
  - `000`
  - `)
    $bytes = New-Object -TypeName byte[] -ArgumentList ($RNBX1.Length / 1+1+0)
    for ($i = 0; $i -lt $RNBX1.Length`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - executionpolicy_bypass: 1
  - noprofile: 1
- Pfade: `C:\ProgramData\holatyrimakachola`, `C:\ProgramData\holatyrimakachola\ChromeExtentionUpdate.vbs`, `C:\ProgramData\holatyrimakachola\GOLGAPORA.PS1`, `C:\ProgramData\holatyrimakachola\JIGIJIGI.bat`, `C:\ProgramData\holatyrimakachola\JIGIJIGI.vbs`, `C:\ProgramData\holatyrimakachola\helloitsindian.vbs`
- Cmdlets: New-Item, New-Object, Stop-Process

## Stufe 3 - Struktur (zusaetzlich)
