# Steckbrief: 0e242927eceb9af6c0d5be7a11a4a9eb4eefa9699cd8a156ddb10af03b95e3fe.ps1

- SHA256: `0e242927eceb9af6c0d5be7a11a4a9eb4eefa9699cd8a156ddb10af03b95e3fe`
- Groesse: 21342 Bytes, 30 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 10 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 0
- Strings (Auszug):
  - `4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000`
  - `A.B`
  - `
$oo =`
  - `.Replace("HISTORRY","Type")
$tt =`
  - `.Replace("TERNET","voke")
$qq ="GetMethod"
$rr = `
  - `.Replace("!!!!!!!!!!!!!!!!!","indows\Microsoft.NET\Fr")
$FT = `
  - `.Replace("l","ad")
$ee=`
  - `.Replace("lo","ul")
$vv = [Reflection.Assembly]
$xx = $vv::$FT($H5);$t1 = `
  - `;$t2 = `
  - `;$HBar=($t1,$t2 -Join `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - reflection_assembly: 1
- Pfade: `C:\W!!!!!!!!!!!!!!!!!amework\v4.0.30319\aspnet_compiler.exe`
- Cmdlets: New-Object

## Stufe 3 - Struktur (zusaetzlich)
