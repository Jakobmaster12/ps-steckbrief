# Steckbrief: 0e2f3b3ee0463eed39361790dd95f323890716f4e7fbf169efeab7133a6d123a.ps1

- SHA256: `0e2f3b3ee0463eed39361790dd95f323890716f4e7fbf169efeab7133a6d123a`
- Groesse: 26638 Bytes, 1 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 5 (Auszug unten)
- Base64-Bloecke gesamt: 87, davon dekodierbar: 10
- Strings (Auszug):
  - `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  - `$Embroil = `
  - `SidFKniuTvanSemcAsstUntiDiaoantnBes ForHArbTIntBSub Lib{Syg Det spo Imp BenpParaMonrTetaFejmFuz(Vid[IceSSestSeqrsymiHaan`
  - `;Function Vgavisen9 {    param([String]$Revisionsvirksomhedens);	For($opsummeringers=3; $opsummeringers -lt $Revisionsvi`
  - `');if([IntPtr]::size -eq 8){    .$env:windir\S*64\W*Power*\v1.0\*ll.exe $Timedes1 ;}else{    & ($Timedes0) $Timedes1;}`
- Dekodierter Base64-Block (Laenge 91):
  ```
  ꨱ㇑庫ᘯ抋랦ㆬꊩꥅ㸨➺褮ⷬܮ㊢꜅Ԥꤽศꚻ⬎䨡鹌ꬅ㵝庩렖Ƨⳇ
  ```
- Dekodierter Base64-Block (Laenge 59):
  ```
  젖ન⦇ꨝ㋬⸧⭋⨦暉렺؞ꭖ饊啢㫠Ẹ褊ᷫ골⤲
  ```
- Dekodierter Base64-Block (Laenge 67):
  ```
  ۨ⦈❖劬⹷䫦ꛖ褎䶞⯨뜖劢❻먾䨠麛蝆ㆫ泩誒㻿뙖뮡
  ```

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Pfade: `$env:windir\S*64\W*Power*\v1.0\*ll.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- Cmdlets: Cha-Indlutotluk, Dob-GgebGeoxHeloCharOve, Non-CouPCelaAfstTilhMof, Off-PatvTipaRetlBruuVaneJob, Pod-TulnJejaSvrmCoueTen

## Stufe 3 - Struktur (zusaetzlich)
- Dekodierte Befehle (Auszug):
  ```
  ꨱ㇑庫ᘯ抋랦ㆬꊩꥅ㸨➺褮ⷬܮ㊢꜅Ԥꤽศꚻ⬎䨡鹌ꬅ㵝庩렖Ƨⳇ
  ```
  ```
  젖ન⦇ꨝ㋬⸧⭋⨦暉렺؞ꭖ饊啢㫠Ẹ褊ᷫ골⤲
  ```
