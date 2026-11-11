# Steckbrief: 056deb6e3f5de68f9ae2b1ed11f7d3d398a3488387294937bebcb0f8f847b5c9.ps1

- SHA256: `056deb6e3f5de68f9ae2b1ed11f7d3d398a3488387294937bebcb0f8f847b5c9`
- Groesse: 369 Bytes, 15 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 2 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `fix\data.txt`
  - `;
$r = $b64.ToCharArray();
[array]::Reverse($r);
-join($r);

$filename = `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 1
- Pfade: `C:\users\public\agreeBrood.jpg`
- Cmdlets: Get-Content

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
