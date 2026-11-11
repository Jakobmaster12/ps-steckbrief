# Steckbrief: 0c2bb3e84cc99eced7a999b2ff8a068f3993a8a80487fbff55b8e0083bb43c9e.ps1

- SHA256: `0c2bb3e84cc99eced7a999b2ff8a068f3993a8a80487fbff55b8e0083bb43c9e`
- Groesse: 338231 Bytes, 70 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Hinweis: Analyse auf erste 200000 Bytes begrenzt
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 1 (Auszug unten)
- Base64-Bloecke gesamt: 129, davon dekodierbar: 10
- Strings (Auszug):
  - `4D5A9@@@@3@@@@@@@4@@@@@@FFFF@@@@B8@@@@@@@@@@@@@@4@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@`
- Dekodierter Base64-Block (Laenge 40):
  ```
  쇟ᑻ䔱崔푵畍鷗푵祟巗흺䕝黷㞀
  ```
- Dekodierter Base64-Block (Laenge 40):
  ```
  샟Ꮋ䖑崔흵疍鷗흵租巗흺絝黷㙐
  ```
- Dekodierter Base64-Block (Laenge 78):
  ```
  焗ᑅ썝넗ᑅŞ焓ᑅ㱞넗ᑅ㥟ㄐᑅ焓ᑅ㭑焗ᑅﵐꄗᑅŐ턓ᑅ筐섗ᑅ
  ```

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Cmdlets: Convert-HexToByte, New-Object

## Stufe 3 - Struktur (zusaetzlich)
- Dekodierte Befehle (Auszug):
  ```
  쇟ᑻ䔱崔푵畍鷗푵祟巗흺䕝黷㞀
  ```
  ```
  샟Ꮋ䖑崔흵疍鷗흵租巗흺絝黷㙐
  ```
