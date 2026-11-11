# Steckbrief: 0c79ad0f738bdbcb2b761295a25a2c9a66aa2ca96eba8e6b8913d3168e9dacbc.ps1

- SHA256: `0c79ad0f738bdbcb2b761295a25a2c9a66aa2ca96eba8e6b8913d3168e9dacbc`
- Groesse: 36276 Bytes, 708 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 505 (Auszug unten)
- Base64-Bloecke gesamt: 12, davon dekodierbar: 1
- Strings (Auszug):
  - `lCNSX`
  - `c6Ew`
  - `BOBCw`
  - `zD4!`
  - `SaqVZ`
  - `UY5*`
  - `jotrd`
  - `chain`
  - `lRDuN`
  - `SFKuD`
  - `zJifX`
  - `SVGjl`
  - `vcTfZ`
  - `jcJri`
  - `jNHsM`
- Dekodierter Base64-Block (Laenge 65):
  ```
  띩礝⇸㦊騥⥺뮪먭ㇼニࠁԱ爘⠉ඳ䤑ᔵ癙팙띝黣뿟
  ```

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - encodedcommand: 2
  - noprofile: 2

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. kodierten Befehl ausfuehren
- Dekodierte Befehle (Auszug):
  ```
  띩礝⇸㦊騥⥺뮪먭ㇼニࠁԱ爘⠉ඳ䤑ᔵ癙팙띝黣뿟
  ```
