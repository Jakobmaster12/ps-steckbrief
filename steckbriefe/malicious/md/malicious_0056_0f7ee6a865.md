# Steckbrief: 0f7ee6a8657f531f5ae654e0420823de493c33cfe45348f53e6bb40ac2cb1613.ps1

- SHA256: `0f7ee6a8657f531f5ae654e0420823de493c33cfe45348f53e6bb40ac2cb1613`
- Groesse: 2152 Bytes, 1 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 3 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe`
  - `92^64^43^43^64^44^03^65^65^42^82^85^54^94^B3^72^72^02^E6^96^F6^A6^D2^02^37^27^16^86^34^96^96^36^37^16^42^02^D3^64^43^43^`
  - `) | forEach {[char]([convert]::toint16($_,16))};$jm -join `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - window_hidden: 1
- Pfade: `C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe`

## Stufe 3 - Struktur (zusaetzlich)
