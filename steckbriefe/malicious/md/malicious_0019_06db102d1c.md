# Steckbrief: 06db102d1c5d9386cd8d13e22237b286e4ecf1869c84cc70f17da0d421ccad3d.ps1

- SHA256: `06db102d1c5d9386cd8d13e22237b286e4ecf1869c84cc70f17da0d421ccad3d`
- Groesse: 456 Bytes, 10 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 7 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `http://85.192.63.184/s.exe`
  - `Host`
  - `hacktree.org`
  - `user-agent`
  - `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; .NET CLR 1.0.3705;`
  - `C:\s.exe`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - downloadfile: 1
  - start_process: 1
- URLs: `http://85.192.63.184/s.exe`
- IPv4: `85.192.63.184`
- Pfade: `C:\s.exe`
- Cmdlets: New-Object, Start-Process

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Datei von URL herunterladen
  2. Prozess starten
