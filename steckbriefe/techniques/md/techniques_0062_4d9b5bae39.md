# Steckbrief: tech_061_WifiBrute.ps1

- SHA256: `4d9b5bae39bd7a5a253602276a07b2bd963747090bbc2bd03bb1913b1bb7ab69`
- Groesse: 1441 Bytes, 36 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 11 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `https://www.python.org/ftp/python/3.9.6/python-3.9.6-amd64.exe`
  - `$env:TEMP\python-3.9.7-amd64.exe`
  - `/quiet InstallAllUsers=1 PrependPath=1`
  - `https://raw.githubusercontent.com/calinux-py/Python/main/WiFi%20Password%20Bruteforce/pass.txt`
  - `$env:TEMP\pass.txt`
  - `$env:TEMP\flipper.py`
  - `https://raw.githubusercontent.com/calinux-py/Python/main/WiFi%20Password%20Bruteforce/flipper.py`
  - `YOUR_SSID_HERE`
  - `$ssid`
  - `YOUR SSID`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_webrequest: 3
  - start_process: 1
- URLs: `https://raw.githubusercontent.com/calinux-py/Python/main/WiFi%20Password%20Bruteforce/flipper.py`, `https://raw.githubusercontent.com/calinux-py/Python/main/WiFi%20Password%20Bruteforce/pass.txt`, `https://www.python.org/ftp/python/3.9.6/python-3.9.6-amd64.exe`
- Pfade: `$env:TEMP\flipper.py`, `$env:TEMP\pass.txt`, `$env:TEMP\python-3.9.7-amd64.exe`
- Cmdlets: Get-Command, Get-Content, Invoke-WebRequest, Set-Content, Start-Process

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Web-Anfrage senden
  2. Prozess starten
