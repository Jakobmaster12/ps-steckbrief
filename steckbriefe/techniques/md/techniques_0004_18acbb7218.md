# Steckbrief: tech_003_Get-Aced.ps1

- SHA256: `18acbb721857a826d65f73c3eb3d3e3c45a83f8660484d20a2be4d8a8acb8251`
- Groesse: 981 Bytes, 35 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 10 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Programs\Python`
  - `https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe`
  - `python_installer.exe`
  - `/quiet InstallAllUsers=1 PrependPath=1`
  - `https://raw.githubusercontent.com/calinux-py/Python/main/Overlay-AceVentura/Overlay-Ace.py`
  - `Overlay-Ace.py`
  - `pip`
  - `install pyautogui keyboard`
  - `pip3`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_webrequest: 2
  - start_process: 3
- URLs: `https://raw.githubusercontent.com/calinux-py/Python/main/Overlay-AceVentura/Overlay-Ace.py`, `https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe`
- Pfade: `$env:LOCALAPPDATA`, `$env:TEMP`
- Cmdlets: Invoke-WebRequest, Join-Path, Overlay-Ace, Overlay-AceVentura, Remove-Item, Start-Process, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Web-Anfrage senden
  2. Prozess starten
