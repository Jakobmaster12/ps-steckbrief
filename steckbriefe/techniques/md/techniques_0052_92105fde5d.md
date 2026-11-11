# Steckbrief: tech_051_SubnetGrab(PYTHON).ps1

- SHA256: `92105fde5d96a397b465852ac9dcfbabc59981c1b33d02f71f71104e5035fe2e`
- Groesse: 1663 Bytes, 40 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 18 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `py.exe`
  - `Python is not installed. Installing Python...`
  - `https://www.python.org/ftp/python/3.9.7/python-3.9.7-amd64.exe`
  - `python_installer.exe`
  - `/quiet InstallAllUsers=1 PrependPath=1`
  - `Python is already installed.`
  - `Programs/Python/Python39/Scripts/pip.exe`
  - `Pip is not installed. Installing Pip...`
  - `https://bootstrap.pypa.io/get-pip.py`
  - `get-pip.py`
  - `Pip is already installed.`
  - `https://raw.githubusercontent.com/calinux-py/Python/main/Subnet%20Device%20Grab/SubnetGrab.py`
  - `YOUR DISCORD WEBHOOK HERE`
  - `SubnetGrab.py`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_webrequest: 3
  - start_process: 1
- URLs: `https://bootstrap.pypa.io/get-pip.py`, `https://raw.githubusercontent.com/calinux-py/Python/main/Subnet%20Device%20Grab/SubnetGrab.py`, `https://www.python.org/ftp/python/3.9.7/python-3.9.7-amd64.exe`
- Pfade: `$env:LOCALAPPDATA`, `$env:SYSTEMROOT`
- Cmdlets: Invoke-WebRequest, Join-Path, Remove-Item, Select-Object, Set-Content, Start-Process, Subnet-Grab, Test-Path, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Web-Anfrage senden
  2. Prozess starten
