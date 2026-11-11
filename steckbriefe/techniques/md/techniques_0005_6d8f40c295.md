# Steckbrief: tech_004_AdvEmail.ps1

- SHA256: `6d8f40c295af0d34d455fe2205853aca088388f2c3ae6ecef6ca0171095ae647`
- Groesse: 2094 Bytes, 65 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 11 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `YOUR DISCORD WEBHOOK HERE`
  - `https://www.python.org/ftp/python/3.9.6/python-3.9.6-amd64.exe`
  - `$env:TEMP\python-installer.exe`
  - `/quiet`
  - `PrependPath=1`
  - `https://raw.githubusercontent.com/calinux-py/Python/main/Adv%20Email%20Info%20Grab%20%26%20Upload/emailgrabber.py`
  - `$env:TEMP\emailgrabber.py`
  - `Python is already installed.`
  - `YOUR WEBHOOK`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_webrequest: 2
  - start_process: 1
- URLs: `https://raw.githubusercontent.com/calinux-py/Python/main/Adv%20Email%20Info%20Grab%20%26%20Upload/emailgrabber.py`, `https://www.python.org/ftp/python/3.9.6/python-3.9.6-amd64.exe`
- Pfade: `$env:TEMP\emailgrabber.py`, `$env:TEMP\python-installer.exe`
- Cmdlets: Get-Command, Get-Content, Grab-Emails, Invoke-WebRequest, Remove-Item, Set-Content, Start-Process, Test-Path, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Web-Anfrage senden
  2. Prozess starten
