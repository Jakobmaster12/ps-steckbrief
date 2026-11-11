# Steckbrief: tech_045_OverlayAttack.ps1

- SHA256: `a59febab729f89331e18b1744c6c869e5288af3f344e2a04591b50661ac9ce5c`
- Groesse: 2498 Bytes, 68 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 12 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `https://www.python.org/ftp/python/3.9.6/python-3.9.6-amd64.exe`
  - `$env:TEMP\python_installer.exe`
  - `/quiet`
  - `PrependPath=1`
  - `https://raw.githubusercontent.com/calinux-py/Python/main/Basic%20Overlay%20Ransom/datsmean.png`
  - `datsmean.png`
  - `Error downloading the file: $_.Exception.Message`
  - `https://raw.githubusercontent.com/calinux-py/Python/main/Basic%20Overlay%20Ransom/FlipperVersion.py`
  - `$env:TEMP\FlipperVersion.py`
  - `Downloading the Python script...`
  - `Running the downloaded Python script...`
  - `An error occurred: $_.Exception.Message`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - downloadfile: 2
  - invoke_webrequest: 2
  - start_process: 1
- URLs: `https://raw.githubusercontent.com/calinux-py/Python/main/Basic%20Overlay%20Ransom/FlipperVersion.py`, `https://raw.githubusercontent.com/calinux-py/Python/main/Basic%20Overlay%20Ransom/datsmean.png`, `https://www.python.org/ftp/python/3.9.6/python-3.9.6-amd64.exe`
- Pfade: `$env:TEMP\FlipperVersion.py`, `$env:TEMP\python_installer.exe`
- Cmdlets: Download-File, Invoke-WebRequest, New-Object, Remove-Item, Start-Overlay, Start-Process, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Datei von URL herunterladen
  2. Prozess starten
  3. Web-Anfrage senden
