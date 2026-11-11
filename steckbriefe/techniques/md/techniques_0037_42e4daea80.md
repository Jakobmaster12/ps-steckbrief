# Steckbrief: tech_036_drivepwn.ps1

- SHA256: `42e4daea8068c3e4f45041af4125899384c3de659290d2d19027018fd3b59e83`
- Groesse: 1546 Bytes, 52 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 11 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `https://drive.google.com/drive/u/0/my-drive`
  - `https://drive.google.com/drive/u/1/my-drive`
  - `https://drive.google.com/drive/u/2/my-drive`
  - `https://drive.google.com/drive/u/3/my-drive`
  - `^(a)`
  - `^%a`
  - `{ENTER}`
  - `{TAB}`
  - `Google Drive`
  - `your_email@example.com`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - start_process: 4
  - add_type: 1
- URLs: `https://drive.google.com/drive/u/0/my-drive`, `https://drive.google.com/drive/u/1/my-drive`, `https://drive.google.com/drive/u/2/my-drive`, `https://drive.google.com/drive/u/3/my-drive`
- Cmdlets: Access-Drive, Add-Type, Get-Process, Start-Process, Start-Sleep, Stop-Process, Where-Object

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Prozess starten
