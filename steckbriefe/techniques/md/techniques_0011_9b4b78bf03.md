# Steckbrief: tech_010_Convert-Base64.ps1

- SHA256: `9b4b78bf032f42fbd53080d0b1040a5fa9e37d5506c8560cec57b43059f5aef3`
- Groesse: 1064 Bytes, 32 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 4 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Enter the path of the file you want to convert`
  - `')

    if (-Not (Test-Path $filePath)) {
        Write-Host `
  - `
        return
    }

    $fileContent = Get-Content -Path $filePath -Raw
    
    try {
        [System.Text.En`
  - `
    } else {
        $encodedContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($fileCo`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 2
- Cmdlets: Get-Content, Read-Host, Set-Content, Test-Path, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
