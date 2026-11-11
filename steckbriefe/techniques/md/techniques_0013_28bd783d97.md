# Steckbrief: tech_012_Convert-Base64.ps1

- SHA256: `28bd783d9790a4b512ab2e87bdadd51fc7f40bec3ab679590213065ecb8358ad`
- Groesse: 1034 Bytes, 33 Zeilen
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
        [System.Text.Encoding]`
  - `
    } else {
        $encodedContent = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($fileCont`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 2
- Cmdlets: Get-Content, Read-Host, Set-Content, Test-Path, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
