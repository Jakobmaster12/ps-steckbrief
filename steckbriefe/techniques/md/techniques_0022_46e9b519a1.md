# Steckbrief: tech_021_PicturesDocumentsGrab.ps1

- SHA256: `46e9b519a18843fec86edb10f035515b8746735f8d9c64510229963391019f79`
- Groesse: 1581 Bytes, 34 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 18 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `CaliLoot`
  - `Authorization`
  - `Bearer $DropBoxAccessToken`
  - `Content-Type`
  - `application/json`
  - `{ "path": "/CaliLoot", "autorename": false }`
  - `MyDocuments`
  - `MyPictures`
  - `
        $folderName = $_ -replace `
  - `
        $targetPath = "/CaliLoot/$folderName"
        Copy-Item $sourcePath $TempFolderPath -Recurse -ErrorAction Silen`
  - `path`
  - `' + $targetFilePath + '`
  - `mode`
  - `add`
  - `autorename`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://api.dropboxapi.com/2/files/create_folder_v2`, `https://content.dropboxapi.com/2/files/upload`
- Pfade: `$env:TEMP`
- Cmdlets: Content-Type, Copy-Item, Dropbox-API, Get-ChildItem, Get-PicDoc, Invoke-RestMethod, Join-Path, Out-Null, Remove-Item

## Stufe 3 - Struktur (zusaetzlich)
