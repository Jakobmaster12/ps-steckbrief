# Steckbrief: tech_039_Meme.ps1

- SHA256: `d17e37134a3abc00721bd09638bd29df73632f18fd39324fb6f3bb659ed5870c`
- Groesse: 2183 Bytes, 62 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 7 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `YouHaveBeenDabbedOnGoodSir`
  - `$FP.meme`
  - `File encrypted successfully: $encryptedFilePath`
  - `.meme`
  - `)
    [System.IO.File]::WriteAllText($decryptedFilePath, $decryptedContent)
}

#$FP = `
  - `
#EF $FP
#DF `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 1
- Cmdlets: Get-Content, New-Object, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
