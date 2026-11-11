# Steckbrief: tech_006_Ask AI.ps1

- SHA256: `6d7682ee9e4417aedcf464e8ea9f4a5ec63e0e84b88fb181eb089650566ba186`
- Groesse: 3394 Bytes, 109 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 28 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `YOUR API KEY`
  - `https://api.openai.com/v1/chat/completions`
  - `Authorization`
  - `Bearer $apiKey`
  - `Content-Type`
  - `application/json`
  - `

`nAsk-AI is a PowerShell function crafted to simplify troubleshooting within PowerShell.
Just type Ask-AI following a `
  - `
    $maxLength = ($lines | Measure-Object -Property Length -Maximum).Maximum

    $border = `
  - ` * $maxLength
    `
  - `
}

    if ($arg -eq `
  - `) {
        $showErrorInfo = $true
    } elseif ($arg -eq `
  - `) {
        $detailed = $true
    } elseif ($arg -eq `
  - `) {
        $showErrorInfo = $true
        $detailed = $true
    } elseif ($arg -eq `
  - `) {
        $userInputMode = $true
    } elseif ($arg -eq `
  - ` -or $arg -eq `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://api.openai.com/v1/chat/completions`
- Cmdlets: Ask-AI, Content-Type, Create-TextBox, Invoke-RestMethod, Measure-Object, Read-Host, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
