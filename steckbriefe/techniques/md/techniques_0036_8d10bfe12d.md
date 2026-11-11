# Steckbrief: tech_035_github_crawler.ps1

- SHA256: `8d10bfe12d9e392f6a402046d1d227ba5eb737165fe477f1343f795c012c3433`
- Groesse: 3345 Bytes, 90 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 20 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Enter the GitHub username`
  - `https://api.github.com/users/$username/repos`
  - `GitHubRepos.txt`
  - `Invoke-RestMethod`
  - `GitHub has rate limited your IP address. Try switching IP addresses or waiting for a period.`
  - `Press Enter to continue`
  - `An error occurred: $responseMessage`
  - `If GitHub has rate limited your IP address. Try switching IP addresses or waiting for a period.`
  - `An error occurred: $($_.Exception.Message)`
  - `\{\+path\}`
  - `
        $repoContents = Invoke-RestMethod -Uri $contentsUrl

        # Append subdirectories, sub-repos, or files UR`
  - ` -match `
  - `next`
  - `$prefix $($nestedContent.html_url)`
  - `dir`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://api`, `https://api.github.com/users/$username/repos`
- Cmdlets: Fetch-Content, Fetch-Repos, Invoke-RestMethod, Out-File, Read-Host, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
