# Steckbrief: 03f7cc3cfda880c17d3339c63bc87ee4af3d75fff81ff104741dea04e1f9752a.ps1

- SHA256: `03f7cc3cfda880c17d3339c63bc87ee4af3d75fff81ff104741dea04e1f9752a`
- Groesse: 300159 Bytes, 90 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Hinweis: Analyse auf erste 200000 Bytes begrenzt
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 4 (Auszug unten)
- Base64-Bloecke gesamt: 2, davon dekodierbar: 0
- Strings (Auszug):
  - `C:\ProgramData\png`
  - `

Try{
function go {

param($COIN)$COIN = $COIN -split `
  - ` | ? { $_ }
ForEach ($chrome in $COIN){[Convert]::ToInt32($chrome,16)}}
}catch{}

Try{

[byte[]] $MyS  = go(`
  - `)

[byte[]] $RNP  = go(`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Pfade: `C:\ProgramData\png`
- Cmdlets: New-Item, Start-Sleep

## Stufe 3 - Struktur (zusaetzlich)
