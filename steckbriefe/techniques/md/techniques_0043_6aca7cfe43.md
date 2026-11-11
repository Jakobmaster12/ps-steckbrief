# Steckbrief: tech_042_Medium.ps1

- SHA256: `6aca7cfe430e2afd6833acade2b39a8c0763a4d7fee35783bab5b43ccf536ac5`
- Groesse: 711 Bytes, 32 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 10 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `In this world, those who seek to create find purpose, while those who seek to destroy find only emptiness.`
  - `$ba$bb$ac`
  - ` + $ab.Substring(46,1)
$1 = ([char]115)
$cb = $ii
$ca = $ab.Substring(10,1)
$bc = `
  - `
$ic = `
  - `
$i1 = `
  - `

$a = $i1
$ia = $ab.Substring(3,1);$ai = $ab.Substring(4,1);$bi = $ab.Substring(19,1)
$ci = $i + `
  - `
$c1 = `
  - `
$a1 = `
  - `
$b1 = `
  - `

$c = `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_expression: 1
  - char_array: 1
- Cmdlets: Invoke-Expression, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Zeichenkette als Code ausfuehren
