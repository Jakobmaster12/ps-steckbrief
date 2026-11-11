# Steckbrief: Invoke-ObfuscateRandomFiles.ps1

- SHA256: `ba4e1d443d7889773f2ae8f45942f66d41199d4c567ef58610850c855bfc6bfa`
- Groesse: 1437 Bytes, 28 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 16 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `-obf-$randomCommand`
  - `Executing '$randomCommand' for file: $file`
  - `$randomCommand -Path $sourcefilename > $newfilename`
  - `-------------------------------`
  - `Out-CompressedCommand`
  - `Out-EncodedAsciiCommand`
  - `Out-EncodedBinaryCommand`
  - `Out-EncodedBXORCommand`
  - `Out-EncodedHexCommand`
  - `Out-EncodedOctalCommand`
  - `Out-EncodedSpecialCharOnlyCommand`
  - `Out-EncodedWhitespaceCommand`
  - `Out-ObfuscatedAst`
  - `Out-ObfuscatedStringCommand`
  - `Out-ObfuscatedTokenCommand`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_expression: 1
- Cmdlets: Get-ChildItem, Get-Random, Invoke-Expression, Invoke-ObfuscateRandomFiles, Out-CompressedCommand, Out-EncodedAsciiCommand, Out-EncodedBXORCommand, Out-EncodedBinaryCommand, Out-EncodedHexCommand, Out-EncodedOctalCommand, Out-EncodedSpecialCharOnlyCommand, Out-EncodedWhitespaceCommand, Out-ObfuscatedAst, Out-ObfuscatedStringCommand, Out-ObfuscatedTokenCommand, Out-SecureStringCommand, Select-Object, Where-Object, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Zeichenkette als Code ausfuehren
