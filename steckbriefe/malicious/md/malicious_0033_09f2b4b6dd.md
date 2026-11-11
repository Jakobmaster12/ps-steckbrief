# Steckbrief: 09f2b4b6ddb2f0311812bd06802a37f7b15c0b4160becc8287b6a6329ae31074.ps1

- SHA256: `09f2b4b6ddb2f0311812bd06802a37f7b15c0b4160becc8287b6a6329ae31074`
- Groesse: 68183 Bytes, 296 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 34 (Auszug unten)
- Base64-Bloecke gesamt: 3, davon dekodierbar: 0
- Strings (Auszug):
  - `
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("ker`
  - `);
    $KV = New-Object System.Collections.ArrayList

    foreach($Mz in $q) {
        if($Mz.Length -gt 1) {
     `
  - `
    $Z = ($Z[$Z.Length..0] -join(`
  - `)) -split(`
  - `) | ? {$_}
    $KV = New-Object System.Collections.ArrayList

    foreach($Mz in $zYY) {
        [void]$KV.Add($Psk `
  - `)

    $Tj = @{
        Size = `
  - `;
        Auth = $True;
        Method = `
  - `
    }

    $Eel = ($Tj.Size[2..0] + $Tj.Method[0]) -join(`
  - `)
    $eZa = (((`
  - `) + $Tj.Method[1] + $Tj.Size[3..4]) -join(`
  - `)) -replace(`
  - `)

    $iwg = [char[]]@(99, 110, 66, 117, 102, 101, 114)
    $Ts = $($Eel[0].ToString().ToUpper()) + $Eel[1..3] + $($`
  - `)

    $pJQ = haN ($Eel + $eZa)
    $VX = Cc $pJQ $Ts

    sdE $VX $Psk

    try{
        dsl $Psk $VX
        `
  - `kernel32.dll`
  - `user32.dll`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - start_process: 2
  - add_type: 2
  - registry_run: 2
  - char_array: 1
- Pfade: `$env:APPDATA`, `U:\Control`
- Cmdlets: Add-Type, Get-ChildItem, Get-Item, New-ItemProperty, New-Object, Remove-Item, Select-Object, Set-ItemProperty, Start-Process, Start-Sleep, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Registry-Autostart beruehren
  2. Prozess starten
