# Steckbrief: tech_020_DiscordCapper.ps1

- SHA256: `7b70da8310eaaa73aeb3dcfda1289de4b90c9f20651b1f8b0c2a5fdba4d06025`
- Groesse: 4426 Bytes, 133 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 15 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Application/Json`
  - `username`
  - `content`
  - `
using System;
using System.Runtime.InteropServices;

public class Keyboard {
    [DllImport(`
  - `)]
    public static extern void keybd_event(byte virtualKey, byte scanCode, uint flags, IntPtr extraInfo);
}
`
  - `$env:LOCALAPPDATA\Discord\Update.exe`
  - `$env:ProgramFiles\Discord\Discord.exe`
  - `$env:ProgramFiles(x86)\Discord\Discord.exe`
  - `--processStart Discord.exe`
  - `$env:TEMP\screenshot1.png`
  - `$env:TEMP\screenshot2.png`
  - `$env:TEMP\screenshot3.png`
  - `$env:TEMP\screenshot4.png`
  - `Discord is not installed on this machine.`
  - `YOUR DISCORD WEBHOOK`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - webclient: 1
  - start_process: 1
  - add_type: 2
- Pfade: `$env:LOCALAPPDATA\Discord\Update.exe`, `$env:ProgramFiles`, `$env:ProgramFiles\Discord\Discord.exe`, `$env:TEMP\screenshot1.png`, `$env:TEMP\screenshot2.png`, `$env:TEMP\screenshot3.png`, `$env:TEMP\screenshot4.png`, `$env:username`
- Cmdlets: Add-Type, Get-Discord, Invoke-RestMethod, New-Object, Start-Process, Start-Sleep, Test-Path, Upload-Discord, Write-Output

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. WebClient erstellen
  2. Prozess starten
