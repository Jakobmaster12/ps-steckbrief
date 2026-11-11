# Steckbrief: tech_001_brute7dtd.ps1

- SHA256: `f42b0767e6a62a6bcfc2cdf007286e89aa134457080a82dd026fbcb155286e57`
- Groesse: 2734 Bytes, 75 Zeilen
- Ground-Truth-Label (aus Ordner): **techniques**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 8 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `Go to 7DtD door you want to unlock and go to the 'Enter Code' screen and click OK.`
  - `Unlock Door`
  - `Hold CTRL for 3 seconds to stop.`
  - `Instruction`
  - `C:\Programming\#PythonScripts\Malware\Windows\WiFi Password Bruteforce\pass.txt`
  - `
using System;
using System.Runtime.InteropServices;

public class MouseActions {
    [DllImport(`
  - `, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
    public static extern void mouse_event(uin`
  - `{ENTER}`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - add_type: 5
- Pfade: `C:\Programming\#PythonScripts\Malware\Windows\WiFi`
- Cmdlets: Add-Type, Check-CtrlPressed, Get-Content, Get-Random, Mouse-ClickCenter, New-Object, Send-Keystroke, Start-Sleep

## Stufe 3 - Struktur (zusaetzlich)
