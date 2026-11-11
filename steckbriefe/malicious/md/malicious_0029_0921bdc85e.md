# Steckbrief: 0921bdc85effd18e3c467d28105458420febcab5e458f58fcee82914e5ca61c7.ps1

- SHA256: `0921bdc85effd18e3c467d28105458420febcab5e458f58fcee82914e5ca61c7`
- Groesse: 2742 Bytes, 98 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 26 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `

using System;

using System.Runtime.InteropServices;

public static class Sludrech1

{

[DllImport(`
  - `)]public static extern int NtAllocateVirtualMemory(int Sludrech6,ref Int32 VERSALERN,int Forbistrin,ref Int32 Sludrech,i`
  - `)]public static extern IntPtr CreateFileA(string Monstr,uint Melle8,int Nonpercep,int Sludrech0,int HABAN,int BAAN,int N`
  - `)]public static extern int ReadFile(int Forbistrin0,uint Forbistrin1,IntPtr Forbistrin2,ref Int32 Forbistrin3,int Forbis`
  - `)]public static extern IntPtr CallWindowProcW(IntPtr Forbistrin5,int Forbistrin6,int Forbistrin7,int Forbistrin8,int For`
  - `Hild3`
  - `Pierid`
  - `sekreter`
  - `$env:temp`
  - `\TRICA.dat`
  - `Carcharo`
  - `Overtrampl`
  - `Zeal9`
  - `Kalkvrk4`
  - `levefodend`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - add_type: 1
- Pfade: `$env:temp`
- Cmdlets: Add-Type, Test-Path

## Stufe 3 - Struktur (zusaetzlich)
