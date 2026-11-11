# Steckbrief: 09094ed7deb2b722d47c888b47bc8d71b33355e5052b6e42621e4e98642e7ea9.ps1

- SHA256: `09094ed7deb2b722d47c888b47bc8d71b33355e5052b6e42621e4e98642e7ea9`
- Groesse: 372087 Bytes, 43 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Hinweis: Analyse auf erste 200000 Bytes begrenzt
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 15 (Auszug unten)
- Base64-Bloecke gesamt: 1, davon dekodierbar: 0
- Strings (Auszug):
  - `)[-1].Equals(`
  - `) }).GetType(`
  - `)
	$var_gpa = $var_unsafe_native_methods.GetMethod(`
  - `, [Type[]] @(`
  - `string`
  - `GetModuleHandle`
  - `ReflectedDelegate`
  - `InMemoryModule`
  - `MyDelegateType`
  - `Class, Public, Sealed, AnsiClass, AutoClass`
  - `RTSpecialName, HideBySig, Public`
  - `Runtime, Managed`
  - `Invoke`
  - `Public, HideBySig, NewSlot, Virtual`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 1
  - reflection_assembly: 3
- Cmdlets: New-Object, Set-StrictMode, Where-Object

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
