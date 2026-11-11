# Steckbrief: 0749c57fa5774132e6218a35182fdb0d52a0f06fcd6d740dffa31342e43554eb.ps1

- SHA256: `0749c57fa5774132e6218a35182fdb0d52a0f06fcd6d740dffa31342e43554eb`
- Groesse: 3528 Bytes, 36 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 16 (Auszug unten)
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
  - `32ugx9PL6yMjI2JyYnNxcnVrEvFGa6hxQ2uocTtrqHEDa6hRc2sslGlpbhLqaxLjjx9CXyEPA2Li6i5iIuLBznFicmuocQOoYR9rIvNFols7KCFWUaijqyMj`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 1
  - reflection_assembly: 3
- Cmdlets: New-Object, Set-StrictMode, Where-Object

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
