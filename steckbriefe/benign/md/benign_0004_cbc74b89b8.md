# Steckbrief: benign_003_build-repo.ps1

- SHA256: `cbc74b89b8f145d01f15baa2acd9e43aa9095bd24112f8db07290bed1842c4a2`
- Groesse: 6820 Bytes, 187 Zeilen
- Ground-Truth-Label (aus Ordner): **benign**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 91 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `cmake .`
  - `ninja`
  - `$PWD`
  - `$path`
  - `$path/CMakeLists.txt`
  - `⏳ (1/3) Configuring CMake by executing 'cmake .'...`
  - `win64`
  - `$path/_$($architecture)_builds/`
  - `Executing 'cmake ..' failed with exit code $lastExitCode`
  - `⏳ (2/3) Building $dirName by executing 'make'...`
  - `Executing 'make' failed with exit code $lastExitCode`
  - `⏳ (3/3) Testing $dirName by executing 'ctest -V'... (if tests are provided)`
  - `Executing 'ctest -V' failed with exit code $lastExitCode`
  - `$path/.cargo/release.toml`
  - `⏳ Building '$dirName' by executing 'cargo build'...`

## Stufe 2 - Statische Merkmale (zusaetzlich)
- URLs: `https://github.com/fleschutz/PowerShell`
- Pfade: `C:\Repos\ninja`, `C:\Repos\ninja\_x86_64_builds`
- Cmdlets: Get-Item, Get-Location, Set-Location, Test-Path, Write-Host, Write-Warning

## Stufe 3 - Struktur (zusaetzlich)
