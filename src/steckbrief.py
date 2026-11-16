#!/usr/bin/env python3
"""
steckbrief.py - Statischer Extraktor fuer PowerShell-Skripte (Version 2)

Zweck (Masterarbeit, Incident-Response-Kontext):
  Erzeugt pro Skript einen Steckbrief: eine Liste von Fakten, die sich exakt
  BERECHNEN lassen. Der Extraktor dekodiert, entpackt und setzt zusammen, was
  ein Sprachmodell nur raten koennte. Er URTEILT NICHT.

Was er berechnet:
  - Kommentare, Code und String-Literale trennen (eigener Lexer)
  - Verschleierung aufloesen: Backticks, Konkatenation, [char]-Codes,
    Format-Operator -f, .Replace()/-replace, -join, umgedrehte Strings
  - Schichten auspacken: Base64, Hex, Byte-Listen, gzip, zlib, Deflate,
    XOR mit im Skript sichtbarem Schluessel, auch ineinander verschachtelt
  - Indikatoren vollstaendig auflisten (URLs, IPv4, Pfade, Registry, Cmdlets,
    auffaellige Tokens) und fuer jeden Fund festhalten, AB WANN er sichtbar ist
    (original, nur Kommentar, nach Deobfuskation, Schicht Sn)
  - Entropie, Blob-Kennungen (z.B. PE-Datei), auffaellige Zeilen mit Parametern

WICHTIG: Das Skript FUEHRT NICHTS AUS. Es liest Bytes und rechnet.
Alle Regeln sind ASCII-basiert, damit Python- und Browser-Fassung
(tool/steckbrief-werkbank.html) exakt dasselbe Ergebnis liefern.

Aufruf:
  python3 steckbrief.py <datei_oder_ordner> --out <ausgabeordner> [--label <text>]
"""

import argparse
import hashlib
import json
import math
import re
import sys
import zlib
from pathlib import Path

VERSION = "2.0.0"
MAX_CHARS = 200_000        # Analysegrenze je Text (Zeichen)
MAX_DECOMP = 2_000_000     # Obergrenze fuer entpackte Daten (Bytes)
MAX_DEPTH = 4              # maximale Verschachtelung von Schichten
MAX_LAYERS = 20
MAX_BLOBS_PER_TEXT = 40
HINWEIS = "Kein Urteil enthalten. Bewertung erfolgt durch das LLM."

F = re.ASCII | re.IGNORECASE
WSC = " \t\r\n\f\v"
WS = "[ \\t\\r\\n\\f\\v]"
NUM = "(?:0x[0-9a-f]{1,4}|[0-9]{1,5})"
L = "\x01([0-9]+)\x02"                     # Platzhalter eines String-Literals im Skelett
LN = "\x01[0-9]+\x02"

# ---------------------------------------------------------------------------
# Auffaellige Tokens. Neutrale Beobachtungen ("kommt vor"), keine Wertung.
# PowerShell unterscheidet keine Gross-/Kleinschreibung, die Regeln auch nicht.
_ENC_LANG = "|".join(sorted(("encodedcommand"[:k] for k in range(3, 15)), key=len, reverse=True))
ENC_PARAM = r"(?<![\w-])-(?:" + _ENC_LANG + r")(?![\w-])"
ENC_KURZ = r"(?<![\w-])-(?:ec|en|e)(?=" + WS + r"+['\"]?[A-Za-z0-9+/]{16})"
TOKENS = [
    ("invoke_expression",   r"(?<![\w-])(?:iex|invoke-expression)(?![\w-])"),
    ("invoke_command",      r"(?<![\w-])(?:icm|invoke-command)(?![\w-])"),
    ("encodedcommand",      ENC_PARAM + "|" + ENC_KURZ),
    ("frombase64",          r"frombase64string"),
    ("downloadstring",      r"downloadstring"),
    ("downloadfile",        r"downloadfile"),
    ("downloaddata",        r"downloaddata"),
    ("webclient",           r"net\.webclient"),
    ("invoke_webrequest",   r"(?<![\w-])(?:invoke-webrequest|iwr|wget|curl)(?![\w-])"),
    ("invoke_restmethod",   r"(?<![\w-])(?:invoke-restmethod|irm)(?![\w-])"),
    ("bitstransfer",        r"start-bitstransfer|bitsadmin"),
    ("tcpclient",           r"net\.sockets\.tcpclient|net\.sockets\.socket"),
    ("executionpolicy_bypass", r"-e(?:p|x|xec|xecutionpolicy)" + WS + r"+(?:bypass|unrestricted)"),
    ("window_hidden",       r"-w(?:in|indowstyle)?" + WS + r"+(?:hidden|1)(?![\w-])"),
    ("noprofile",           r"(?<![\w-])-nop(?:rofile)?(?![\w-])"),
    ("noninteractive",      r"(?<![\w-])-noni(?:nteractive)?(?![\w-])"),
    ("start_process",       r"(?<![\w-])start-process(?![\w-])|diagnostics\.process\]::start"),
    ("wscript_shell",       r"wscript\.shell|shell\.application"),
    ("lolbin",              r"(?<![\w-])(?:mshta|rundll32|regsvr32|certutil|cmstp|msiexec|wmic)(?:\.exe)?(?![\w-])"),
    ("reflection_load",     r"reflection\.assembly|\[appdomain\]|assembly\]::load"),
    ("add_type",            r"(?<![\w-])add-type(?![\w-])"),
    ("native_memory",       r"virtualalloc|virtualprotect|createthread|writeprocessmemory|getdelegateforfunctionpointer|marshal\]::copy"),
    ("compression",         r"gzipstream|deflatestream|io\.compression"),
    ("memorystream",        r"io\.memorystream"),
    ("xor",                 r"-bxor(?![\w-])"),
    ("securestring",        r"convertto-securestring|securestringtobstr|cryptography\.aes|rijndaelmanaged"),
    ("amsi",                r"amsi(?:initfailed|context|utils|scanbuffer)?"),
    ("defender_settings",   r"set-mppreference|add-mppreference|disablerealtimemonitoring"),
    ("etw_logging",         r"scriptblocklogging|etweventwrite|eventprovider"),
    ("registry_run",        r"currentversion\\run"),
    ("scheduled_task",      r"schedule\.service|register-scheduledtask|new-scheduledtask|schtasks"),
    ("new_service",         r"(?<![\w-])new-service(?![\w-])|sc(?:\.exe)?" + WS + r"+create"),
    ("wmi",                 r"(?<![\w-])(?:get-wmiobject|gwmi|invoke-wmimethod|get-ciminstance|invoke-cimmethod)(?![\w-])"),
    ("credentials",         r"get-credential|mimikatz|sekurlsa|lsass|credentialcache|net\.networkcredential"),
    ("eventlog_clear",      r"clear-eventlog|wevtutil" + WS + r"+cl|remove-eventlog"),
    ("shadow_copies",       r"vssadmin|shadowcopy|wbadmin"),
    ("firewall",            r"-netfirewallrule|netsh" + WS + r"+(?:adv)?firewall"),
    ("char_cast",           r"\[char\]"),
]
STARKE_TOKENS = [
    "invoke_expression", "encodedcommand", "frombase64", "downloadstring", "downloadfile",
    "downloaddata", "window_hidden", "reflection_load", "native_memory", "amsi",
    "defender_settings", "eventlog_clear", "shadow_copies", "credentials",
]
ABFOLGE = [
    ("frombase64",        "Base64-Inhalt dekodieren"),
    ("compression",       "Daten entpacken"),
    ("encodedcommand",    "kodierten Befehl ausführen"),
    ("webclient",         "WebClient erstellen"),
    ("downloadstring",    "Inhalt von URL laden"),
    ("downloadfile",      "Datei von URL herunterladen"),
    ("downloaddata",      "Daten von URL laden"),
    ("invoke_webrequest", "Web-Anfrage senden"),
    ("invoke_restmethod", "REST-Anfrage senden"),
    ("tcpclient",         "TCP-Verbindung aufbauen"),
    ("invoke_expression", "Zeichenkette als Code ausführen"),
    ("reflection_load",   "Assembly im Speicher laden"),
    ("native_memory",     "Speicherfunktionen der Windows-API ansprechen"),
    ("start_process",     "Prozess starten"),
    ("registry_run",      "Registry-Autostart berühren"),
    ("scheduled_task",    "geplante Aufgabe ansprechen"),
    ("new_service",       "Dienst anlegen"),
    ("defender_settings", "Defender-Einstellung ändern"),
    ("amsi",              "AMSI ansprechen"),
    ("eventlog_clear",    "Ereignisprotokoll leeren"),
    ("shadow_copies",     "Schattenkopien ansprechen"),
]
VERBS = (
    "add approve assert backup block build checkpoint clear close compare complete compress confirm "
    "connect convert convertfrom convertto copy debug deny deploy disable disconnect dismount edit "
    "enable enter exit expand export find foreach format get grant group hide import initialize "
    "install invoke join limit lock measure merge mount move new open optimize out ping pop protect "
    "publish push read receive redo register remove rename repair request reset resize resolve "
    "restart restore resume revoke save search select send set show skip sort split start step stop "
    "submit suspend switch sync tee test trace unblock undo uninstall unlock unprotect unpublish "
    "unregister update use wait watch where write"
).split()

NOQ = "[^ \\t\\r\\n\\f\\v'\"<>|`]"
RE_TOKENS = [(n, re.compile(p, F)) for n, p in TOKENS]
RE_CMDLET = re.compile(r"(?<![\w-])((?:" + "|".join(VERBS) + r")-[a-z][a-z0-9]+)(?![\w-])", F)
RE_URL = re.compile(r"(?:https?|ftp)://[^ \t\r\n\f\v'\"\\)>}<`\x01-\x04]+", F)
OCT = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
RE_IPV4 = re.compile(r"(?<![0-9.])(?:" + OCT + r"\.){3}" + OCT + r"(?![0-9.])", re.ASCII)
RE_PATH = re.compile(
    r"(?<![a-z0-9])[a-z]:\\" + NOQ + r"+"
    r"|\$env:[a-z_]+(?:\\" + NOQ + r"+)?"
    r"|%[a-z_]+%(?:\\" + NOQ + r"*)?"
    r"|\\\\[a-z0-9._-]+\\" + NOQ + r"+", F)
RE_REG = re.compile(r"(?<![a-z0-9_])(?:hklm|hkcu|hkcr|hku|hkcc|hkey_[a-z_]+):?\\" + NOQ + r"+", F)
RE_B64 = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}", re.ASCII)
RE_ENC_ARG = re.compile(r"(?:" + ENC_PARAM + "|" + ENC_KURZ + r")" + WS + r"+['\"]?([A-Za-z0-9+/]{8,}={0,2})", F)
BYTE = "(?:0x[0-9a-f]{1,2}|[0-9]{1,3})"
RE_BYTELIST = re.compile(r"(?<![\w.])" + BYTE + r"(?:" + WS + r"*," + WS + r"*" + BYTE + r"){7,}(?![\w.])", F)
RE_XORKEY = re.compile(r"-bxor" + WS + r"*\(?" + WS + r"*(0x[0-9a-f]{1,2}|[0-9]{1,3})(?![0-9a-fx])", F)
RE_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$", re.ASCII)
REV_KEYWORDS = ["http://", "https://", "invoke-expression", "downloadstring", "frombase64string",
                "powershell", "new-object", "net.webclient"]

# Deobfuskations-Regeln auf dem Skelett (String-Literale sind Platzhalter)
RE_CHARARR = re.compile(r"(?:\[string\]" + WS + r"*)?\[char\[\]\]" + WS + r"*\(?" + WS + r"*(" + NUM +
                        r"(?:" + WS + r"*," + WS + r"*" + NUM + r")*)" + WS + r"*\)?", F)
RE_CHAR = re.compile(r"\[char\]" + WS + r"*(?:\(" + WS + r"*(" + NUM + r")" + WS + r"*\)|(" + NUM + r"))(?![0-9a-fx])", F)
RE_PAREN = re.compile(r"(?<![\w\]\.\x02])\(" + WS + r"*" + L + WS + r"*\)", F)
RE_FORMAT = re.compile(L + WS + r"*-f" + WS + r"*(" + LN + r"(?:" + WS + r"*," + WS + r"*" + LN + r")*)", F)
RE_CONCAT = re.compile(L + WS + r"*\+" + WS + r"*" + L, F)
RE_REPLACE_M = re.compile(L + WS + r"*\." + WS + r"*replace" + WS + r"*\(" + WS + r"*" + L + WS + r"*," + WS + r"*" + L + WS + r"*\)", F)
RE_REV = (L + WS + r"*\[" + WS + r"*-" + WS + r"*1" + WS + r"*\.\." + WS + r"*-" + WS + r"*\(?" + WS +
          r"*(?:([0-9]{1,6})|" + LN + WS + r"*\." + WS + r"*length)" + WS + r"*\)?" + WS + r"*\]")
RE_REV_UN = re.compile(r"-join" + WS + r"*\(?" + WS + r"*" + RE_REV + WS + r"*\)?", F)
RE_REV_BIN = re.compile(r"\(?" + WS + r"*" + RE_REV + WS + r"*\)?" + WS + r"*-join" + WS + r"*" + LN, F)
RE_JOIN_BIN = re.compile(r"\(?" + WS + r"*(" + LN + r"(?:" + WS + r"*," + WS + r"*" + LN + r")+)" + WS + r"*\)?" + WS + r"*-join" + WS + r"*" + L, F)
RE_JOIN_UN = re.compile(r"(^|[^\x02\)\]\w \t\r\n\f\v])(" + WS + r"*)-join" + WS + r"*\(" + WS + r"*(" + LN +
                        r"(?:" + WS + r"*," + WS + r"*" + LN + r")*)" + WS + r"*\)", F)
RE_REPLACE_OP = re.compile(L + WS + r"*-(c|i)?replace" + WS + r"*" + L + WS + r"*," + WS + r"*" + L, F)
RE_LIT = re.compile(L, re.ASCII)
RE_ANYLIT = re.compile("[\x01\x03]([0-9]+)[\x02\x04]", re.ASCII)
RE_FMT_ITEM = re.compile(r"\{([0-9]{1,3})\}", re.ASCII)
REGEX_META = set("\\^$.|?*+()[]{}")


# ---------------------------------------------------------------------------
# Hilfsfunktionen (bewusst ohne Unicode-Tabellen, damit portierbar)
def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strip_ws(s: str) -> str:
    return s.strip(WSC)


def ascii_lower(s: str) -> str:
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def entropy(data: bytes) -> str:
    if not data:
        return "0.00"
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return "%.2f" % h


RE_ASTRAL = re.compile("[\U00010000-\U0010FFFF]")


def bmp_only(text: str) -> str:
    """Zeichen ausserhalb der BMP (z.B. Emoji) -> U+FFFD. So zaehlen Python und
    JavaScript Zeichen gleich, und Positionen stimmen in beiden Fassungen ueberein."""
    return RE_ASTRAL.sub("\ufffd", text)


def utf16le_to_str(data: bytes) -> str:
    """UTF-16LE von Hand, jede Einheit ein Zeichen, Surrogate -> U+FFFD."""
    out = []
    for i in range(len(data) // 2):
        u = data[2 * i] | (data[2 * i + 1] << 8)
        out.append("\ufffd" if 0xD800 <= u <= 0xDFFF else chr(u))
    return "".join(out)


def decode_file(data: bytes) -> str:
    if data[:2] == b"\xff\xfe":
        return utf16le_to_str(data[2:])
    if data[:2] == b"\xfe\xff":
        swapped = bytearray(data[2:len(data) - (len(data) % 2)])
        swapped[0::2], swapped[1::2] = swapped[1::2], swapped[0::2]
        return utf16le_to_str(bytes(swapped))
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    return bmp_only(data.decode("utf-8", errors="replace"))


def ascii_ratio_ok(txt: str) -> bool:
    if not txt:
        return False
    good = 0
    for c in txt:
        o = ord(c)
        if 0x20 <= o <= 0x7E or o in (9, 10, 13):
            good += 1
    return good * 100 >= len(txt) * 85


def bytes_as_text(data: bytes):
    """Gibt (text, kodierung) zurueck, wenn die Bytes plausibler Text sind, sonst None."""
    n = len(data)
    if n >= 8 and n % 2 == 0:
        body = data[2:] if data[:2] == b"\xff\xfe" else data
        zeros = sum(1 for i in range(1, len(body), 2) if body[i] == 0)
        if zeros * 10 >= (len(body) // 2) * 6:
            txt = utf16le_to_str(body)
            if ascii_ratio_ok(txt):
                return txt, "utf-16le"
    body = data[3:] if data[:3] == b"\xef\xbb\xbf" else data
    try:
        txt = bmp_only(body.decode("utf-8", errors="strict"))
    except UnicodeDecodeError:
        return None
    if len(txt) >= 6 and ascii_ratio_ok(txt):
        return txt, "utf-8"
    return None


def inflate(data: bytes, wbits: int):
    """Entpackt genau einen vollstaendigen Strom. Sonst None."""
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(data, MAX_DECOMP + 1)
        if len(out) > MAX_DECOMP or not d.eof or d.unused_data or d.unconsumed_tail:
            return None
        return out
    except zlib.error:
        return None


def b64_bytes(blob: str):
    data = blob.rstrip("=")
    if len(data) % 4 == 1:
        return None
    try:
        import base64
        return base64.b64decode(data + "=" * (-len(data) % 4), validate=False)
    except Exception:
        return None


def magic_of(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE-Datei (MZ-Kopf)"
    if data[:4] == b"PK\x03\x04":
        return "ZIP-Archiv"
    if data[:4] == b"\x7fELF":
        return "ELF-Datei"
    if data[:4] == b"%PDF":
        return "PDF-Datei"
    if data[:4] == b"\xfc\x48\x83\xe4":
        return "beginnt mit FC 48 83 E4 (häufiger x64-Shellcode-Anfang)"
    if data[:2] == b"\xfc\xe8":
        return "beginnt mit FC E8 (häufiger x86-Shellcode-Anfang)"
    return ""


def ascii_strings(data: bytes):
    out, cur = [], []
    for b in data:
        if 0x20 <= b <= 0x7E:
            cur.append(chr(b))
        else:
            if len(cur) >= 6:
                out.append("".join(cur))
            cur = []
    if len(cur) >= 6:
        out.append("".join(cur))
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s[:120])
    return uniq[:20]


# ---------------------------------------------------------------------------
# Lexer: trennt Kommentare, Code und String-Literale
DQ_ESC = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b"}


class Lexed:
    def __init__(self):
        self.skeleton = ""      # Code, Literale als Platzhalter, ohne Kommentare und Backticks
        self.code = ""          # Originaltext ohne Kommentare
        self.comments = ""      # nur Kommentare
        self.lits = []          # {"v": Wert, "x": expandierbar, "raw": Originalschreibweise}
        self.ticks = 0


def lex(text: str) -> Lexed:
    text = re.sub("[\x01-\x04]", " ", text)
    r = Lexed()
    sk, code, com = [], [], []
    n, i = len(text), 0

    def add_lit(value, expandable, raw):
        r.lits.append({"v": value, "x": expandable, "raw": raw})
        idx = len(r.lits) - 1
        sk.append(("\x03%d\x04" if expandable else "\x01%d\x02") % idx)
        code.append(raw)

    while i < n:
        c = text[i]
        if c == "<" and text.startswith("<#", i):
            j = text.find("#>", i + 2)
            j = n if j < 0 else j + 2
            com.append(text[i:j]); com.append("\n")
            sk.append(" "); code.append(" ")
            i = j
            continue
        if c == "#" and (i == 0 or text[i - 1] in " \t\r\n\f\v;(){}|"):
            j = i
            while j < n and text[j] not in "\r\n":
                j += 1
            com.append(text[i:j]); com.append("\n")
            i = j
            continue
        if c == "@" and i + 1 < n and text[i + 1] in "'\"":
            q = text[i + 1]
            k = text.find("\n", i + 2)
            if k >= 0 and text[i + 2:k].strip(" \t\r") == "":
                e = text.find("\n" + q + "@", k)
                if e >= 0:
                    value = text[k + 1:e] if e > k else ""
                    if value.endswith("\r"):
                        value = value[:-1]
                    add_lit(value, q == '"' and "$" in value, text[i:e + 3])
                    i = e + 3
                    continue
        if c == "'":
            j, buf, closed = i + 1, [], False
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        buf.append("'"); j += 2
                        continue
                    closed = True
                    break
                buf.append(text[j]); j += 1
            if closed:
                add_lit("".join(buf), False, text[i:j + 1])
                i = j + 1
                continue
        if c == '"':
            j, buf, closed, expandable = i + 1, [], False, False
            while j < n:
                d = text[j]
                if d == "`" and j + 1 < n:
                    buf.append(DQ_ESC.get(text[j + 1], text[j + 1])); j += 2
                    continue
                if d == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        buf.append('"'); j += 2
                        continue
                    closed = True
                    break
                if d == "$" and j + 1 < n and (text[j + 1] in "({_" or ("a" <= ascii_lower(text[j + 1]) <= "z")):
                    expandable = True
                buf.append(d); j += 1
            if closed:
                add_lit("".join(buf), expandable, text[i:j + 1])
                i = j + 1
                continue
        if c == "`" and i + 1 < n:
            code.append(c)
            if text[i + 1] in "\r\n":
                sk.append(" ")
            else:
                r.ticks += 1
            i += 1
            continue
        sk.append(c); code.append(c)
        i += 1
    r.skeleton = "".join(sk)
    r.code = "".join(code)
    r.comments = "".join(com)
    return r


# ---------------------------------------------------------------------------
# Deobfuskation auf dem Skelett
def num_value(s: str) -> int:
    s = ascii_lower(s)
    return int(s[2:], 16) if s.startswith("0x") else int(s)


def replace_ci_ascii(hay: str, needle: str, repl: str) -> str:
    h, nd = ascii_lower(hay), ascii_lower(needle)
    out, i, ln = [], 0, len(needle)
    while True:
        j = h.find(nd, i)
        if j < 0:
            out.append(hay[i:])
            return "".join(out)
        out.append(hay[i:j]); out.append(repl)
        i = j + ln


def deobfuscate(lx: Lexed):
    """Loest Verschleierung rein rechnerisch auf. Gibt (skelett, zaehler) zurueck."""
    lits = lx.lits
    cnt = {"backticks": lx.ticks, "char_codes": 0, "format_operator": 0, "konkatenation": 0,
           "replace": 0, "join": 0, "umgedreht": 0}

    def new(value):
        lits.append({"v": value, "x": False, "raw": None})
        return "\x01%d\x02" % (len(lits) - 1)

    def val(idx):
        return lits[int(idx)]["v"]

    def ids(s):
        return [m.group(1) for m in RE_LIT.finditer(s)]

    def chars_of(numbers):
        out = []
        for m in re.finditer(NUM, numbers, F):
            v = num_value(m.group(0))
            if v > 0xFFFF or 0xD800 <= v <= 0xDFFF:
                return None
            out.append(chr(v))
        return "".join(out)

    def r_chararr(m):
        s = chars_of(m.group(1))
        if s is None:
            return m.group(0)
        cnt["char_codes"] += 1
        return new(s)

    def r_char(m):
        s = chars_of(m.group(1) or m.group(2))
        if s is None:
            return m.group(0)
        cnt["char_codes"] += 1
        return new(s)

    def r_format(m):
        tpl, args = val(m.group(1)), [val(x) for x in ids(m.group(2))]
        rest = RE_FMT_ITEM.sub("", tpl)
        idxs = [int(x) for x in RE_FMT_ITEM.findall(tpl)]
        if "{" in rest or "}" in rest or not idxs or max(idxs) >= len(args):
            return m.group(0)
        cnt["format_operator"] += 1
        return new(RE_FMT_ITEM.sub(lambda t: args[int(t.group(1))], tpl))

    def r_concat(m):
        cnt["konkatenation"] += 1
        return new(val(m.group(1)) + val(m.group(2)))

    def r_replace_m(m):
        s, a, b = val(m.group(1)), val(m.group(2)), val(m.group(3))
        if a == "":
            return m.group(0)
        cnt["replace"] += 1
        return new(s.replace(a, b))

    def r_rev(m):
        s = val(m.group(1))
        k = int(m.group(2)) if m.group(2) else len(s)
        cnt["umgedreht"] += 1
        return new(s[::-1][:k])

    def r_join_bin(m):
        cnt["join"] += 1
        return new(val(m.group(2)).join(val(x) for x in ids(m.group(1))))

    def r_join_un(m):
        cnt["join"] += 1
        return m.group(1) + m.group(2) + new("".join(val(x) for x in ids(m.group(3))))

    def r_replace_op(m):
        s, a, b = val(m.group(1)), val(m.group(3)), val(m.group(4))
        if a == "" or "$" in b or any(ch in REGEX_META for ch in a):
            return m.group(0)
        cnt["replace"] += 1
        if ascii_lower(m.group(2) or "") == "c":
            return new(s.replace(a, b))
        return new(replace_ci_ascii(s, a, b))

    sk = lx.skeleton
    for _ in range(40):
        before = sk
        for _ in range(40):
            inner = sk
            sk = RE_CHARARR.sub(r_chararr, sk)
            sk = RE_CHAR.sub(r_char, sk)
            sk = RE_PAREN.sub(lambda m: "\x01" + m.group(1) + "\x02", sk)
            sk = RE_REPLACE_M.sub(r_replace_m, sk)
            sk = RE_REV_UN.sub(r_rev, sk)
            sk = RE_REV_BIN.sub(r_rev, sk)
            sk = RE_JOIN_UN.sub(r_join_un, sk)
            sk = RE_FORMAT.sub(r_format, sk)
            sk = RE_CONCAT.sub(r_concat, sk)
            if sk == inner:
                break
        # Operatoren mit niedrigerem Vorrang erst, wenn der Rest stabil ist
        sk = RE_JOIN_BIN.sub(r_join_bin, sk)
        sk = RE_REPLACE_OP.sub(r_replace_op, sk)
        if sk == before:
            break
    return sk, cnt


def render(sk: str, lits) -> str:
    def rep(m):
        lit = lits[int(m.group(1))]
        if lit["raw"] is not None and lit["x"]:
            return lit["raw"]
        return "'" + lit["v"].replace("'", "''") + "'"
    return RE_ANYLIT.sub(rep, sk)


def used_literals(sk: str, lits):
    return [lits[int(m.group(1))]["v"] for m in RE_ANYLIT.finditer(sk)]


# ---------------------------------------------------------------------------
# Scanner fuer Indikatoren
TRAIL = ".,;:)]}'\""


def clean(s: str) -> str:
    return s.rstrip(TRAIL)


def scan(text: str) -> dict:
    tokens = {}
    for name, rx in RE_TOKENS:
        c = len(rx.findall(text))
        if c:
            tokens[name] = c
    cm = {}
    for m in RE_CMDLET.finditer(text):
        cm.setdefault(ascii_lower(m.group(1)), m.group(1))
    return {
        "tokens": tokens,
        "cmdlets": cm,
        "urls": {clean(m.group(0)): 1 for m in RE_URL.finditer(text)},
        "ipv4": {m.group(0): 1 for m in RE_IPV4.finditer(text)},
        "pfade": {clean(m.group(0)): 1 for m in RE_PATH.finditer(text)},
        "registry": {clean(m.group(0)): 1 for m in RE_REG.finditer(text)},
    }


def token_windows(text: str, quelle: str, out: list, seen: set):
    hits = []
    for _, rx in RE_TOKENS:
        for m in rx.finditer(text):
            hits.append(m.start())
    hits.sort()
    last_end = -1
    for pos in hits:
        if pos < last_end or len(out) >= 30:
            continue
        a = max(text.rfind("\n", 0, pos) + 1, pos - 120)
        e = text.find("\n", pos)
        e = len(text) if e < 0 else e
        e = min(e, pos + 160)
        last_end = e
        line = strip_ws(re.sub(WS + "+", " ", text[a:e]))
        if line and line not in seen:
            seen.add(line)
            out.append({"quelle": quelle, "zeile": line})


# ---------------------------------------------------------------------------
# Schichten auspacken
class Analysis:
    def __init__(self):
        self.layers = []          # Schichten fuer die Ausgabe
        self.levels = []          # [(name, scan-ergebnis)] in Sichtbarkeits-Reihenfolge
        self.zeilen = []
        self.zeilen_seen = set()
        self.seen_text = set()
        self.seen_blob = set()
        self.deob_counts = {}
        self.xor_count = 0


def find_blobs(deob: str, sk: str, lit_values):
    """Kandidaten fuer kodierte Daten: [(art, text)] in Fundreihenfolge, ohne Dubletten."""
    out, seen = [], set()

    def add(kind, s):
        if (kind, s) not in seen and len(out) < MAX_BLOBS_PER_TEXT:
            seen.add((kind, s))
            out.append((kind, s))

    for m in RE_ENC_ARG.finditer(deob):
        add("b64", m.group(1))
    for src in [sk] + list(lit_values):
        for m in RE_B64.finditer(src):
            add("b64", m.group(0))
    for m in RE_BYTELIST.finditer(sk):
        add("bytes", m.group(0))
    return out


def blob_bytes(kind: str, s: str):
    if kind == "bytes":
        vals = [num_value(m.group(0)) for m in re.finditer(BYTE, s, F)]
        if any(v > 255 for v in vals):
            return None, None
        return bytes(vals), "byte-liste"
    if RE_HEX.match(s):
        return bytes.fromhex(s), "hex"
    b = b64_bytes(s)
    return (b, "base64") if b is not None else (None, None)


def classify(an: Analysis, data: bytes, chain: list, herkunft: str, xor_keys: list, depth: int):
    if len(an.layers) >= MAX_LAYERS or len(data) < 4:
        return
    if data[:3] == b"\x1f\x8b\x08":
        out = inflate(data, 31)
        if out is not None:
            return classify(an, out, chain + ["gzip"], herkunft, xor_keys, depth)
    if len(data) >= 2 and data[0] == 0x78 and data[1] in (0x01, 0x5E, 0x9C, 0xDA):
        out = inflate(data, 15)
        if out is not None:
            return classify(an, out, chain + ["zlib"], herkunft, xor_keys, depth)
    t = bytes_as_text(data)
    if t is not None:
        return add_text_layer(an, t[0], chain + [t[1]], herkunft, depth)
    if len(data) >= 16:
        out = inflate(data, -15)
        if out is not None and len(out) >= 8:
            return classify(an, out, chain + ["deflate"], herkunft, xor_keys, depth)
    for k in xor_keys:
        x = bytes(b ^ k for b in data)
        if bytes_as_text(x) is not None or x[:3] == b"\x1f\x8b\x08" or x[:2] == b"MZ":
            an.xor_count += 1
            return classify(an, x, chain + ["xor 0x%02x" % k], herkunft, [], depth)
    mg = magic_of(data)
    if len(data) >= 64 or mg:
        key = hashlib.sha256(data).hexdigest()
        if key in an.seen_blob:
            return
        an.seen_blob.add(key)
        an.layers.append({
            "id": "S%d" % (len(an.layers) + 1), "herkunft": herkunft, "kette": chain + ["binär"],
            "art": "binaer", "laenge": len(data), "entropie": entropy(data), "kennung": mg,
            "hex_anfang": data[:16].hex(), "strings_im_blob": ascii_strings(data),
        })


def add_text_layer(an: Analysis, text: str, chain: list, herkunft: str, depth: int):
    text = strip_ws(text)
    if len(text) < 4 or text in an.seen_text or len(an.layers) >= MAX_LAYERS:
        return
    an.seen_text.add(text)
    lid = "S%d" % (len(an.layers) + 1)
    layer = {"id": lid, "herkunft": herkunft, "kette": chain, "art": "text", "laenge": len(text),
             "entropie": entropy(text.encode("utf-8", errors="replace")),
             "inhalt": text[:1500], "inhalt_gekuerzt": len(text) > 1500}
    an.layers.append(layer)
    analyze_text(an, text[:MAX_CHARS], lid, depth + 1)


def analyze_text(an: Analysis, text: str, name: str, depth: int):
    lx = lex(text)
    sk, cnt = deobfuscate(lx)
    deob = render(sk, lx.lits)
    values = used_literals(sk, lx.lits)
    if name == "original":
        an.deob_counts = cnt
        an.main = (lx, sk, deob)
        an.levels.append(("original", scan(lx.code)))
        an.levels.append(("kommentar", scan(lx.comments)))
        an.levels.append(("deobfuskiert", scan(deob)))
        token_windows(deob, "skript", an.zeilen, an.zeilen_seen)
    else:
        merged = scan(lx.code + "\n" + lx.comments + "\n" + deob)
        an.levels.append((name, merged))
        token_windows(deob, name, an.zeilen, an.zeilen_seen)
    # umgedrehte String-Literale mit bekannten Schluesselwoertern
    for v in values:
        if 8 <= len(v) <= 4000:
            rv, low = v[::-1], ascii_lower(v)
            lrv = ascii_lower(rv)
            if any(k in lrv and k not in low for k in REV_KEYWORDS):
                add_text_layer(an, rv, ["umgedreht"], name, depth)
    if depth >= MAX_DEPTH:
        return
    keys = []
    for m in RE_XORKEY.finditer(lx.code + "\n" + deob):
        k = num_value(m.group(1))
        if 0 < k < 256 and k not in keys and len(keys) < 4:
            keys.append(k)
    for kind, s in find_blobs(deob, sk, values):
        data, how = blob_bytes(kind, s)
        if data is not None:
            classify(an, data, [how], name, keys, depth)


# ---------------------------------------------------------------------------
SICHT_ORDER = ["original", "kommentar", "deobfuskiert"]


def first_seen(levels, key):
    """Ordnet jeden Fund der ersten Ebene zu, in der er sichtbar ist."""
    out, seen = [], set()
    for name, res in levels:
        for value in res[key]:
            k = ascii_lower(value) if key == "cmdlets" else value
            if k not in seen:
                seen.add(k)
                out.append({"wert": res[key][value] if key == "cmdlets" else value, "sichtbar_in": name})
    out.sort(key=lambda d: (d["wert"]))
    return out


def build_steckbrief(name: str, data: bytes, label: str) -> dict:
    text_full = decode_file(data)
    text = text_full[:MAX_CHARS]
    an = Analysis()
    analyze_text(an, text, "original", 0)
    lx, sk, deob = an.main

    tokens, seen = [], set()
    for lname, res in an.levels:
        for tname, _ in TOKENS:
            if tname in res["tokens"] and tname not in seen:
                seen.add(tname)
                tokens.append({"name": tname, "anzahl": res["tokens"][tname], "sichtbar_in": lname})

    positions = []
    for key, beschreibung in ABFOLGE:
        m = dict(RE_TOKENS)[key].search(deob)
        if m:
            positions.append((m.start(), beschreibung))
    positions.sort()

    strings, sseen = [], set()
    for lit in lx.lits:
        if lit["raw"] is not None and len(lit["v"]) >= 3 and lit["v"] not in sseen:
            sseen.add(lit["v"])
            strings.append(lit["v"][:200])
    lines = text_full.split("\n")
    counts = dict(an.deob_counts)
    counts["xor"] = an.xor_count
    changed = any(counts.values())

    return {
        "meta": {
            "quelldatei": name,
            "sha256": sha256_of(data),
            "groesse_bytes": len(data),
            "ground_truth_label": label,
            "extraktor_version": VERSION,
            "analyse_gekuerzt": len(text_full) > MAX_CHARS,
            "hinweis": HINWEIS,
        },
        "ueberblick": {
            "zeilen": len(lines),
            "laengste_zeile": max(len(x) for x in lines),
            "entropie": entropy(data),
            "kommentar_anteil_prozent": (len(lx.comments) * 100) // max(len(text), 1),
            "string_literale": len(strings),
            "schichten": len(an.layers),
        },
        "deobfuskation": {
            "schritte": counts,
            "auszug": deob[:2000] if changed else "",
        },
        "befunde": {
            "tokens": tokens,
            "urls": first_seen(an.levels, "urls")[:60],
            "ipv4": first_seen(an.levels, "ipv4")[:60],
            "pfade": first_seen(an.levels, "pfade")[:60],
            "registry": first_seen(an.levels, "registry")[:60],
            "cmdlets": first_seen(an.levels, "cmdlets")[:80],
        },
        "abfolge": [b for _, b in positions],
        "auffaellige_zeilen": an.zeilen,
        "schichten": an.layers,
        "strings": strings[:60],
    }


# ---------------------------------------------------------------------------
# Ausgabe als Text
SICHT_TEXT = {"original": "original", "kommentar": "nur Kommentar", "deobfuskiert": "nach Deobfuskation"}
SCHRITT_TEXT = [("backticks", "Backticks"), ("konkatenation", "Konkatenation"), ("char_codes", "Zeichencodes"),
                ("format_operator", "Format-Operator"), ("replace", "Replace"), ("join", "Join"),
                ("umgedreht", "umgedrehte Strings"), ("xor", "XOR")]


def sicht(s: str) -> str:
    return SICHT_TEXT.get(s, "Schicht " + s)


def body_lines(sb: dict) -> list:
    """Der Teil, den das LLM sieht. Ohne Meta: kein Label, kein Dateiname, kein Hash."""
    u, b, out = sb["ueberblick"], sb["befunde"], []
    out.append("## Überblick")
    out.append("- %d Zeilen, längste Zeile %d Zeichen, Entropie %s Bit/Byte, Kommentaranteil %d %%"
               % (u["zeilen"], u["laengste_zeile"], u["entropie"], u["kommentar_anteil_prozent"]))
    st = sb["deobfuskation"]["schritte"]
    teile = ["%s %d" % (t, st[k]) for k, t in SCHRITT_TEXT if st.get(k)]
    out.append("- Aufgelöste Verschleierung: " + (", ".join(teile) if teile else "keine der unterstützten Arten gefunden"))
    out.append("- Dekodierte Schichten: %d" % u["schichten"])
    out.append("")
    out.append("## Befunde (mit Angabe, ab wann sichtbar)")
    if b["tokens"]:
        out.append("Auffällige Tokens:")
        for t in b["tokens"]:
            out.append("- %s: %d (%s)" % (t["name"], t["anzahl"], sicht(t["sichtbar_in"])))
    else:
        out.append("Auffällige Tokens: keine")
    for key, titel in (("urls", "URLs"), ("ipv4", "IPv4"), ("pfade", "Pfade"), ("registry", "Registry"), ("cmdlets", "Cmdlets")):
        if b[key]:
            out.append(titel + ":")
            for x in b[key][:40]:
                out.append("- `%s` (%s)" % (x["wert"][:300], sicht(x["sichtbar_in"])))
        else:
            out.append(titel + ": keine")
    out.append("")
    if sb["abfolge"]:
        out.append("## Reihenfolge der ersten Fundstellen im Code")
        for i, s in enumerate(sb["abfolge"], 1):
            out.append("%d. %s" % (i, s))
        out.append("")
    if sb["auffaellige_zeilen"]:
        out.append("## Auffällige Zeilen (Ausschnitte nach Deobfuskation)")
        for z in sb["auffaellige_zeilen"]:
            out.append("- [%s] `%s`" % ("Skript" if z["quelle"] == "skript" else "Schicht " + z["quelle"], z["zeile"]))
        out.append("")
    if sb["schichten"]:
        out.append("## Dekodierte Schichten")
        for s in sb["schichten"]:
            kopf = "### %s: %s (aus %s)" % (s["id"], " → ".join(s["kette"]),
                                             "Skript" if s["herkunft"] == "original" else s["herkunft"])
            out.append(kopf)
            if s["art"] == "text":
                out.append("%d Zeichen%s" % (s["laenge"], ", gekürzt" if s["inhalt_gekuerzt"] else ""))
                out.append("```\n" + s["inhalt"] + "\n```")
            else:
                out.append("%d Bytes, Entropie %s Bit/Byte, Anfang (hex): %s" % (s["laenge"], s["entropie"], s["hex_anfang"]))
                if s["kennung"]:
                    out.append("Kennung: " + s["kennung"])
                if s["strings_im_blob"]:
                    out.append("Lesbare Zeichenketten im Blob: " + ", ".join("`%s`" % x for x in s["strings_im_blob"][:12]))
        out.append("")
    if sb["deobfuskation"]["auszug"]:
        out.append("## Code nach Deobfuskation (Auszug)")
        out.append("```\n" + sb["deobfuskation"]["auszug"] + "\n```")
        out.append("")
    if sb["strings"]:
        out.append("## String-Literale (Auszug)")
        for s in sb["strings"][:25]:
            out.append("- `%s`" % s[:120])
        out.append("")
    return out


def llm_text(sb: dict) -> str:
    return "\n".join(body_lines(sb)).rstrip("\n") + "\n"


def to_markdown(sb: dict) -> str:
    m, out = sb["meta"], []
    out.append("# Steckbrief: " + m["quelldatei"])
    out.append("")
    out.append("- SHA256: `%s`" % m["sha256"])
    out.append("- Größe: %d Bytes" % m["groesse_bytes"])
    out.append("- Ground-Truth-Label: **%s**" % m["ground_truth_label"])
    out.append("- Extraktor-Version: " + m["extraktor_version"])
    if m["analyse_gekuerzt"]:
        out.append("- Hinweis: Analyse auf die ersten %d Zeichen begrenzt" % MAX_CHARS)
    out.append("- " + m["hinweis"])
    out.append("")
    return "\n".join(out + body_lines(sb))


def to_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


def main():
    ap = argparse.ArgumentParser(description="Statischer Steckbrief-Extraktor (fuehrt nichts aus)")
    ap.add_argument("eingang", help="Datei oder Ordner mit Skripten")
    ap.add_argument("--out", required=True, help="Ausgabeordner")
    ap.add_argument("--label", default="unbekannt", help="Ground-Truth-Label (benign/malicious)")
    ap.add_argument("--limit", type=int, default=0, help="max. Anzahl Dateien (0 = alle)")
    args = ap.parse_args()

    eingang, out = Path(args.eingang), Path(args.out)
    for sub in ("json", "md", "llm"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    dateien = [eingang] if eingang.is_file() else sorted(
        p for p in eingang.rglob("*") if p.is_file() and p.suffix.lower() in (".ps1", ".psm1", ".txt"))
    if args.limit:
        dateien = dateien[:args.limit]

    manifest = []
    for i, p in enumerate(dateien, 1):
        try:
            sb = build_steckbrief(p.name, p.read_bytes(), args.label)
        except Exception as e:                      # ein kaputtes Sample darf den Lauf nicht stoppen
            print(f"  FEHLER bei {p.name}: {e!r}", file=sys.stderr)
            continue
        stem = f"{args.label}_{i:04d}_{sb['meta']['sha256'][:10]}"
        (out / "json" / f"{stem}.json").write_text(to_json(sb), encoding="utf-8")
        (out / "md" / f"{stem}.md").write_text(to_markdown(sb), encoding="utf-8")
        (out / "llm" / f"{stem}.txt").write_text(llm_text(sb), encoding="utf-8")
        manifest.append({"id": stem, "quelldatei": sb["meta"]["quelldatei"], "sha256": sb["meta"]["sha256"],
                         "label": args.label, "groesse_bytes": sb["meta"]["groesse_bytes"],
                         "extraktor_version": VERSION})
    (out / f"manifest_{args.label}.json").write_text(to_json(manifest), encoding="utf-8")
    print(f"{len(manifest)} Steckbriefe erzeugt -> {out}")


if __name__ == "__main__":
    main()
