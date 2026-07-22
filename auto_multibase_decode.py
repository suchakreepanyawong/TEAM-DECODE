#!/usr/bin/env python3
"""TEAM-DECODE_compact.py - High-Performance Compact Multi-Layer Auto-Decoder.
Provides complete 100% decoding parity with TEAM-DECODE.py in a self-contained single file.
"""
from __future__ import annotations
import argparse, base64, binascii, bz2, gzip, hashlib, html, importlib.util, json, lzma, math, os, re, shutil, string, sys, textwrap, urllib.parse, zlib
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Iterable

if importlib.util.find_spec("zstandard") is not None:
    import zstandard as zstd
else:
    zstd = None

PRINTABLE = set(string.printable)
ENGLISH_LETTER_FREQ = {
    "e": 12.70, "t": 9.06, "a": 8.17, "o": 7.51, "i": 6.97, "n": 6.75, "s": 6.33, "h": 6.09, "r": 5.99,
    "d": 4.25, "l": 4.03, "c": 2.78, "u": 2.76, "m": 2.41, "w": 2.36, "f": 2.23, "g": 2.02, "y": 1.97,
    "p": 1.93, "b": 1.29, "v": 0.98, "k": 0.77, "j": 0.15, "x": 0.15, "q": 0.10, "z": 0.07
}

def _log_debug(msg: str) -> None:
    try:
        if os.environ.get("DEBUG_AUTO_DECODE"):
            print(msg, file=sys.stderr)
    except Exception:
        pass

def english_chi_squared(text: str) -> float | None:
    letters = [ch.lower() for ch in text if ch.isalpha()]
    n = len(letters)
    if n < 5: return None
    counts = Counter(letters)
    chi2 = 0.0
    for letter, expected_pct in ENGLISH_LETTER_FREQ.items():
        expected = expected_pct / 100.0 * n
        observed = counts.get(letter, 0)
        chi2 += (observed - expected) ** 2 / expected
    return chi2

COMMON_WORDS = ("the", "and", "you", "that", "hello", "world", "password", "secret", "http", "https", "admin", "root", "user", "hack", "pwn", "shell", "exploit", "payload", "firewall", "network", "intrusion")
COMMON_ENGLISH_WORDS = frozenset("""the be to of and a in that have i it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us is are was were been being am has had do does did doing done going gone come came coming go goes went get gets got getting say says said saying tell tells told telling ask asks asked asking need needs needed needing feel feels felt feeling become becomes became becoming leave leaves left leaving put puts putting mean means meant meaning keep keeps kept keeping let lets letting begin begins began beginning seem seems seemed seeming help helps helped helping show shows showed showing hear hears heard hearing play plays played playing run runs ran running move moves moved moving live lives lived living believe believes believed believing bring brings brought bringing happen happens happened happening write writes wrote writing provide provides provided providing sit sits sat sitting stand stands stood standing lose loses lost losing pay pays paid paying meet meets met meeting include includes included including continue continues continued continuing set sets setting learn learns learned learning change changes changed changing lead leads led leading understand understands understood understanding watch watches watched watching follow follows followed following stop stops stopped stopping create creates created creating speak speaks spoke speaking read reads reading allow allows allowed allowing add adds added adding spend spends spent spending grow grows grew growing open opens opened opening walk walks walked walking win wins won winning offer offers offered offering remember remembers remembered remembering love loves loved loving consider considers considered considering appear appears appeared appearing buy buys bought buying wait waits waited waiting serve serves served serving die dies died dying send sends sent sending expect expects expected expecting build builds built building stay stays stayed staying fall falls fell falling cut cuts cutting reach reaches reached reaching kill kills killed killing remain remains remained remaining suggest suggests suggested raise raises raised raising pass passes passed passing sell sells sold selling require requires required requiring report reports reported decide decides decided deciding pull pulls pulled pulling good new first last long great little own other old right big high different small large next early young important few public bad same able man woman child world school state family student group country problem hand part place case week company system program question work government number night point home water room mother area money story fact month lot right study book eye job word business issue side kind head house service friend father power hour game line end member law car city community name president team minute idea body information back parent face others level office door health person art war history party result change morning reason research girl guy moment air teacher force education network computer data file system code key secret password admin user root test layer login access token flag ctf secure hack pwn shell exploit payload firewall intrusion base decode encode chain sample example message value input output string number simple encoded encrypted hidden text unicode character alphabet standard multi single true false quick brown fox jumps jump over lazy dog dogs cat cats bird birds sun moon star stars sky blue red green yellow black white color colors love hate happy sad angry tired hungry thirsty run running walk walking tree trees flower flowers grass rain snow wind storm cloud clouds river lake ocean sea mountain mountains hill hills forest field fields farm animal animals plant plants fish fishes horse horses cow cows pig pigs sheep chicken chickens duck ducks fruit fruits apple apples orange oranges banana bananas bread milk water juice coffee tea food eat eats eating drink drinks drinking sleep sleeps sleeping wake wakes waking morning evening night noon today tomorrow yesterday week month year seashore seashells sells shore beach sand wave waves swim swimming together bring vigilance constant require requires security simple message test remember please nice sunny weather warm cold hot cool important learning things every day thing every own bag important""".split())

CTF_MARKER_WORDS = {"flag", "ctf", "picoctf", "htb"}
DICTIONARY_MIN_TOKENS, DICTIONARY_MAX_BONUS, DICTIONARY_MAX_PENALTY = 3, 4.0, 2.0
DICTIONARY_HIGH_RATIO, DICTIONARY_LOW_RATIO = 0.45, 0.12

def _dictionary_tokens(text: str) -> list[str]:
    return [tok.lower() for tok in re.findall(r"[A-Za-z']+", text) if len(tok) >= 3]

def dictionary_confidence_bonus(text: str) -> float:
    tokens = _dictionary_tokens(text)
    if len(tokens) < DICTIONARY_MIN_TOKENS: return 0.0
    known = sum(1 for tok in tokens if tok in COMMON_ENGLISH_WORDS or tok in CTF_MARKER_WORDS)
    ratio = known / len(tokens)
    if ratio >= DICTIONARY_HIGH_RATIO: return DICTIONARY_MAX_BONUS
    if ratio <= DICTIONARY_LOW_RATIO: return -DICTIONARY_MAX_PENALTY
    frac = (ratio - DICTIONARY_LOW_RATIO) / (DICTIONARY_HIGH_RATIO - DICTIONARY_LOW_RATIO)
    return -DICTIONARY_MAX_PENALTY + frac * (DICTIONARY_MAX_BONUS + DICTIONARY_MAX_PENALTY)

THAI_CHAR_RANGE = (0x0E00, 0x0E7F)
THAI_CHAR_MIN_RATIO, THAI_RATIO_BONUS_SCALE, THAI_WORD_BONUS_CAP = 0.3, 10.0, 5
THAI_COMMON_WORDS = ("และ", "คือ", "ที่", "ไม่", "เป็น", "การ", "ใน", "มี", "ได้", "จะ", "ว่า", "กับ", "ของ", "ให้", "มา", "ไป", "แล้ว", "นี้", "นั้น", "เขา", "ฉัน", "คุณ", "เรา", "ทำ", "พูด", "ดี", "วัน", "เวลา", "คน", "ธง", "ความลับ", "รหัส", "ทดสอบ", "ข้อความ")

def thai_char_ratio(text: str) -> float:
    if not text: return 0.0
    return sum(1 for ch in text if THAI_CHAR_RANGE[0] <= ord(ch) <= THAI_CHAR_RANGE[1]) / len(text)

def thai_confidence_bonus(text: str) -> float:
    ratio = thai_char_ratio(text)
    if ratio < THAI_CHAR_MIN_RATIO: return 0.0
    word_hits = sum(1 for word in THAI_COMMON_WORDS if word in text)
    return ratio * THAI_RATIO_BONUS_SCALE + min(word_hits, THAI_WORD_BONUS_CAP)

DEFAULT_MAX_DEPTH, DEFAULT_BEAM_SIZE, DEFAULT_CANDIDATE_COUNT = 15, 320, 5
MAX_CONSECUTIVE_SUBSTITUTION, MAX_TOTAL_SUBSTITUTION = 3, 3
ALWAYS_SUCCEEDS_STEP_PENALTY, FLAG_FOUND_OVERRIDE_BONUS = 2.0, 100.0

BASE36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
Z85_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
BASE91_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
BASE92_ALPHABET = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}"
BASE100_START, BASE100_END = 0x1F3F7, 0x1F4F6

@dataclass(frozen=True)
class Candidate:
    text: str
    chain: tuple[str, ...]
    score: float

def normalize_input(value: str) -> str:
    return value.strip().strip("'\"")

def bytes_to_text(raw: bytes) -> str | None:
    for encoding in ("utf-8", "latin-1"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if not text: continue
        if not mostly_binary(text) or thai_char_ratio(text) >= THAI_CHAR_MIN_RATIO:
            return text
    return None

def mostly_binary(text: str) -> bool:
    if not text: return True
    return (sum(1 for ch in text if ch not in PRINTABLE and ch not in "\n\r\t") / len(text)) > 0.15

def is_effectively_binary(text: str) -> bool:
    return mostly_binary(text) and thai_char_ratio(text) < THAI_CHAR_MIN_RATIO

def has_control_chars(text: str) -> bool:
    if not text: return True
    return (sum(1 for ch in text if not ch.isprintable() and ch not in "\n\r\t") / len(text)) > 0.15

def add_base64_padding(value: str) -> str:
    return value + ("=" * ((4 - len(value) % 4) % 4))

def decode_base2(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if not compact or len(compact) % 8 != 0 or not set(compact).issubset({'0', '1'}): return None
    try:
        return bytes_to_text(int(compact, 2).to_bytes(len(compact) // 8, byteorder='big'))
    except ValueError:
        return None

def decode_base16(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2 or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact): return None
    return bytes_to_text(bytes.fromhex(compact))

def decode_base32(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value).replace('-', '').replace('.', '').replace('_', '')
    if '%' in compact or '+' in compact:
        try:
            unq = urllib.parse.unquote(compact)
            if unq and unq != compact: compact = unq
        except Exception as e:
            _log_debug(f"decode_base32: unquote failed: {e!r}")
    s = compact.upper().rstrip('=')
    pad32 = lambda t: t + ('=' * ((-len(t)) % 8))
    if re.fullmatch(r"[A-Z2-7]+=*", s) and len(s) >= 2:
        try:
            decoded = bytes_to_text(base64.b32decode(pad32(s), casefold=True))
            if decoded is not None: return decoded
        except (binascii.Error, ValueError): pass
    alt = re.sub(r"[\-_.]", "", value).upper().rstrip('=')
    if alt != s and re.fullmatch(r"[A-Z2-7]+=*", alt):
        try:
            decoded = bytes_to_text(base64.b32decode(pad32(alt), casefold=True))
            if decoded is not None: return decoded
        except Exception as e:
            _log_debug(f"decode_base32: forgiving variant failed: {e!r}")
    BASE32HEX, STANDARD_B32 = "0123456789ABCDEFGHIJKLMNOPQRSTUV", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    cleaned = re.sub(r"=+", "", s)
    if re.fullmatch(r"[0-9A-V]+", cleaned) and len(cleaned) >= 2:
        try:
            mapped = ''.join(STANDARD_B32[BASE32HEX.index(ch)] for ch in cleaned)
            decoded = bytes_to_text(base64.b32decode(pad32(mapped), casefold=True))
            if decoded is not None: return decoded
        except Exception as e:
            _log_debug(f"decode_base32: base32hex mapping failed: {e!r}")
    return None

def decode_base64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+=*", compact): return None
    try:
        return bytes_to_text(base64.b64decode(add_base64_padding(compact), validate=True))
    except (binascii.Error, ValueError): return None

def decode_base64url(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 4 or not re.fullmatch(r"[A-Za-z0-9_-]+=*", compact): return None
    try:
        return bytes_to_text(base64.urlsafe_b64decode(add_base64_padding(compact)))
    except (binascii.Error, ValueError): return None

def decode_int_alphabet(value: str, alphabet: str) -> bytes | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2 or any(ch not in alphabet for ch in compact): return None
    base, number = len(alphabet), 0
    for ch in compact:
        number = number * base + alphabet.index(ch)
    leading_zeroes = len(compact) - len(compact.lstrip(alphabet[0]))
    raw = b"\x00" * leading_zeroes
    if number: raw += number.to_bytes((number.bit_length() + 7) // 8, "big")
    return raw or None

def decode_base36(value: str) -> str | None:
    raw = decode_int_alphabet(value.lower(), BASE36_ALPHABET)
    return bytes_to_text(raw) if raw else None

def decode_base45(value: str) -> str | None:
    compact = value.strip().replace("\n", "").replace("\r", "").upper()
    if not compact or any(ch not in BASE45_ALPHABET for ch in compact): return None
    table = {ch: i for i, ch in enumerate(BASE45_ALPHABET)}
    output = bytearray()
    for i in range(0, len(compact), 3):
        chunk = compact[i:i+3]
        if len(chunk) == 3:
            val = table[chunk[0]] + table[chunk[1]] * 45 + table[chunk[2]] * 45 * 45
            if val > 0xFFFF: return None
            output.extend(val.to_bytes(2, "big"))
        elif len(chunk) == 2:
            val = table[chunk[0]] + table[chunk[1]] * 45
            if val > 0xFF: return None
            output.extend(val.to_bytes(1, "big"))
        else: return None
    return bytes_to_text(bytes(output))

def decode_base58(value: str) -> str | None:
    raw = decode_int_alphabet(value, BASE58_ALPHABET)
    return bytes_to_text(raw) if raw else None

def decode_base58check(value: str) -> str | None:
    raw = decode_int_alphabet(value, BASE58_ALPHABET)
    if raw is None or len(raw) < 5: return None
    payload, checksum = raw[:-4], raw[-4:]
    computed = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if computed != checksum: return None
    text = bytes_to_text(payload)
    if text is not None: return text
    if len(payload) > 1: return bytes_to_text(payload[1:])
    return None

def decode_base62(value: str) -> str | None:
    raw = decode_int_alphabet(value, BASE62_ALPHABET)
    return bytes_to_text(raw) if raw else None

def decode_base85(value: str) -> str | None:
    compact = value.strip()
    if len(compact) < 5: return None
    try: return bytes_to_text(base64.b85decode(compact))
    except (binascii.Error, ValueError): return None

def decode_ascii85(value: str) -> str | None:
    compact = value.strip()
    if len(compact) < 5: return None
    try: return bytes_to_text(base64.a85decode(compact, adobe=False))
    except (binascii.Error, ValueError): return None

def decode_z85(value: str) -> str | None:
    compact = value.strip().replace("\n", "").replace("\r", "")
    if len(compact) % 5 != 0 or any(ch not in Z85_ALPHABET for ch in compact): return None
    table = {ch: i for i, ch in enumerate(Z85_ALPHABET)}
    output = bytearray()
    for i in range(0, len(compact), 5):
        chunk = compact[i:i+5]
        val = sum(table[c] * (85 ** (4 - j)) for j, c in enumerate(chunk))
        if val > 0xFFFFFFFF: return None
        output.extend(val.to_bytes(4, "big"))
    return bytes_to_text(bytes(output))

def decode_base91(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2 or any(ch not in BASE91_ALPHABET for ch in compact): return None
    table = {ch: index for index, ch in enumerate(BASE91_ALPHABET)}
    output = bytearray()
    accumulator, bit_count, pending = 0, 0, -1
    for ch in compact:
        current = table[ch]
        if pending < 0:
            pending = current; continue
        pending += current * 91
        accumulator |= pending << bit_count
        bit_count += 13 if (pending & 8191) > 88 else 14
        while bit_count > 7:
            output.append(accumulator & 255)
            accumulator >>= 8
            bit_count -= 8
        pending = -1
    if pending >= 0: output.append((accumulator | pending << bit_count) & 255)
    return bytes_to_text(bytes(output))

def decode_base92(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if compact == "~": return ""
    if len(compact) < 2 or any(ch not in BASE92_ALPHABET for ch in compact): return None
    try:
        decoding = {ch: index for index, ch in enumerate(BASE92_ALPHABET)}
        output = bytearray()
        buffer, length = 0, 0
        if len(compact) % 2:
            tail_bits, tail, body = 6, decoding[compact[-1]], compact[:-1]
        else:
            tail_bits, tail, body = 13, decoding[compact[-2]] * 91 + decoding[compact[-1]], compact[:-2]
        for index in range(0, len(body), 2):
            block = decoding[body[index]] * 91 + decoding[body[index + 1]]
            buffer = (buffer << 13) | block
            length += 13
            size, length = divmod(length, 8)
            output.extend((buffer >> length).to_bytes(size, "big"))
            buffer &= (1 << length) - 1
        missing = 8 - length
        shift = tail_bits - missing
        byte_count = 1 if shift < 8 else 2
        if shift >= 8: shift -= 8; missing += 8
        if shift < 0: return None
        buffer = (buffer << missing) | (tail >> shift)
        output.extend(buffer.to_bytes(byte_count, "big"))
        if tail & ((1 << shift) - 1): return None
        return bytes_to_text(bytes(output))
    except (OverflowError, KeyError, ValueError): return None

def decode_base100(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2: return None
    codepoints = [ord(ch) for ch in compact]
    if not all(BASE100_START <= cp <= BASE100_END for cp in codepoints): return None
    try: return bytes_to_text(bytes(cp - BASE100_START for cp in codepoints))
    except ValueError: return None

def decode_quoted_printable(value: str) -> str | None:
    if "=" not in value: return None
    has_soft_break = "=\n" in value or "=\r\n" in value
    escape_matches = re.findall(r"=[0-9A-Fa-f]{2}", value)
    if not has_soft_break and len(escape_matches) < 3: return None
    try:
        import quopri
        raw = quopri.decodestring(value.encode("latin-1", errors="ignore"))
    except Exception as e:
        _log_debug(f"decode_quoted_printable: failed: {e!r}")
        return None
    decoded = bytes_to_text(raw)
    if not decoded or decoded == value or is_effectively_binary(decoded): return None
    return decoded

def decode_reverse(value: str) -> str | None:
    compact = value.strip()
    if len(compact) < 4 or is_effectively_binary(compact): return None
    rev = compact[::-1]
    return rev if rev != compact else None

MORSE_TABLE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9"
}

def decode_morse(value: str) -> str | None:
    compact = value.strip()
    if not compact or not re.fullmatch(r"[.\-\s/|_]+", compact): return None
    words = re.split(r"\s*[/|]\s*|_+|\s{2,}", compact)
    out_words = []
    for word in words:
        letters = [MORSE_TABLE.get(tok) for tok in word.split()]
        if not letters or any(letter is None for letter in letters): return None
        out_words.append("".join(letters))
    res = " ".join(out_words).strip()
    return res or None

NATO_PHONETIC_TABLE = {
    "alpha": "A", "bravo": "B", "charlie": "C", "delta": "D", "echo": "E", "foxtrot": "F", "golf": "G", "hotel": "H",
    "india": "I", "juliett": "J", "juliet": "J", "kilo": "K", "lima": "L", "mike": "M", "november": "N", "oscar": "O",
    "papa": "P", "quebec": "Q", "romeo": "R", "sierra": "S", "tango": "T", "uniform": "U", "victor": "V", "whiskey": "W",
    "xray": "X", "x-ray": "X", "yankee": "Y", "zulu": "Z", "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9", "niner": "9", "fower": "4", "tree": "3", "fife": "5"
}

def decode_nato_phonetic(value: str) -> str | None:
    compact = value.strip()
    if not compact: return None
    tokens = compact.split()
    if len(tokens) < 2: return None
    letters = []
    for tok in tokens:
        mapped = NATO_PHONETIC_TABLE.get(tok.lower().strip(",.;:"))
        if mapped is None: return None
        letters.append(mapped)
    res = "".join(letters)
    return res if res and res != compact else None

def decode_brainfuck(value: str) -> str | None:
    code = "".join(ch for ch in value if not ch.isspace())
    if len(code) < 8 or any(ch not in "+-<>.,[]" for ch in code) or "." not in code or code.count("[") != code.count("]"): return None
    bracket_pairs, stack = {}, []
    for i, ch in enumerate(code):
        if ch == "[": stack.append(i)
        elif ch == "]":
            if not stack: return None
            s = stack.pop()
            bracket_pairs[s] = i; bracket_pairs[i] = s
    if stack: return None
    tape, pointer, ip, output, steps = bytearray(30000), 0, 0, bytearray(), 0
    while ip < len(code):
        steps += 1
        if steps > 200000: return None
        ch = code[ip]
        if ch == "+": tape[pointer] = (tape[pointer] + 1) % 256
        elif ch == "-": tape[pointer] = (tape[pointer] - 1) % 256
        elif ch == ">":
            pointer += 1
            if pointer >= 30000: return None
        elif ch == "<":
            pointer -= 1
            if pointer < 0: return None
        elif ch == ".": output.append(tape[pointer])
        elif ch == ",": tape[pointer] = 0
        elif ch == "[":
            if tape[pointer] == 0: ip = bracket_pairs[ip]
        elif ch == "]":
            if tape[pointer] != 0: ip = bracket_pairs[ip]
        ip += 1
    decoded = bytes_to_text(bytes(output))
    return decoded if decoded and decoded != value else None

MALBOLGE_MEM_SIZE, MALBOLGE_MIN_SOURCE_LEN = 59049, 8
_MALBOLGE_VALID_OPS = frozenset({4, 5, 23, 39, 40, 62, 68, 81})
_MALBOLGE_REAL_OPS = frozenset({4, 5, 23, 39, 40, 62, 81})
_MALBOLGE_XLAT_IN = """!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"""
_MALBOLGE_XLAT_OUT = """5z]&gqtyfr$(we4{WP)H-Zn,[%\\3dL+Q;>U!pJS72FhOA1CB6v^=I_0/8|jsb9m<.TVac`uY*MK'X~xDl}REokN:#?G"i@"""
_MALBOLGE_XLAT = str.maketrans(_MALBOLGE_XLAT_IN, _MALBOLGE_XLAT_OUT)

def _malbolge_crazy(a: int, d: int) -> int:
    table = [[1, 0, 0], [1, 0, 2], [2, 2, 1]]
    res, base = 0, 1
    for _ in range(10):
        res += table[d % 3][a % 3] * base
        a //= 3; d //= 3; base *= 3
    return res

def _malbolge_rot_right(v: int) -> int:
    return (v // 3) + (v % 3) * (MALBOLGE_MEM_SIZE // 3)

def _looks_like_malbolge(code: str) -> bool:
    pos = 0
    for ch in code:
        if ch in ' \t\r\n': continue
        val = ord(ch)
        if not (33 <= val <= 126) or (val + pos) % 94 not in _MALBOLGE_VALID_OPS: return False
        pos += 1
    return pos >= MALBOLGE_MIN_SOURCE_LEN

def decode_malbolge(value: str) -> str | None:
    code = "".join(ch for ch in value if ch in ' \t\r\n' or 33 <= ord(ch) <= 126)
    op_chars = [ch for ch in code if ch not in ' \t\r\n' and 33 <= ord(ch) <= 126]
    if len(op_chars) < MALBOLGE_MIN_SOURCE_LEN or not _looks_like_malbolge(code): return None
    if sum(1 for i, ch in enumerate(op_chars) if (ord(ch) + i) % 94 in _MALBOLGE_REAL_OPS) < max(2, len(op_chars) // 16) or sum(1 for i, ch in enumerate(op_chars) if (ord(ch) + i) % 94 == 5) < 1:
        return None
    mem, ptr = [0] * MALBOLGE_MEM_SIZE, 0
    for ch in code:
        if ch in ' \t\r\n' or not (33 <= ord(ch) <= 126): continue
        mem[ptr] = ord(ch); ptr += 1
        if ptr >= MALBOLGE_MEM_SIZE: break
    for i in range(ptr, MALBOLGE_MEM_SIZE):
        mem[i] = _malbolge_crazy(mem[i - 1], mem[i - 2])
    c_reg, d_reg, a_reg, output_chars, steps = 0, 0, 0, [], 0
    try:
        while steps < 2000000:
            steps += 1
            cell = mem[c_reg]
            if not (33 <= cell <= 126): break
            opcode = (cell + c_reg) % 94
            if opcode == 4: c_reg = mem[d_reg]
            elif opcode == 5:
                output_chars.append(chr(a_reg % 256))
                if len(output_chars) > 4096: break
            elif opcode == 23 or opcode == 81: break
            elif opcode == 39:
                v = _malbolge_rot_right(mem[d_reg]); mem[d_reg] = v; a_reg = v
            elif opcode == 40: d_reg = mem[d_reg]
            elif opcode == 62:
                v = _malbolge_crazy(a_reg, mem[d_reg]); mem[d_reg] = v; a_reg = v
            if 33 <= mem[c_reg] <= 126:
                mem[c_reg] = ord(chr(mem[c_reg]).translate(_MALBOLGE_XLAT))
            c_reg = 0 if c_reg == MALBOLGE_MEM_SIZE - 1 else c_reg + 1
            d_reg = 0 if d_reg == MALBOLGE_MEM_SIZE - 1 else d_reg + 1
    except Exception as e:
        _log_debug(f"decode_malbolge: VM error: {e!r}")
        return None
    if len(output_chars) < 4: return None
    res = "".join(output_chars)
    decoded = bytes_to_text(res.encode("latin-1", errors="replace"))
    return decoded if decoded and decoded != value else None

def decode_url(value: str) -> str | None:
    compact = value.strip()
    if "%" not in compact and "+" not in compact: return None
    escape_matches = re.findall(r"%[0-9A-Fa-f]{2}", compact)
    if not escape_matches or (len(escape_matches) < 2 and (len(escape_matches) * 3 / max(len(compact), 1)) < 0.15):
        return None
    try: decoded = urllib.parse.unquote(compact, errors="strict")
    except (UnicodeDecodeError, ValueError): return None
    if not decoded or decoded == compact or is_effectively_binary(decoded): return None
    return decoded

def decode_punycode(value: str) -> str | None:
    compact = value.strip()
    if "xn--" not in compact.lower(): return None
    labels, decoded_labels, changed = compact.split("."), [], False
    if not any(label.lower().startswith("xn--") for label in labels): return None
    for label in labels:
        if label.lower().startswith("xn--"):
            body = label[4:]
            if not body: return None
            try: decoded_label = body.encode("ascii").decode("punycode")
            except (UnicodeError, UnicodeDecodeError, LookupError): return None
            decoded_labels.append(decoded_label); changed = True
        else: decoded_labels.append(label)
    if not changed: return None
    res = ".".join(decoded_labels)
    return res if res and res != compact else None

HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")
OCTAL_ESCAPE_RE = re.compile(r"\\([0-7]{1,3})")
HTML_NUMERIC_ENTITY_RE = re.compile(r"&#(x[0-9A-Fa-f]+|[0-9]+);")
HTML_NAMED_ENTITY_RE = re.compile(r"&([a-zA-Z][a-zA-Z0-9]*);")

def _escape_guard_ok(value: str, matches: list, min_matches: int = 2, min_density: float = 0.15, chars_per_match: int = 4) -> bool:
    if len(matches) >= min_matches: return True
    return ((len(matches) * chars_per_match) / max(len(value), 1)) >= min_density

def decode_hex_escape(value: str) -> str | None:
    matches = HEX_ESCAPE_RE.findall(value)
    if not matches or not _escape_guard_ok(value, matches, chars_per_match=4): return None
    decoded = HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), value)
    if not decoded or decoded == value or is_effectively_binary(decoded): return None
    return decoded

def decode_octal_escape(value: str) -> str | None:
    matches = OCTAL_ESCAPE_RE.findall(value)
    if not matches or not _escape_guard_ok(value, matches, chars_per_match=3): return None
    try: decoded = OCTAL_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 8)), value)
    except ValueError: return None
    if not decoded or decoded == value or is_effectively_binary(decoded): return None
    return decoded

def decode_html_numeric_entity(value: str) -> str | None:
    matches = HTML_NUMERIC_ENTITY_RE.findall(value)
    if not matches or not _escape_guard_ok(value, matches, min_matches=1, chars_per_match=5): return None
    def _sub(m: re.Match) -> str:
        tok = m.group(1)
        cp = int(tok[1:], 16) if tok[0] in "xX" else int(tok)
        try: return chr(cp)
        except (ValueError, OverflowError): return m.group(0)
    decoded = HTML_NUMERIC_ENTITY_RE.sub(_sub, value)
    if not decoded or decoded == value or has_control_chars(decoded): return None
    return decoded

def decode_jwt(value: str) -> str | None:
    parts = value.strip().split(".")
    if len(parts) != 3 or any(not p or not re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts): return None
    try:
        h_raw = base64.urlsafe_b64decode(add_base64_padding(parts[0]))
        p_raw = base64.urlsafe_b64decode(add_base64_padding(parts[1]))
    except (binascii.Error, ValueError): return None
    h_text, p_text = bytes_to_text(h_raw), bytes_to_text(p_raw)
    if not h_text or not p_text or not (h_text.lstrip().startswith("{") and p_text.lstrip().startswith("{")): return None
    return f"header: {h_text} | payload: {p_text}"

def decode_html_entity(value: str) -> str | None:
    candidates = HTML_NAMED_ENTITY_RE.findall(value)
    if not candidates: return None
    rec = [c for c in candidates if html.unescape(f"&{c};") != f"&{c};"]
    if not rec or not _escape_guard_ok(value, rec, min_matches=1, chars_per_match=4): return None
    decoded = html.unescape(value)
    if not decoded or decoded == value or has_control_chars(decoded): return None
    return decoded

def _decompress_payload(value: str, decompressor_func: Callable[[bytes], bytes], debug_name: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0:
        try:
            res = bytes_to_text(decompressor_func(bytes.fromhex(compact)))
            if res is not None: return res
        except Exception as e: _log_debug(f"{debug_name}: hex path failed: {e!r}")
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
        try:
            res = bytes_to_text(decompressor_func(base64.b64decode(add_base64_padding(compact))))
            if res is not None: return res
        except Exception as e: _log_debug(f"{debug_name}: base64 path failed: {e!r}")
    try:
        res = bytes_to_text(decompressor_func(value.encode("latin-1")))
        if res is not None: return res
    except Exception as e: _log_debug(f"{debug_name}: raw bytes path failed: {e!r}")
    return None

def decode_gzip(value: str) -> str | None:
    return _decompress_payload(value, gzip.decompress, "decode_gzip")

def decode_zlib(value: str) -> str | None:
    def _zlib_decomp(data: bytes) -> bytes:
        try: return zlib.decompress(data)
        except Exception: return zlib.decompress(data, wbits=-15)
    return _decompress_payload(value, _zlib_decomp, "decode_zlib")

def decode_bzip2(value: str) -> str | None:
    return _decompress_payload(value, bz2.decompress, "decode_bzip2")

def decode_xz(value: str) -> str | None:
    return _decompress_payload(value, lzma.decompress, "decode_xz")

def decode_zstd(value: str) -> str | None:
    if zstd is None: return None
    return _decompress_payload(value, lambda data: zstd.ZstdDecompressor().decompress(data), "decode_zstd")

XOR_SINGLEBYTE_MIN_SCORE = 15.0

def decode_xor_singlebyte(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    raw = None
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0 and len(compact) >= 6:
        try: raw = bytes.fromhex(compact)
        except ValueError: pass
    if raw is None and re.fullmatch(r"[A-Za-z0-9+/]+=*", compact) and len(compact) >= 8:
        try: raw = base64.b64decode(add_base64_padding(compact), validate=True)
        except (binascii.Error, ValueError): pass
    if raw is None or len(raw) < 4: return None
    best_text, best_score = None, -999.0
    for key in range(1, 256):
        text = bytes_to_text(bytes(b ^ key for b in raw))
        if text is None: continue
        s = score_text(text)
        if s > best_score: best_text, best_score = text, s
    if best_text is not None and best_score >= XOR_SINGLEBYTE_MIN_SCORE: return best_text
    return None

MULTI_XOR_MIN_LENGTH, MULTI_XOR_MIN_KEYLEN, MULTI_XOR_MAX_KEYLEN = 40, 2, 8
MULTI_XOR_IC_THRESHOLD, MULTI_XOR_MIN_BYTES_PER_COLUMN, MULTI_XOR_FINAL_SCORE_THRESHOLD = 0.045, 18, 16.0

def _index_of_coincidence(data: bytes) -> float:
    n = len(data)
    if n < 2: return 0.0
    counts = Counter(data)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))

def _shortlist_xor_multikey_lengths(raw: bytes, max_keylen: int) -> list[int]:
    candidates = []
    for keylen in range(MULTI_XOR_MIN_KEYLEN, max_keylen + 1):
        if len(raw) < keylen * MULTI_XOR_MIN_BYTES_PER_COLUMN: continue
        column_ics = []
        for i in range(keylen):
            col = raw[i::keylen]
            if len(col) >= 2: column_ics.append(_index_of_coincidence(col))
        if column_ics and (sum(column_ics) / len(column_ics)) >= MULTI_XOR_IC_THRESHOLD:
            candidates.append(keylen)
    return candidates

def _crack_xor_multikey_column(column: bytes) -> int:
    best_key, best_score = 0, float("-inf")
    for key in range(256):
        score = 0.0
        for b in column:
            decoded_byte = b ^ key
            ch = chr(decoded_byte)
            if ch == " ": score += 2.5
            elif "a" <= ch <= "z": score += ENGLISH_LETTER_FREQ.get(ch, 0.05)
            elif "A" <= ch <= "Z": score += ENGLISH_LETTER_FREQ.get(ch.lower(), 0.05) * 0.8
            elif ch in ".,!?'\"-_{}": score += 0.4
            elif 32 <= decoded_byte < 127: score += 0.05
            else: score -= 3.0
        if score > best_score: best_score, best_key = score, key
    return best_key

def decode_xor_multikey(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    raw = None
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0 and len(compact) >= MULTI_XOR_MIN_LENGTH:
        try: raw = bytes.fromhex(compact)
        except ValueError: pass
    if raw is None and re.fullmatch(r"[A-Za-z0-9+/]+=*", compact) and len(compact) >= MULTI_XOR_MIN_LENGTH:
        try: raw = base64.b64decode(add_base64_padding(compact), validate=True)
        except (binascii.Error, ValueError): pass
    if raw is None and len(compact) >= MULTI_XOR_MIN_LENGTH:
        if score_text(value) < 15.0:
            try: raw = value.encode("latin-1")
            except UnicodeEncodeError: pass
    if raw is None or len(raw) < MULTI_XOR_MIN_LENGTH: return None
    keylen_candidates = _shortlist_xor_multikey_lengths(raw, MULTI_XOR_MAX_KEYLEN)
    if not keylen_candidates: return None
    best_text, best_score = None, float("-inf")
    for keylen in keylen_candidates:
        key = bytes(_crack_xor_multikey_column(raw[i::keylen]) for i in range(keylen))
        if all(k == 0 for k in key): continue
        text = bytes_to_text(bytes(b ^ key[i % keylen] for i, b in enumerate(raw)))
        if text is None: continue
        s = score_text(text)
        if s > best_score: best_text, best_score = text, s
    if best_text is not None and best_score >= MULTI_XOR_FINAL_SCORE_THRESHOLD: return best_text
    return None

BACON_TABLE = {
    "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E", "AABAB": "F", "AABBA": "G", "AABBB": "H",
    "ABAAA": "I", "ABAAB": "J", "ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N", "ABBBA": "O", "ABBBB": "P",
    "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T", "BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X",
    "BBAAA": "Y", "BBAAB": "Z"
}
BACON_TABLE_24 = dict(BACON_TABLE)
BACON_TABLE_24["ABAAB"] = "I"; BACON_TABLE_24["BABAB"] = "U"

def decode_bacon(value: str) -> str | None:
    compact = re.sub(r"[\s/_,.\-]+", "", value).upper()
    if len(compact) < 15 or len(compact) % 5 != 0 or not re.fullmatch(r"[AB]+", compact): return None
    groups = [compact[i:i + 5] for i in range(0, len(compact), 5)]
    letters = []
    for g in groups:
        letter = BACON_TABLE.get(g) or BACON_TABLE_24.get(g)
        if letter is None: return None
        letters.append(letter)
    res = "".join(letters)
    return res if res and res != compact else None

DECODERS: tuple[tuple[str, Callable[[str], str | None]], ...] = (
    ("bacon", decode_bacon), ("malbolge", decode_malbolge), ("base64", decode_base64), ("base64url", decode_base64url),
    ("base32", decode_base32), ("base16", decode_base16), ("base2", decode_base2), ("base100", decode_base100),
    ("gzip", decode_gzip), ("zlib", decode_zlib), ("bzip2", decode_bzip2), ("xz", decode_xz), ("zstd", decode_zstd),
    ("url", decode_url), ("punycode", decode_punycode), ("hex_escape", decode_hex_escape), ("octal_escape", decode_octal_escape),
    ("html_numeric_entity", decode_html_numeric_entity), ("jwt", decode_jwt), ("html_entity", decode_html_entity),
    ("quoted_printable", decode_quoted_printable), ("base45", decode_base45), ("base85", decode_base85), ("ascii85", decode_ascii85),
    ("z85", decode_z85), ("base91", decode_base91), ("base92", decode_base92), ("morse", decode_morse), ("nato_phonetic", decode_nato_phonetic),
    ("brainfuck", decode_brainfuck), ("base36", decode_base36), ("base58check", decode_base58check), ("base58", decode_base58),
    ("base62", decode_base62), ("xor_singlebyte", decode_xor_singlebyte), ("xor_multikey", decode_xor_multikey), ("reverse", decode_reverse),
)

RESIDUAL_ARTIFACT_RE = re.compile(r"&#|&[a-zA-Z][a-zA-Z0-9]*;|%[0-9A-Fa-f]{2}|\\x[0-9A-Fa-f]{2}|\\[0-7]{1,3}")

def has_residual_encoding_artifact(text: str) -> bool:
    return bool(RESIDUAL_ARTIFACT_RE.search(text))

def looks_like_rotatable_text(text: str) -> bool:
    return len(text) >= 3 and any(ch.isalpha() for ch in text)

def rot_n(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if 'a' <= ch <= 'z': out.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z': out.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else: out.append(ch)
    return "".join(out)

def decode_rot_all(value: str) -> list[tuple[str, str]]:
    if not looks_like_rotatable_text(value): return []
    results = []
    for shift in range(1, 26):
        cand = rot_n(value, shift)
        if cand != value: results.append((f"rot{(26 - shift) % 26}", cand))
    return results

def rot5(text: str) -> str:
    return "".join(chr((ord(ch) - ord('0') + 5) % 10 + ord('0')) if '0' <= ch <= '9' else ch for ch in text)

def rot13(text: str) -> str: return rot_n(text, 13)

def rot18(text: str) -> str:
    out = []
    for ch in text:
        if '0' <= ch <= '9': out.append(chr((ord(ch) - ord('0') + 5) % 10 + ord('0')))
        elif 'a' <= ch <= 'z': out.append(chr((ord(ch) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z': out.append(chr((ord(ch) - ord('A') + 13) % 26 + ord('A')))
        else: out.append(ch)
    return "".join(out)

def rot47(text: str) -> str:
    return "".join(chr(33 + (ord(ch) + 47 - 33) % 94) if 33 <= ord(ch) <= 126 else ch for ch in text)

def decode_rot47(value: str) -> str | None:
    if not looks_like_rotatable_text(value): return None
    cand = rot47(value)
    return cand if cand != value else None

def decode_rot5(value: str) -> str | None:
    if not re.search(r"\d", value): return None
    cand = rot5(value)
    return cand if cand != value else None

def decode_rot18(value: str) -> str | None:
    if not re.search(r"[A-Za-z0-9]", value): return None
    cand = rot18(value)
    return cand if cand != value else None

def atbash(text: str) -> str:
    out = []
    for ch in text:
        if 'a' <= ch <= 'z': out.append(chr(ord('z') - (ord(ch) - ord('a'))))
        elif 'A' <= ch <= 'Z': out.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        else: out.append(ch)
    return "".join(out)

def decode_atbash(value: str) -> str | None:
    if not looks_like_rotatable_text(value): return None
    cand = atbash(value)
    return cand if cand != value else None

THAI_CONSONANTS = "กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรลวศษสหฬอฮ"
THAI_ROT_MIN_CONSONANTS = 3

def thai_rot_n(text: str, shift: int) -> str:
    out, n = [], len(THAI_CONSONANTS)
    for ch in text:
        idx = THAI_CONSONANTS.find(ch)
        out.append(THAI_CONSONANTS[(idx + shift) % n] if idx >= 0 else ch)
    return "".join(out)

def looks_like_thai_rotatable_text(text: str) -> bool:
    return len(text) >= 3 and sum(1 for ch in text if ch in THAI_CONSONANTS) >= THAI_ROT_MIN_CONSONANTS

def decode_thai_rot_all(value: str) -> list[tuple[str, str]]:
    if not looks_like_thai_rotatable_text(value): return []
    results, n = [], len(THAI_CONSONANTS)
    for shift in range(1, n):
        cand = thai_rot_n(value, shift)
        if cand != value: results.append((f"thairot{(n - shift) % n}", cand))
    return results

def decode_thai_atbash(value: str) -> str | None:
    if sum(1 for ch in value if ch in THAI_CONSONANTS) < THAI_ROT_MIN_CONSONANTS: return None
    n = len(THAI_CONSONANTS)
    res = "".join(THAI_CONSONANTS[n - 1 - idx] if (idx := THAI_CONSONANTS.find(ch)) >= 0 else ch for ch in value)
    return res if res != value else None

THAI_POLYBIUS_CONSONANTS = THAI_CONSONANTS[:25]

def _build_thai_polybius() -> tuple[dict[str, str], dict[str, str]]:
    enc, dec = {}, {}
    for i, ch in enumerate(THAI_POLYBIUS_CONSONANTS):
        row, col = divmod(i, 5)
        code = f"{row+1}{col+1}"
        enc[ch] = code; dec[code] = ch
    return enc, dec

_THAI_POLYBIUS_ENC, _THAI_POLYBIUS_DEC = _build_thai_polybius()

def decode_thai_polybius(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if not re.fullmatch(r"[1-5]+", compact) or len(compact) % 2 != 0 or len(compact) < 4: return None
    pairs = [compact[i:i+2] for i in range(0, len(compact), 2)]
    if not all(p in _THAI_POLYBIUS_DEC for p in pairs): return None
    res = "".join(_THAI_POLYBIUS_DEC[p] for p in pairs)
    return res if res and res != value else None

DECODERS = DECODERS + (("thai_atbash", decode_thai_atbash), ("thai_polybius", decode_thai_polybius))
SUBSTITUTION_DECODERS: tuple[tuple[str, Callable[[str], str | None]], ...] = (
    ("rot5", decode_rot5), ("rot18", decode_rot18), ("rot47", decode_rot47), ("atbash", decode_atbash)
)

def is_substitution_scheme(name: str) -> bool:
    return name.startswith("rot") or name.startswith("thairot") or name in {"atbash", "thai_atbash", "xor_singlebyte"}

def is_always_succeeds_scheme(name: str) -> bool:
    return is_substitution_scheme(name) or name == "reverse" or name == "thai_polybius"

VALIDATED_DECODE_BONUS = 8.0
WEAK_VALIDATION_SCHEMES = {"base36", "base58", "base62", "reverse", "thai_polybius"}
ONCE_PER_CHAIN_SCHEMES = {"quoted_printable", "url", "malbolge", "brainfuck", "thai_polybius"}
DENSE_LOW_CONFIDENCE_SCHEMES = {"base2", "base16", "ascii85", "base85", "z85", "base91", "base92", "xor_singlebyte"}
MIN_LENGTH_FOR_DENSE_BONUS = 18
SUBSTITUTION_LEGIBILITY_BONUS, SUBSTITUTION_LEGIBILITY_THAI_THRESHOLD = 4.0, 3.0
THAI_ROT_MIN_WORD_HITS = 3

def thai_rot_word_evidence(text: str) -> bool:
    return sum(1 for word in THAI_COMMON_WORDS if word in text) >= THAI_ROT_MIN_WORD_HITS

def substitution_legibility_bonus(scheme: str, decoded: str) -> float:
    if not (scheme.startswith("rot") or scheme.startswith("thairot") or scheme in {"atbash", "reverse", "thai_atbash"}):
        return 0.0
    if scheme in {"rot5", "rot18"} and any(ch.isdigit() for ch in decoded): return 0.0
    if dictionary_confidence_bonus(decoded) >= DICTIONARY_MAX_BONUS: return SUBSTITUTION_LEGIBILITY_BONUS
    if scheme.startswith("thairot") or scheme in {"reverse", "atbash", "thai_atbash"}:
        return SUBSTITUTION_LEGIBILITY_BONUS if thai_rot_word_evidence(decoded) else 0.0
    if thai_confidence_bonus(decoded) >= SUBSTITUTION_LEGIBILITY_THAI_THRESHOLD: return SUBSTITUTION_LEGIBILITY_BONUS
    return 0.0

URL_LEGIBILITY_BONUS, URL_LEGIBILITY_THAI_THRESHOLD = 3.0, 3.0

def url_legibility_bonus(scheme: str, decoded: str) -> float:
    if scheme != "url": return 0.0
    if dictionary_confidence_bonus(decoded) >= DICTIONARY_MAX_BONUS or thai_confidence_bonus(decoded) >= URL_LEGIBILITY_THAI_THRESHOLD:
        return URL_LEGIBILITY_BONUS
    return 0.0

UNICODE_LEGIBILITY_BONUS = 3.0

def unicode_legibility_bonus(scheme: str, decoded: str) -> float:
    if scheme != "punycode" or is_effectively_binary(decoded): return 0.0
    return UNICODE_LEGIBILITY_BONUS if sum(1 for ch in decoded if ord(ch) > 127 and ch.isalpha()) >= 1 else 0.0

def gets_validated_bonus(scheme: str) -> bool:
    if scheme in {"xor_singlebyte", "xor_multikey"}: return True
    return not is_substitution_scheme(scheme) and scheme not in WEAK_VALIDATION_SCHEMES

def trailing_substitution_run(chain: tuple[str, ...]) -> int:
    count = 0
    for scheme in reversed(chain):
        if is_always_succeeds_scheme(scheme): count += 1
        else: break
    return count

def total_substitution_count(chain: tuple[str, ...]) -> int:
    return sum(1 for scheme in chain if is_always_succeeds_scheme(scheme))

WEAK_CHAIN_CAP_SCHEMES = {"base36", "base58", "base62"}
MAX_WEAK_CHAIN_LENGTH = 3

def total_weak_chain_count(chain: tuple[str, ...]) -> int:
    return sum(1 for scheme in chain if scheme in WEAK_CHAIN_CAP_SCHEMES)

def has_boundaried_token(text: str, word: str) -> bool:
    for match in re.finditer(re.escape(word), text, re.IGNORECASE):
        token = match.group()
        start, end = match.start(), match.end()
        if token.isupper():
            if start == 0 or not text[start - 1].isalnum() or text[start - 1].islower(): return True
            continue
        before_ok = start == 0 or not text[start - 1].isalnum()
        after_ok = end == len(text) or not text[end].isalnum()
        if before_ok and after_ok: return True
    return False

FULL_FLAG_PATTERN = re.compile(r"\b[A-Za-z0-9_]{2,20}\{[^{}]{1,200}\}")

def has_full_flag_pattern(text: str) -> bool:
    match = FULL_FLAG_PATTERN.search(text)
    if not match: return False
    tag = match.group().split("{", 1)[0].lower()
    return "flag" in tag or "ctf" in tag or "picoctf" in tag or "htb" in tag

FLAG_CONTEXT_MIN_REMAINDER_FOR_CHECK, FLAG_CONTEXT_MIN_TOKEN_RATIO, FLAG_CONTEXT_MIN_WORD_LEN = 4, 0.35, 3

def _flag_context_word_tokens(remainder: str) -> list[str]:
    words = []
    for chunk in remainder.split():
        stripped = chunk.strip("'\".,;:!?()[]{}")
        if stripped and stripped.isalpha(): words.append(stripped.lower())
    return words

def flag_context_is_plausible(text: str) -> bool:
    match = FULL_FLAG_PATTERN.search(text)
    if not match: return False
    remainder = text[:match.start()] + text[match.end():]
    if len(remainder) < FLAG_CONTEXT_MIN_REMAINDER_FOR_CHECK: return True
    words = _flag_context_word_tokens(remainder)
    if any(len(w) >= FLAG_CONTEXT_MIN_WORD_LEN and w in COMMON_ENGLISH_WORDS for w in words): return True
    all_tokens = remainder.split()
    n = len(all_tokens)
    if n == 0: return True
    if n >= 3: return (len(words) / n) >= FLAG_CONTEXT_MIN_TOKEN_RATIO
    return len(words) == n

def shannon_entropy(text: str) -> float:
    if not text: return 0.0
    counts = {ch: text.count(ch) for ch in set(text)}
    return -sum((count / len(text)) * math.log2(count / len(text)) for count in counts.values())

AES_DETECTION_BLOCK_SIZE, AES_DETECTION_MIN_BYTES, AES_DETECTION_ENTROPY_RATIO_THRESHOLD = 16, 48, 0.90

def shannon_entropy_bytes(data: bytes) -> float:
    if not data: return 0.0
    counts, n = Counter(data), len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def normalized_entropy_ratio(data: bytes) -> float:
    n = len(data)
    if n < 2: return 0.0
    max_possible = math.log2(min(256, n))
    return (shannon_entropy_bytes(data) / max_possible) if max_possible > 0 else 0.0

def _try_parse_as_bytes_for_detection(value: str) -> bytes | None:
    compact = re.sub(r"\s+", "", value)
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0 and compact:
        try: return bytes.fromhex(compact)
        except ValueError: pass
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", compact) and len(compact) >= 4:
        try: return base64.b64decode(add_base64_padding(compact), validate=True)
        except (binascii.Error, ValueError): pass
    try: return value.encode("latin-1")
    except UnicodeEncodeError: return None

def detect_likely_block_cipher(value: str) -> str | None:
    if dictionary_confidence_bonus(value) >= DICTIONARY_MAX_BONUS or thai_confidence_bonus(value) >= SUBSTITUTION_LEGIBILITY_THAI_THRESHOLD:
        return None
    raw = _try_parse_as_bytes_for_detection(value)
    if raw is None or len(raw) < AES_DETECTION_MIN_BYTES or len(raw) % AES_DETECTION_BLOCK_SIZE != 0: return None
    ratio = normalized_entropy_ratio(raw)
    if ratio < AES_DETECTION_ENTROPY_RATIO_THRESHOLD: return None
    entropy = shannon_entropy_bytes(raw)
    return f"หมายเหตุ: ข้อมูลนี้มีลักษณะคล้ายถูกเข้ารหัสด้วย block cipher (เช่น AES) — ยาว {len(raw)} bytes (หาร {AES_DETECTION_BLOCK_SIZE} ลงตัว), entropy {entropy:.2f} bits/byte ({ratio*100:.0f}% ของค่าสูงสุดที่เป็นไปได้) ซึ่งเป็นลักษณะเฉพาะของ ciphertext ที่เข้ารหัสแล้ว ไม่ใช่ encoding ทั่วไป ต้องมี key ที่ถูกต้องถึงจะถอดได้ — เครื่องมือนี้ auto-decode ต่อไม่ได้"

def printable_ratio_unicode_aware(text: str) -> float:
    if not text: return 0.0
    return sum(1 for ch in text if ch in PRINTABLE or ch.isprintable() or ch in "\n\r\t") / len(text)

def score_text(text: str) -> float:
    if not text: return -999.0
    printable_ratio = printable_ratio_unicode_aware(text)
    alpha_space_ratio = sum(1 for ch in text if ch.isalnum() or ch in " _-{}[]():;,.!?/@#$%^&*+=\n\r\t") / len(text)
    lower = text.lower()
    word_bonus = sum(2.0 for word in COMMON_WORDS if word in lower)
    flag_bonus = 0.0
    if re.search(r"(flag|ctf)[\{_\-:]", lower): flag_bonus = 10.0
    elif has_boundaried_token(text, "ctf") or has_boundaried_token(text, "flag"): flag_bonus = 3.0
    entropy = shannon_entropy(text)
    entropy_penalty = abs(entropy - 4.2) * 0.5
    ctf_style_bonus = 0.0
    if any(ch.isdigit() for ch in text) and any(ch.isalpha() for ch in text):
        if "_" in text or "{" in text or "}" in text or "-" in text: ctf_style_bonus = 2.0
    if any(ch.isdigit() for ch in text) and any(ch.isalpha() for ch in text) and "_" in text:
        ctf_style_bonus = max(ctf_style_bonus, 2.5)
    length_bonus = min(len(text), 80) / 80
    if " " not in text and len(text) > 20 and word_bonus == 0 and ctf_style_bonus == 0: length_bonus = -3.0
    chi2 = english_chi_squared(text)
    if chi2 is not None: chi2_penalty = min(chi2 / 140.0, 6.0)
    elif len(text) >= 5: chi2_penalty = 1.5
    else: chi2_penalty = 0.0
    return (printable_ratio * 8 + alpha_space_ratio * 5 + word_bonus + flag_bonus + ctf_style_bonus + length_bonus - entropy_penalty - chi2_penalty + dictionary_confidence_bonus(text) + thai_confidence_bonus(text))

def _score_breakdown(text: str) -> dict:
    if not text: return {"total": -999.0}
    printable_ratio = printable_ratio_unicode_aware(text)
    alpha_space_ratio = sum(1 for ch in text if ch.isalnum() or ch in " _-{}[]():;,.!?/@#$%^&*+=\n\r\t") / len(text)
    lower = text.lower()
    word_bonus = sum(2.0 for word in COMMON_WORDS if word in lower)
    flag_bonus = 0.0
    if re.search(r"(flag|ctf)[\{_\-:]", lower): flag_bonus = 10.0
    elif has_boundaried_token(text, "ctf") or has_boundaried_token(text, "flag"): flag_bonus = 3.0
    entropy = shannon_entropy(text)
    entropy_penalty = abs(entropy - 4.2) * 0.5
    ctf_style_bonus = 0.0
    if any(ch.isdigit() for ch in text) and any(ch.isalpha() for ch in text):
        if "_" in text or "{" in text or "}" in text or "-" in text: ctf_style_bonus = 2.0
    if any(ch.isdigit() for ch in text) and any(ch.isalpha() for ch in text) and "_" in text:
        ctf_style_bonus = max(ctf_style_bonus, 2.5)
    length_bonus = min(len(text), 80) / 80
    if " " not in text and len(text) > 20 and word_bonus == 0 and ctf_style_bonus == 0: length_bonus = -3.0
    chi2 = english_chi_squared(text)
    if chi2 is not None: chi2_penalty = min(chi2 / 140.0, 6.0)
    elif len(text) >= 5: chi2_penalty = 1.5
    else: chi2_penalty = 0.0
    dict_bonus, thai_bonus = dictionary_confidence_bonus(text), thai_confidence_bonus(text)
    total = (printable_ratio * 8 + alpha_space_ratio * 5 + word_bonus + flag_bonus + ctf_style_bonus + length_bonus - entropy_penalty - chi2_penalty + dict_bonus + thai_bonus)
    return {
        "printable_ratio_contrib": round(printable_ratio * 8, 4), "alpha_space_ratio_contrib": round(alpha_space_ratio * 5, 4),
        "word_bonus": round(word_bonus, 4), "flag_bonus": round(flag_bonus, 4), "ctf_style_bonus": round(ctf_style_bonus, 4),
        "length_bonus": round(length_bonus, 4), "entropy_penalty": round(-entropy_penalty, 4), "chi2_penalty": round(-chi2_penalty, 4),
        "dict_bonus": round(dict_bonus, 4), "thai_bonus": round(thai_bonus, 4), "total": round(total, 4)
    }

def safe_preview(text: str, limit: int = 120) -> str:
    preview = text.encode("unicode_escape", errors="backslashreplace").decode("ascii")
    return (preview[: limit - 3] + "...") if len(preview) > limit else preview

def terminal_width() -> int:
    return max(72, min(shutil.get_terminal_size((96, 24)).columns, 120))

def supports_color() -> bool:
    if os.environ.get("NO_COLOR"): return False
    return sys.stdout.isatty() or os.name == "nt"

USE_COLOR = supports_color()
SHOW_PROGRESS = sys.stdout.isatty()

def color(text: str, code: str) -> str: return f"\033[{code}m{text}\033[0m" if USE_COLOR else text
def cyan(text: str) -> str: return color(text, "36")
def green(text: str) -> str: return color(text, "32")
def yellow(text: str) -> str: return color(text, "33")
def dim(text: str) -> str: return color(text, "2")

PROGRESS_BAR_WIDTH = 28

def render_progress_bar(current: int, total: int, label: str = "") -> str:
    total = max(total, 1); current = max(0, min(current, total))
    filled = int(PROGRESS_BAR_WIDTH * current / total)
    bar = "█" * filled + "░" * (PROGRESS_BAR_WIDTH - filled)
    return f"\r{dim('decoding')} {cyan('[')}{green(bar)}{cyan(']')} {int(100 * current / total):3d}%  {dim(label)}\033[K"

def print_progress(current: int, total: int, label: str = "") -> None:
    if SHOW_PROGRESS: sys.stdout.write(render_progress_bar(current, total, label)); sys.stdout.flush()

def clear_progress_line() -> None:
    if SHOW_PROGRESS: sys.stdout.write("\r\033[K"); sys.stdout.flush()

def clear_screen() -> None: os.system("cls" if os.name == "nt" else "clear")

def divider(title: str = "") -> str:
    w = terminal_width()
    if not title: return dim("-" * w)
    lbl = f" {title} "
    left = max(2, (w - len(lbl)) // 2)
    right = max(2, w - left - len(lbl))
    return dim("-" * left) + cyan(lbl) + dim("-" * right)

def print_banner() -> None:
    w = terminal_width()
    art = [
        " ████████╗███████╗ █████╗ ███╗   ███╗      ██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗",
        " ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║      ██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝",
        "    ██║   █████╗  ███████║██╔████╔██║      ██║  ██║█████╗  ██║     ██║   ██║██║  ██║█████╗  ",
        "    ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║      ██║  ██║██╔══╝  ██║     ██║   ██║██║  ██║██╔══╝  ",
        "    ██║   ███████╗██║  ██║██║ ╚═╝ ██║      ██████╔╝███████╗╚██████╗╚██████╔╝██████╔╝███████╗",
        "    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝",
        "", " > root@localhost:/home/team_decode# _"
    ]
    print(cyan("=" * w) + "\n" + color("CRYPTO UTILITY — SECURE MULTIBASE DECODER 🔑".center(w), "1;33") + "\n" + color("20+ encodings • smart heuristics • safe preview".center(w), "1;33") + "\n")
    groups = [
        ("Binary", ["base2"]), ("Radix/Base", ["base16", "base32", "base36", "base45", "base58", "base62", "base64", "base64url", "base100"]),
        ("High-enc", ["base85", "ascii85", "z85", "base91", "base92"]),
        ("Text/Other", ["morse", "url", "quoted_printable", "rotN", "rot47", "rot5", "rot18", "atbash", "xor_singlebyte", "reverse"])
    ]
    col_w = max(20, w // len(groups))
    print("".join(cyan(title.center(col_w)) for title, _ in groups).center(w))
    wrapped_lists = [textwrap.wrap(", ".join(items), width=col_w - 2) or [""] for _, items in groups]
    for i in range(max(len(wl) for wl in wrapped_lists)):
        print("".join(dim((wl[i] if i < len(wl) else "").center(col_w)) for wl in wrapped_lists).center(w))
    print("\n" + cyan("=" * w))
    for line in art: print(green(line.center(w)))
    print("\n" + yellow("🏠 q = quit 🧹 c = clear ❓  h/help/? = help   ⏎ empty = input") + "    " + color("💳 Create by Mr.Suchakree Panyawong", "1;35") + "\n\n" + cyan("=" * w))

def print_help() -> None:
    print(divider("Help") + "\nPaste one encoded value per prompt. The tool will recursively try known decoders.\nThe decode chain is shown in the order used to decode.\nCommands Quick: q = quit, c = clear terminal, h/help/? = show help, empty input = new prompt\n")
    print(divider("Tier-3 Manual Commands") + "\nThese are NOT auto-chained (too ambiguous / false-positive prone). Invoke them explicitly:\n" + f"  {cyan('railfence')} <rails> <text>     e.g. railfence 3 WECRLTEERDSOEEFEAOCAIVDEN\n  {cyan('vigenere')} <key> <text>         e.g. vigenere LEMON ATTACKATDAWN\n  {cyan('columnar')} <key> <text>         e.g. columnar 4 WECRLTEERDSOEEFEAOCAIVDEN\n")

def _get_crypto_hint(winner: Candidate, raw_input: str | None) -> str | None:
    hint = detect_likely_block_cipher(winner.text) if not winner.chain else None
    return detect_likely_block_cipher(raw_input) if (hint is None and raw_input is not None) else hint

def format_result_json(candidates: list[Candidate], candidate_count: int = DEFAULT_CANDIDATE_COUNT, raw_input: str | None = None) -> dict:
    winner = candidates[0]
    return {
        "winner": {"text": winner.text, "chain": list(winner.chain), "score": round(winner.score, 4), "score_breakdown": _score_breakdown(winner.text)},
        "candidates": [{"rank": i + 1, "text": c.text, "chain": list(c.chain), "score": round(c.score, 4)} for i, c in enumerate(candidates[:candidate_count])],
        "crypto_hint": _get_crypto_hint(winner, raw_input),
    }

def print_result(candidates: list[Candidate], show_candidates: bool, candidate_count: int = DEFAULT_CANDIDATE_COUNT, raw_input: str | None = None) -> None:
    winner = candidates[0]
    chain = " -> ".join(winner.chain) if winner.chain else "(input looked already decoded)"
    print(divider("Best Guess") + f"\n{green(winner.text)}\n\n{cyan('Decode chain: ')}{chain}\n{dim(f'Score: {winner.score:.2f}')}")
    if (crypto_hint := _get_crypto_hint(winner, raw_input)): print(f"\n{yellow(crypto_hint)}")
    if show_candidates:
        print("\n" + divider("Top Candidates"))
        for index, candidate in enumerate(candidates[:candidate_count], start=1):
            cand_chain = " -> ".join(candidate.chain) if candidate.chain else "original"
            print(f"{yellow(f'{index:02d}.')} score={candidate.score:.2f}  chain={cand_chain}\n    {safe_preview(candidate.text)}")

def decode_once(value: str, chain: tuple[str, ...] = ()) -> Iterable[tuple[str, str]]:
    for name, decoder in DECODERS:
        if name in ONCE_PER_CHAIN_SCHEMES and name in chain: continue
        if is_always_succeeds_scheme(name) and total_substitution_count(chain) >= MAX_TOTAL_SUBSTITUTION: continue
        if name in WEAK_CHAIN_CAP_SCHEMES and total_weak_chain_count(chain) >= MAX_WEAK_CHAIN_LENGTH: continue
        try: decoded = decoder(value)
        except Exception as e: _log_debug(f"decode_once: decoder {name!r} raised: {e!r}"); continue
        if not decoded: continue
        decoded = decoded.strip()
        if not decoded or decoded == value: continue
        yield name, decoded
    if trailing_substitution_run(chain) < MAX_CONSECUTIVE_SUBSTITUTION and total_substitution_count(chain) < MAX_TOTAL_SUBSTITUTION:
        try: rot_candidates = decode_rot_all(value)
        except Exception as e: _log_debug(f"decode_once: rot generation failed: {e!r}"); rot_candidates = []
        for name, decoded in rot_candidates:
            decoded = decoded.strip()
            if decoded and decoded != value: yield name, decoded
        try: thai_rot_candidates = decode_thai_rot_all(value)
        except Exception as e: _log_debug(f"decode_once: thai rot generation failed: {e!r}"); thai_rot_candidates = []
        for name, decoded in thai_rot_candidates:
            decoded = decoded.strip()
            if decoded and decoded != value: yield name, decoded
        for name, decoder in SUBSTITUTION_DECODERS:
            try: decoded = decoder(value)
            except Exception as e: _log_debug(f"decode_once: substitution decoder {name!r} raised: {e!r}"); continue
            if not decoded: continue
            decoded = decoded.strip()
            if decoded and decoded != value: yield name, decoded

def auto_decode(value: str, max_depth: int = 15, beam_size: int = DEFAULT_BEAM_SIZE, progress_callback: Callable[[int, int, int], None] | None = None) -> list[Candidate]:
    start = normalize_input(value)
    best: dict[str, Candidate] = {start: Candidate(text=start, chain=(), score=score_text(start))}
    frontier = [best[start]]
    if has_full_flag_pattern(start) and flag_context_is_plausible(start):
        if not has_residual_encoding_artifact(start):
            return sorted(best.values(), key=lambda item: (item.score, -len(item.chain)), reverse=True)
        best[start] = Candidate(text=start, chain=(), score=best[start].score + FLAG_FOUND_OVERRIDE_BONUS - 10.0)
        frontier = [best[start]]
    try:
        if '%' in start or '+' in start:
            unq = decode_url(start)
            if unq and unq != start and unq not in best:
                best[unq] = Candidate(text=unq, chain=("url",), score=score_text(unq) + VALIDATED_DECODE_BONUS + url_legibility_bonus("url", unq))
                frontier.append(best[unq])
    except Exception as e: _log_debug(f"auto_decode: pre-pass unquote failed: {e!r}")
    for depth_index in range(max_depth):
        if progress_callback is not None:
            try: progress_callback(depth_index, max_depth, len(best))
            except Exception as e: _log_debug(f"auto_decode: progress_callback raised: {e!r}")
        next_frontier: list[Candidate] = []
        for candidate in frontier:
            for scheme, decoded in decode_once(candidate.text, candidate.chain):
                if decoded in best: continue
                base_score = score_text(decoded)
                bonus = 0.0
                if gets_validated_bonus(scheme):
                    if not (scheme in DENSE_LOW_CONFIDENCE_SCHEMES and len(decoded) < MIN_LENGTH_FOR_DENSE_BONUS):
                        bonus += VALIDATED_DECODE_BONUS
                    bonus += url_legibility_bonus(scheme, decoded) + unicode_legibility_bonus(scheme, decoded)
                else:
                    if scheme in {"base36", "base58", "base62"}:
                        if len(decoded) >= 6 and any(ch.isalpha() for ch in decoded) and not is_effectively_binary(decoded) and ("_" in decoded or "{" in decoded or decoded.isalnum()):
                            bonus += VALIDATED_DECODE_BONUS
                    else: bonus += substitution_legibility_bonus(scheme, decoded)
                new_chain = candidate.chain + (scheme,)
                chain_penalty = total_substitution_count(new_chain) * ALWAYS_SUCCEEDS_STEP_PENALTY
                new_candidate = Candidate(text=decoded, chain=new_chain, score=base_score + bonus - chain_penalty)
                best[decoded] = new_candidate
                next_frontier.append(new_candidate)
                if has_full_flag_pattern(decoded) and flag_context_is_plausible(decoded):
                    override_bonus = FLAG_FOUND_OVERRIDE_BONUS - (10.0 if has_residual_encoding_artifact(decoded) else 0.0)
                    winning_candidate = Candidate(text=new_candidate.text, chain=new_candidate.chain, score=new_candidate.score + override_bonus)
                    best[decoded] = winning_candidate
                    next_frontier[-1] = winning_candidate
        if not next_frontier: break
        frontier = sorted(next_frontier, key=lambda item: item.score, reverse=True)[:beam_size]
    if progress_callback is not None:
        try: progress_callback(max_depth, max_depth, len(best))
        except Exception as e: _log_debug(f"auto_decode: final progress_callback raised: {e!r}")
    return sorted(best.values(), key=lambda item: (item.score, -len(item.chain)), reverse=True)

def railfence_decode(text: str, rails: int) -> str | None:
    if rails < 2 or rails >= max(len(text), 2): return None
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    if not pattern: return None
    rail_index = [pattern[i % len(pattern)] for i in range(len(text))]
    counts = Counter(rail_index)
    slots = {r: [] for r in range(rails)}
    pos = 0
    for r in range(rails):
        for _ in range(counts.get(r, 0)):
            slots[r].append(text[pos]); pos += 1
    cursors = {r: 0 for r in range(rails)}
    out = []
    for r in rail_index:
        out.append(slots[r][cursors[r]]); cursors[r] += 1
    return "".join(out)

def vigenere_decode(text: str, key: str) -> str | None:
    key = re.sub(r"[^A-Za-z]", "", key)
    if not key: return None
    key_upper, out, ki = key.upper(), [], 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key_upper[ki % len(key_upper)]) - ord('A')
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base - shift) % 26 + base))
            ki += 1
        else: out.append(ch)
    return "".join(out)

def columnar_decode(text: str, key_width: int) -> str | None:
    if key_width < 2 or key_width >= max(len(text), 2): return None
    n = len(text)
    num_rows = math.ceil(n / key_width)
    num_full_cols = n % key_width or key_width
    col_lengths = [num_rows if c < num_full_cols else num_rows - 1 for c in range(key_width)]
    cols, pos = [], 0
    for length in col_lengths:
        cols.append(text[pos:pos + length]); pos += length
    out = []
    for r in range(num_rows):
        for c in range(key_width):
            if r < len(cols[c]): out.append(cols[c][r])
    return "".join(out)

def handle_manual_command(raw_input: str) -> bool:
    parts = raw_input.split(None, 2)
    if len(parts) < 3: return False
    cmd = parts[0].lower()
    if cmd == "railfence":
        try: rails = int(parts[1])
        except ValueError: return False
        res = railfence_decode(parts[2], rails)
        print(divider("Rail Fence Result") + f"\n{green(res) if res else dim('(invalid rail count for this input length)')}\n")
        return True
    if cmd == "vigenere":
        res = vigenere_decode(parts[2], parts[1])
        print(divider("Vigenère Result") + f"\n{green(res) if res else dim('(invalid key)')}\n")
        return True
    if cmd == "columnar":
        try: width = int(parts[1])
        except ValueError: return False
        res = columnar_decode(parts[2], width)
        print(divider("Columnar Transposition Result") + f"\n{green(res) if res else dim('(invalid key width for this input length)')}\n")
        return True
    return False

def read_payload(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle: return handle.read().strip()
    if args.value: return args.value
    raise SystemExit("Provide an encoded value or use -f/--file.")

def run_interactive(max_depth: int, beam_size: int, show_candidates: bool) -> None:
    print_banner()
    while True:
        print(divider())
        try: payload = input(cyan("encoded> ")).strip()
        except (EOFError, KeyboardInterrupt): print("\n" + dim("bye")); return
        if not payload: continue
        if payload.lower() in {"q", "quit", "exit"}: print(dim("bye")); return
        if payload.lower() == "c": clear_screen(); continue
        if payload.lower() in {"h", "help", "?"}: print_help(); continue
        if handle_manual_command(payload): continue
        _on_prog = lambda depth, total, explored: print_progress(depth, total, label=f"layer {depth}/{total} · {explored} explored")
        candidates = auto_decode(payload, max_depth=max_depth, beam_size=beam_size, progress_callback=_on_prog)
        clear_progress_line()
        print_result(candidates, show_candidates=show_candidates, raw_input=payload)
        print()

def main() -> None:
    parser = argparse.ArgumentParser(description="God-Tier Auto-decode multi-layer encoded text.")
    parser.add_argument("value", nargs="?", help="Encoded text to decode")
    parser.add_argument("-f", "--file", help="Read encoded text from a file")
    parser.add_argument("-m", "--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="Maximum decode layers")
    parser.add_argument("-b", "--beam-size", type=int, default=DEFAULT_BEAM_SIZE, help="Number of candidates to keep per layer")
    parser.add_argument("--show-candidates", action="store_true", help="Print top candidate results")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of human output")
    args = parser.parse_args()
    if not args.value and not args.file:
        run_interactive(max_depth=args.max_depth, beam_size=args.beam_size, show_candidates=False)
        return
    payload = read_payload(args)
    _on_prog = lambda depth, total, explored: (print_progress(depth, total, label=f"layer {depth}/{total} · {explored} explored") if not args.json else None)
    candidates = auto_decode(payload, max_depth=args.max_depth, beam_size=args.beam_size, progress_callback=_on_prog)
    if not args.json:
        clear_progress_line()
        print_result(candidates, show_candidates=args.show_candidates, candidate_count=10, raw_input=payload)
    else:
        if sys.stdout.encoding.lower() != 'utf-8': sys.stdout.reconfigure(encoding='utf-8')
        print(json.dumps(format_result_json(candidates, candidate_count=10, raw_input=payload), ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
