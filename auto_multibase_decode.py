#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import importlib.util
import zlib
import bz2
import lzma

if importlib.util.find_spec("zstandard") is not None:
    import zstandard as zstd
else:
    zstd = None

import math
import os
import textwrap
import re
import shutil
import string
import sys
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Iterable

PRINTABLE = set(string.printable)

ENGLISH_LETTER_FREQ = {
    "e": 12.70, "t": 9.06, "a": 8.17, "o": 7.51, "i": 6.97, "n": 6.75,
    "s": 6.33, "h": 6.09, "r": 5.99, "d": 4.25, "l": 4.03, "c": 2.78,
    "u": 2.76, "m": 2.41, "w": 2.36, "f": 2.23, "g": 2.02, "y": 1.97,
    "p": 1.93, "b": 1.29, "v": 0.98, "k": 0.77, "j": 0.15, "x": 0.15,
    "q": 0.10, "z": 0.07,
}

def english_chi_squared(text: str) -> float | None:
    letters = [ch.lower() for ch in text if ch.isalpha()]
    n = len(letters)
    if n < 5:
        return None
    counts = Counter(letters)
    chi2 = 0.0
    for letter, expected_pct in ENGLISH_LETTER_FREQ.items():
        expected = expected_pct / 100.0 * n
        observed = counts.get(letter, 0)
        chi2 += (observed - expected) ** 2 / expected
    return chi2
COMMON_WORDS = (
    "the", "and", "you", "that", "hello", "world",
    "password", "secret", "http", "https", "admin", "root", "user",
    "hack", "pwn", "shell", "exploit", "payload", "firewall", "network", "intrusion"
)
DEFAULT_MAX_DEPTH = 15
DEFAULT_BEAM_SIZE = 320
DEFAULT_CANDIDATE_COUNT = 5
MAX_CONSECUTIVE_SUBSTITUTION = 2

BASE36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
Z85_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
BASE91_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)
BASE92_ALPHABET = (
    "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_"
    "abcdefghijklmnopqrstuvwxyz{|}"
)

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
        if text and not mostly_binary(text):
            return text
    return None

def mostly_binary(text: str) -> bool:
    if not text:
        return True
    bad = sum(1 for ch in text if ch not in PRINTABLE and ch not in "\n\r\t")
    return bad / len(text) > 0.15

def add_base64_padding(value: str) -> str:
    return value + ("=" * ((4 - len(value) % 4) % 4))

def decode_base2(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if not compact or len(compact) % 8 != 0 or not set(compact).issubset({'0', '1'}):
        return None
    try:
        raw = int(compact, 2).to_bytes(len(compact) // 8, byteorder='big')
        return bytes_to_text(raw)
    except ValueError:
        return None

def decode_base16(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2 or len(compact) % 2:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return None
    return bytes_to_text(bytes.fromhex(compact))

def decode_base32(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)

    # permissive pre-clean: remove common separators used in some variants
    compact = compact.replace('-', '').replace('.', '').replace('_', '')

    # If input looks URL-encoded, try unquoting first (heuristic for URL↔base32 chains)
    if '%' in compact or '+' in compact:
        try:
            unq = urllib.parse.unquote(compact)
            if unq and unq != compact:
                compact = unq
        except Exception:
            pass

    s = compact.upper().rstrip('=')

    # helper to pad to multiple of 8 for base32
    def pad32(t: str) -> str:
        pad = (-len(t)) % 8
        return t + ('=' * pad)

    # Try standard base32 (casefold and padding tolerant)
    if re.fullmatch(r"[A-Z2-7]+=*", s) and len(s) >= 2:
        try:
            decoded = bytes_to_text(base64.b32decode(pad32(s), casefold=True))
            if decoded is not None:
                return decoded
        except (binascii.Error, ValueError):
            pass

    # Try forgiving variants: remove separators and try again
    alt = re.sub(r"[\-_.]", "", value).upper().rstrip('=')
    if alt != s and re.fullmatch(r"[A-Z2-7]+=*", alt):
        try:
            decoded = bytes_to_text(base64.b32decode(pad32(alt), casefold=True))
            if decoded is not None:
                return decoded
        except Exception:
            pass

    # Try base32hex (RFC 4648 "extended hex") by translating alphabet
    BASE32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    STANDARD_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    cleaned = re.sub(r"=+", "", s)
    if re.fullmatch(r"[0-9A-V]+", cleaned) and len(cleaned) >= 2:
        try:
            mapped = ''.join(STANDARD_B32[BASE32HEX.index(ch)] for ch in cleaned)
            decoded = bytes_to_text(base64.b32decode(pad32(mapped), casefold=True))
            if decoded is not None:
                return decoded
        except Exception:
            pass

    return None

def decode_base64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
        return None
    try:
        return bytes_to_text(base64.b64decode(add_base64_padding(compact), validate=True))
    except (binascii.Error, ValueError):
        return None

def decode_base64url(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 4 or not re.fullmatch(r"[A-Za-z0-9_-]+=*", compact):
        return None
    try:
        return bytes_to_text(base64.urlsafe_b64decode(add_base64_padding(compact)))
    except (binascii.Error, ValueError):
        return None

def decode_int_alphabet(value: str, alphabet: str) -> bytes | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2 or any(ch not in alphabet for ch in compact):
        return None
    base = len(alphabet)
    number = 0
    for ch in compact:
        number = number * base + alphabet.index(ch)
    leading_zeroes = len(compact) - len(compact.lstrip(alphabet[0]))
    raw = b"\x00" * leading_zeroes
    if number:
        raw += number.to_bytes((number.bit_length() + 7) // 8, "big")
    return raw or None

def decode_base36(value: str) -> str | None:
    raw = decode_int_alphabet(value.lower(), BASE36_ALPHABET)
    return bytes_to_text(raw) if raw else None

def decode_base45(value: str) -> str | None:
    compact = value.strip().replace("\n", "").replace("\r", "")
    if not compact or any(ch not in BASE45_ALPHABET for ch in compact):
        return None

    table = {ch: i for i, ch in enumerate(BASE45_ALPHABET)}
    output = bytearray()

    for i in range(0, len(compact), 3):
        chunk = compact[i:i+3]
        if len(chunk) == 3:
            val = table[chunk[0]] + table[chunk[1]] * 45 + table[chunk[2]] * 45 * 45
            if val > 0xFFFF:
                return None
            output.extend(val.to_bytes(2, "big"))
        elif len(chunk) == 2:
            val = table[chunk[0]] + table[chunk[1]] * 45
            if val > 0xFF:
                return None
            output.extend(val.to_bytes(1, "big"))
        else:
            return None

    return bytes_to_text(bytes(output))

def decode_base58(value: str) -> str | None:
    raw = decode_int_alphabet(value, BASE58_ALPHABET)
    return bytes_to_text(raw) if raw else None

def decode_base62(value: str) -> str | None:
    raw = decode_int_alphabet(value, BASE62_ALPHABET)
    return bytes_to_text(raw) if raw else None

def decode_base85(value: str) -> str | None:
    compact = value.strip()
    if len(compact) < 5:
        return None
    try:
        return bytes_to_text(base64.b85decode(compact))
    except (binascii.Error, ValueError):
        return None

def decode_ascii85(value: str) -> str | None:
    compact = value.strip()
    if len(compact) < 5:
        return None
    try:
        return bytes_to_text(base64.a85decode(compact, adobe=False))
    except (binascii.Error, ValueError):
        return None

def decode_z85(value: str) -> str | None:
    compact = value.strip().replace("\n", "").replace("\r", "")
    if len(compact) % 5 != 0 or any(ch not in Z85_ALPHABET for ch in compact):
        return None
    table = {ch: i for i, ch in enumerate(Z85_ALPHABET)}
    output = bytearray()
    for i in range(0, len(compact), 5):
        chunk = compact[i:i+5]
        val = sum(table[c] * (85 ** (4 - j)) for j, c in enumerate(chunk))
        if val > 0xFFFFFFFF:
            return None
        output.extend(val.to_bytes(4, "big"))
    return bytes_to_text(bytes(output))

def decode_base91(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2 or any(ch not in BASE91_ALPHABET for ch in compact):
        return None
    table = {ch: index for index, ch in enumerate(BASE91_ALPHABET)}
    output = bytearray()
    accumulator = 0
    bit_count = 0
    pending = -1
    for ch in compact:
        current = table[ch]
        if pending < 0:
            pending = current
            continue
        pending += current * 91
        accumulator |= pending << bit_count
        bit_count += 13 if (pending & 8191) > 88 else 14
        while bit_count > 7:
            output.append(accumulator & 255)
            accumulator >>= 8
            bit_count -= 8
        pending = -1
    if pending >= 0:
        output.append((accumulator | pending << bit_count) & 255)
    return bytes_to_text(bytes(output))

def decode_base92(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if compact == "~": return ""
    if len(compact) < 2 or any(ch not in BASE92_ALPHABET for ch in compact):
        return None
    try:
        decoding = {ch: index for index, ch in enumerate(BASE92_ALPHABET)}
        output = bytearray()
        buffer = 0
        length = 0
        if len(compact) % 2:
            tail_bits = 6
            tail = decoding[compact[-1]]
            body = compact[:-1]
        else:
            tail_bits = 13
            tail = decoding[compact[-2]] * 91 + decoding[compact[-1]]
            body = compact[:-2]
        for index in range(0, len(body), 2):
            block = decoding[body[index]] * 91 + decoding[body[index + 1]]
            buffer = (buffer << 13) | block
            length += 13
            size, length = divmod(length, 8)
            output.extend((buffer >> length).to_bytes(size, "big"))
            buffer &= (1 << length) - 1
        missing = 8 - length
        shift = tail_bits - missing
        if shift < 8:
            byte_count = 1
        else:
            byte_count = 2
            shift -= 8
            missing += 8
        if shift < 0:
            return None
        buffer = (buffer << missing) | (tail >> shift)
        output.extend(buffer.to_bytes(byte_count, "big"))
        if tail & ((1 << shift) - 1):
            return None
        return bytes_to_text(bytes(output))
    except (OverflowError, KeyError, ValueError):
        return None

def decode_morse(value: str) -> str | None:
    table = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
        "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
        "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
        "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
        "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
        "---..": "8", "----.": "9",
    }
    compact = value.strip()
    if not compact or not re.fullmatch(r"[.\-\s/]+", compact):
        return None
    words = re.split(r"\s*/\s*|\s{2,}", compact)
    out_words = []
    for word in words:
        letters = [table.get(tok) for tok in word.split()]
        if not letters or any(letter is None for letter in letters):
            return None
        out_words.append("".join(letters))
    result = " ".join(out_words).strip()
    return result or None

def decode_url(value: str) -> str | None:
    compact = value.strip()
    if "%" not in compact and "+" not in compact:
        return None
    if not re.search(r"%[0-9A-Fa-f]{2}", compact):
        return None
    try:
        decoded = urllib.parse.unquote(compact, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded if decoded != compact else None

def decode_gzip(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    # try hex
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0:
        try:
            raw = bytes.fromhex(compact)
            out = gzip.decompress(raw)
            return bytes_to_text(out)
        except Exception:
            pass

    # try base64
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
        try:
            raw = base64.b64decode(add_base64_padding(compact))
            out = gzip.decompress(raw)
            return bytes_to_text(out)
        except Exception:
            pass

    # try raw bytes (latin-1 passthrough)
    try:
        raw = value.encode("latin-1")
        out = gzip.decompress(raw)
        return bytes_to_text(out)
    except Exception:
        return None

def decode_zlib(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    # try hex
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0:
        try:
            raw = bytes.fromhex(compact)
            # try zlib wrapper first
            try:
                out = zlib.decompress(raw)
                return bytes_to_text(out)
            except Exception:
                # try raw DEFLATE
                out = zlib.decompress(raw, wbits=-15)
                return bytes_to_text(out)
        except Exception:
            pass

    # try base64
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
        try:
            raw = base64.b64decode(add_base64_padding(compact))
            try:
                out = zlib.decompress(raw)
                return bytes_to_text(out)
            except Exception:
                out = zlib.decompress(raw, wbits=-15)
                return bytes_to_text(out)
        except Exception:
            pass

    # try raw bytes
    try:
        raw = value.encode("latin-1")
        try:
            out = zlib.decompress(raw)
            return bytes_to_text(out)
        except Exception:
            out = zlib.decompress(raw, wbits=-15)
            return bytes_to_text(out)
    except Exception:
        return None

def decode_bzip2(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    # try hex
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0:
        try:
            raw = bytes.fromhex(compact)
            out = bz2.decompress(raw)
            return bytes_to_text(out)
        except Exception:
            pass
    # try base64
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
        try:
            raw = base64.b64decode(add_base64_padding(compact))
            out = bz2.decompress(raw)
            return bytes_to_text(out)
        except Exception:
            pass
    # raw bytes
    try:
        raw = value.encode("latin-1")
        out = bz2.decompress(raw)
        return bytes_to_text(out)
    except Exception:
        return None

def decode_xz(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    # try hex
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0:
        try:
            raw = bytes.fromhex(compact)
            out = lzma.decompress(raw)
            return bytes_to_text(out)
        except Exception:
            pass
    # try base64
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
        try:
            raw = base64.b64decode(add_base64_padding(compact))
            out = lzma.decompress(raw)
            return bytes_to_text(out)
        except Exception:
            pass
    # raw bytes
    try:
        raw = value.encode("latin-1")
        out = lzma.decompress(raw)
        return bytes_to_text(out)
    except Exception:
        return None

def decode_zstd(value: str) -> str | None:
    if zstd is None:
        return None
    compact = re.sub(r"\s+", "", value)
    try:
        # try hex
        if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0:
            raw = bytes.fromhex(compact)
            dctx = zstd.ZstdDecompressor()
            out = dctx.decompress(raw)
            return bytes_to_text(out)
        # try base64
        if re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
            raw = base64.b64decode(add_base64_padding(compact))
            dctx = zstd.ZstdDecompressor()
            out = dctx.decompress(raw)
            return bytes_to_text(out)
        # try raw
        raw = value.encode("latin-1")
        dctx = zstd.ZstdDecompressor()
        out = dctx.decompress(raw)
        return bytes_to_text(out)
    except Exception:
        return None

DECODERS: tuple[tuple[str, Callable[[str], str | None]], ...] = (
    ("base64", decode_base64),
    ("base64url", decode_base64url),
    ("base32", decode_base32),
    ("base16", decode_base16),
    ("base2", decode_base2),
    ("gzip", decode_gzip),
    ("zlib", decode_zlib),
    ("bzip2", decode_bzip2),
    ("xz", decode_xz),
    ("zstd", decode_zstd),
    ("url", decode_url),
    ("base45", decode_base45),
    ("base85", decode_base85),
    ("ascii85", decode_ascii85),
    ("z85", decode_z85),
    ("base91", decode_base91),
    ("base92", decode_base92),
    ("morse", decode_morse),
    ("base36", decode_base36),
    ("base58", decode_base58),
    ("base62", decode_base62),
)

def looks_like_rotatable_text(text: str) -> bool:
    if len(text) < 3:
        return False
    if not any(ch.isalpha() for ch in text):
        return False
    return True

def rot_n(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if 'a' <= ch <= 'z':
            out.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            out.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else:
            out.append(ch)
    return "".join(out)

def decode_rot_all(value: str) -> list[tuple[str, str]]:
    # หมายเหตุเรื่องการตั้งชื่อ: shift ที่ใช้ "ถอด" (บวกเพื่อย้อนกลับ) กับ
    # shift ที่คนใช้ "เข้ารหัส" ไม่ใช่ตัวเดียวกัน — เข้ารหัสด้วย ROT-S (บวก S)
    # ต้องถอดด้วยการบวก (26-S) mod 26 ไม่ใช่ S เอง ถ้าเราถอดสำเร็จตอน
    # shift=K แปลว่าตอนเข้ารหัสจริงๆ ใช้ shift=(26-K) mod 26 — ต้องโชว์ชื่อ
    # chain เป็นเลข shift ตอน "เข้ารหัส" (26-K) เพราะนั่นคือเลขที่คนพิมพ์ใส่
    # เครื่องมือเข้ารหัสจริง ไม่ใช่เลข K ที่เราบวกเพื่อย้อนกลับ
    if not looks_like_rotatable_text(value):
        return []
    results = []
    for shift in range(1, 26):
        candidate = rot_n(value, shift)
        if candidate != value:
            encode_shift = (26 - shift) % 26
            results.append((f"rot{encode_shift}", candidate))
    return results

def rot47(text: str) -> str:
    out = []
    for ch in text:
        code = ord(ch)
        if 33 <= code <= 126:
            out.append(chr(33 + (code + 47 - 33) % 94))
        else:
            out.append(ch)
    return "".join(out)

def decode_rot47(value: str) -> str | None:
    if not looks_like_rotatable_text(value):
        return None
    candidate = rot47(value)
    return candidate if candidate != value else None

def atbash(text: str) -> str:
    out = []
    for ch in text:
        if 'a' <= ch <= 'z':
            out.append(chr(ord('z') - (ord(ch) - ord('a'))))
        elif 'A' <= ch <= 'Z':
            out.append(chr(ord('Z') - (ord(ch) - ord('A'))))
        else:
            out.append(ch)
    return "".join(out)

def decode_atbash(value: str) -> str | None:
    if not looks_like_rotatable_text(value):
        return None
    candidate = atbash(value)
    return candidate if candidate != value else None

SUBSTITUTION_DECODERS: tuple[tuple[str, Callable[[str], str | None]], ...] = (
    ("rot47", decode_rot47),
    ("atbash", decode_atbash),
)

def is_substitution_scheme(name: str) -> bool:
    return name.startswith("rot") or name == "atbash"

# โบนัสสำหรับ decoder ที่ "fail ได้จริง" (กลุ่ม DECODERS: base*, morse, url)
# ต่างจาก ROT/atbash ที่ decode สำเร็จเสมอไม่มีทางล้มเหลว การที่ decoder
# กลุ่มนี้ผ่าน validation ได้ (charset ถูกต้องเป๊ะ, padding/bit-alignment
# ลงตัว ฯลฯ) คือสัญญาณที่เชื่อถือได้ว่ากำลังเดินถูกทาง แม้ผลลัพธ์ที่ได้จะยัง
# ไม่ใช่ plaintext ที่อ่านออก (เช่น base92 ที่ต้องถอด base58/base32 ต่ออีก)
# ก็ตาม ถ้าไม่ให้โบนัสนี้ ผลลัพธ์ระดับกลางแบบนี้จะแพ้ให้กับสตริงที่ถูก
# rot/atbash สับไปเรื่อยๆ ซึ่งบังเอิญยังมีหน้าตาเป็นตัวอักษรอยู่ (คะแนน
# printable/alpha ใกล้เคียงกัน) ทั้งที่ไม่ได้นำไปสู่คำตอบจริงเลย
VALIDATED_DECODE_BONUS = 8.0

# base36/base58/base62 ไม่มี padding หรือ checksum ใดๆ เลย — มันแค่ตีความ
# สตริงที่อยู่ใน alphabet ของมันเป็นเลขจำนวนเต็มตัวใหญ่ ดังนั้น "แทบทุก"
# สตริงตัวอักษร/ตัวเลขสั้นๆ จะ "valid" เสมอ (คล้าย ROT ที่ไม่มีวันล้มเหลว)
# ถ้าให้โบนัสด้วยจะกลายเป็นช่องโหว่ใหม่: string สุ่มที่ไม่เกี่ยวอะไรเลย
# จะได้ +4 ฟรีๆ แค่เพราะมันบังเอิญเป็นตัวอักษร/ตัวเลข จึงต้องกันสามตัวนี้
# ออกจากรายการที่ได้โบนัส (ยังใช้เป็น candidate ในการค้นหาได้ตามปกติ
# เพียงแต่ไม่ได้อภิสิทธิ์คะแนนพิเศษ)
WEAK_VALIDATION_SCHEMES = {"base36", "base58", "base62"}

def gets_validated_bonus(scheme: str) -> bool:
    return not is_substitution_scheme(scheme) and scheme not in WEAK_VALIDATION_SCHEMES

def trailing_substitution_run(chain: tuple[str, ...]) -> int:
    count = 0
    for scheme in reversed(chain):
        if is_substitution_scheme(scheme):
            count += 1
        else:
            break
    return count

def has_boundaried_token(text: str, word: str) -> bool:
    for match in re.finditer(re.escape(word), text, re.IGNORECASE):
        token = match.group()
        start, end = match.start(), match.end()
        if token.isupper():
            # ตัวพิมพ์ใหญ่ล้วน (เช่น "CTF" ใน "TeammerCTFF") ถือเป็น token
            # ที่เด่นชัดในตัวเองอยู่แล้ว แค่เช็คว่าไม่ได้ต่อเนื่องมาจากตัว
            # พิมพ์เล็กก่อนหน้า (ถ้าใช่ = camelCase boundary ที่ต้องการ)
            # ไม่ต้องสนใจว่าหลังจากนี้จะมีอะไรต่อ (อาจมีตัวพิมพ์ใหญ่ต่อ
            # อีกได้ เช่น "CTFF" ก็ยังนับเป็น token เดียวกัน)
            before_ok = (
                start == 0
                or not text[start - 1].isalnum()
                or text[start - 1].islower()
            )
            if before_ok:
                return True
            continue
        before_ok = start == 0 or not text[start - 1].isalnum()
        after_ok = end == len(text) or not text[end].isalnum()
        if before_ok and after_ok:
            return True
    return False

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {ch: text.count(ch) for ch in set(text)}
    return -sum((count / len(text)) * math.log2(count / len(text)) for count in counts.values())

def score_text(text: str) -> float:
    if not text:
        return -999.0

    printable_ratio = sum(1 for ch in text if ch in PRINTABLE or ch in "\n\r\t") / len(text)
    alpha_space_ratio = sum(1 for ch in text if ch.isalnum() or ch in " _-{}[]():;,.!?/@#$%^&*+=\n\r\t") / len(text)

    lower = text.lower()
    word_bonus = sum(2.0 for word in COMMON_WORDS if word in lower)

    flag_bonus = 0.0
    if re.search(r"(flag|ctf)[\{_\-:]", lower):
        flag_bonus = 10.0
    elif has_boundaried_token(text, "ctf") or has_boundaried_token(text, "flag"):
        # โผล่มาแบบมีขอบเขตจริง (แยกด้วยอักขระที่ไม่ใช่ตัวอักษร/ตัวเลข หรือ
        # เป็นรอยต่อ camelCase เช่น "...merCTF") น่าเชื่อกว่าการเจอเป็น
        # substring ลอยๆ กลางคำ (เช่น "...rctfa..." ซึ่งเกิดจาก ROT shift
        # ผิดได้ง่ายๆ โดยบังเอิญ) จึงยังให้คะแนนได้ แต่ไม่มากเท่าที่มี
        # delimiter ชัดเจนแบบ flag{...}
        flag_bonus = 3.0

    entropy = shannon_entropy(text)
    entropy_penalty = abs(entropy - 4.2) * 0.5
    length_bonus = min(len(text), 80) / 80

    if " " not in text and len(text) > 20 and word_bonus == 0 and ctf_style_bonus == 0:
        length_bonus = -3.0

    ctf_style_bonus = 0.0
    if any(ch.isdigit() for ch in text) and any(ch.isalpha() for ch in text):
        if "_" in text or "{" in text or "}" in text or "-" in text:
            ctf_style_bonus = 2.0

    if any(ch.isdigit() for ch in text) and any(ch.isalpha() for ch in text) and "_" in text:
        ctf_style_bonus = max(ctf_style_bonus, 2.5)

    # chi-squared penalty: ยิ่งการกระจายตัวของตัวอักษรใกล้เคียงภาษาอังกฤษ
    # ปกติ (E มากสุด, Z น้อยสุด ฯลฯ) ยิ่ง chi2 ต่ำ ยิ่งน่าเชื่อว่าเป็นข้อความ
    # จริง ส่วนสตริงสุ่ม/ยังไม่ถอด หรือ ROT shift ผิด จะมีการกระจายตัวเพี้ยน
    # ไปจากธรรมชาติของภาษาอังกฤษ ทำให้ chi2 สูงกว่ามาก ตัวหารคงที่ (140) ถูก
    # ปรับจากการทดสอบจริงเพื่อไม่ให้กลบคะแนนจาก word_bonus/flag_bonus
    chi2 = english_chi_squared(text)
    if chi2 is not None:
        chi2_penalty = min(chi2 / 140.0, 6.0)
    elif len(text) >= 5:
        # ตัวอักษรน้อยเกินไปจะคำนวณ chi2 ไม่ได้ (คืน None) แต่ถ้าสตริงยาว
        # พอสมควรแล้วมีตัวอักษรน้อยขนาดนี้ (ส่วนใหญ่เป็นสัญลักษณ์/ตัวเลข
        # จาก rot47 ที่สับไปมา) ก็ไม่ใช่ข้อความจริงเช่นกัน ต้องโดนปรับคะแนน
        # ไม่ใช่ปล่อยผ่านฟรีๆ ไม่งั้นจะหนีบทลงโทษ chi2 ไปได้ง่ายๆ
        chi2_penalty = 1.5
    else:
        chi2_penalty = 0.0

    return (
        printable_ratio * 8
        + alpha_space_ratio * 5
        + word_bonus
        + flag_bonus
        + ctf_style_bonus
        + length_bonus
        - entropy_penalty
        - chi2_penalty
    )

def safe_preview(text: str, limit: int = 120) -> str:
    preview = text.encode("unicode_escape", errors="backslashreplace").decode("ascii")
    if len(preview) > limit:
        preview = preview[: limit - 3] + "..."
    return preview

def terminal_width() -> int:
    return max(72, min(shutil.get_terminal_size((96, 24)).columns, 120))

def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty() or os.name == "nt"

USE_COLOR = supports_color()

def color(text: str, code: str) -> str:
    if not USE_COLOR: return text
    return f"\033[{code}m{text}\033[0m"

def cyan(text: str) -> str: return color(text, "36")
def green(text: str) -> str: return color(text, "32")
def yellow(text: str) -> str: return color(text, "33")
def dim(text: str) -> str: return color(text, "2")

def clear_screen() -> None:
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

def divider(title: str = "") -> str:
    width = terminal_width()
    if not title:
        return dim("-" * width)
    label = f" {title} "
    left = max(2, (width - len(label)) // 2)
    right = max(2, width - left - len(label))
    return dim("-" * left) + cyan(label) + dim("-" * right)

def print_banner() -> None:
    width = terminal_width()
    art = [
        "╔═════════════════════════════════════════════════════════════════════════════════════════════════╗",
        "║ [ - ] [ □ ] [ x ]    SYSTEM_CONSOLE_v2.0    [ STATUS: ONLINE ]    [ ACCESS: ENCRYPTED ]         ║",
        "╠═════════════════════════════════════════════════════════════════════════════════════════════════╣",
        "║                                                                                                 ║",
        "║ ████████╗███████╗ █████╗ ███╗   ███╗    ██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗       ║",
        "║ ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝       ║",
        "║    ██║   █████╗  ███████║██╔████╔██║    ██║  ██║█████╗  ██║     ██║   ██║██║  ██║█████╗         ║",
        "║    ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║    ██║  ██║██╔══╝  ██║     ██║   ██║██║  ██║██╔══╝         ║",
        "║    ██║   ███████╗██║  ██║██║ ╚═╝ ██║    ██████╔╝███████╗╚██████╗╚██████╔╝██████╔╝███████╗       ║",
        "║    ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝    ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝       ║",
        "║                                                                                                 ║",
        "╠═════════════════════════════════════════════════════════════════════════════════════════════════╣",
        "╠═════════════════════════════════════════════════════════════════════════════════════════════════╣",
        "║ > root@localhost:/home/team_decode# _                                                           ║",
        "║                                                                                                 ║",
        "╚═════════════════════════════════════════════════════════════════════════════════════════════════╝"
    ]

    # Compact two-line crypto summary (label + short summary below)
    crypto_label = "CRYPTO UTILITY — SECURE MULTIBASE DECODER 🔑"
    summary = "20+ encodings • smart heuristics • safe preview"

    # Top separator before crypto block (with a blank line after)
    print(cyan("=" * width))
    print()
    print(color(crypto_label.center(width), "1;33"))
    print(color(summary.center(width), "1;33"))
    print()

    # Stylized supported encodings with grouped columns for readability
    groups = [
        ("Binary", ["base2"]),
        ("Radix/Base", ["base16", "base32", "base36", "base45", "base58", "base62", "base64", "base64url"]),
        ("High-enc", ["base85", "ascii85", "z85", "base91", "base92"]),
        ("Text/Other", ["morse", "url", "rotN", "rot47", "atbash"]),
    ]
    col_count = len(groups)
    col_width = max(20, width // col_count)

    # Header row for groups
    header_row = "".join(cyan(title.center(col_width)) for title, _ in groups)
    print(header_row.center(width))

    # Prepare wrapped item lines per column for neat alignment
    wrapped_lists: list[list[str]] = []
    for _, items in groups:
        joined = ", ".join(items)
        wrapped = textwrap.wrap(joined, width=col_width - 2) or [""]
        wrapped_lists.append(wrapped)

    max_lines = max(len(w) for w in wrapped_lists)
    for i in range(max_lines):
        row = ""
        for w in wrapped_lists:
            part = w[i] if i < len(w) else ""
            row += dim(part.center(col_width))
        print(row.center(width))
    print()

    print(cyan("=" * width))
    for line in art:
        print(green(line.center(width)))
    print()

    # Commands (left) and credit (right) on the same bottom line
    commands_line = "🏠 q = quit 🧹 c = clear ❓  h/help/? = help   ⏎ empty = input"
    credit = "💳 Create by Mr.Suchakree Panyawong"
    gap = 4
    line = yellow(commands_line) + " " * gap + color(credit, "1;35")
    print(line)
    # Bottom separator after commands
    print()
    print(cyan("=" * width))


def print_help() -> None:
    print(divider("Help"))
    print("Paste one encoded value per prompt. The tool will recursively try known decoders.")
    print("The decode chain is shown in the order used to decode.")
    print("Commands Quick: q = quit, c = clear terminal, h/help/? = show help, empty input = new prompt")
    print()

def print_result(candidates: list[Candidate], show_candidates: bool, candidate_count: int = DEFAULT_CANDIDATE_COUNT) -> None:
    winner = candidates[0]
    chain = " -> ".join(winner.chain) if winner.chain else "(input looked already decoded)"

    print(divider("Best Guess"))
    print(green(winner.text))
    print()
    print(cyan("Decode chain: ") + chain)
    print(dim(f"Score: {winner.score:.2f}"))

    if show_candidates:
        print()
        print(divider("Top Candidates"))
        for index, candidate in enumerate(candidates[:candidate_count], start=1):
            candidate_chain = " -> ".join(candidate.chain) if candidate.chain else "original"
            preview = safe_preview(candidate.text)
            print(f"{yellow(f'{index:02d}.')} score={candidate.score:.2f}  chain={candidate_chain}")
            print(f"    {preview}")

def decode_once(value: str, chain: tuple[str, ...] = ()) -> Iterable[tuple[str, str]]:
    for name, decoder in DECODERS:
        try:
            decoded = decoder(value)
        except Exception:
            continue
        if not decoded:
            continue
        decoded = decoded.strip()
        if not decoded or decoded == value:
            continue
        yield name, decoded

    # เช็คว่า chain ปัจจุบันมี substitution cipher (rot-family/atbash) ต่อกัน
    # ติดๆ กี่ชั้นแล้ว ถ้าครบเพดานแล้ว (MAX_CONSECUTIVE_SUBSTITUTION) ไม่ต้อง
    # เปิดชั้นต่อไปด้วย substitution อีก เพราะมันคืนคำตอบได้เสมอ (reversible)
    # ไม่มีทาง fail เอง ถ้าปล่อยไม่จำกัดจะขยายพื้นที่ค้นหาไปเรื่อยๆ ด้วยสตริง
    # ที่ไม่มีความหมาย แล้วไปแย่งที่ในบีมจากคำตอบที่ถูกต้องจริงๆ
    if trailing_substitution_run(chain) < MAX_CONSECUTIVE_SUBSTITUTION:
        try:
            rot_candidates = decode_rot_all(value)
        except Exception:
            rot_candidates = []
        for name, decoded in rot_candidates:
            decoded = decoded.strip()
            if not decoded or decoded == value:
                continue
            yield name, decoded

        for name, decoder in SUBSTITUTION_DECODERS:
            try:
                decoded = decoder(value)
            except Exception:
                continue
            if not decoded:
                continue
            decoded = decoded.strip()
            if not decoded or decoded == value:
                continue
            yield name, decoded

def auto_decode(value: str, max_depth: int = 15, beam_size: int = 25) -> list[Candidate]:
    start = normalize_input(value)
    best: dict[str, Candidate] = {
        start: Candidate(text=start, chain=(), score=score_text(start))
    }
    frontier = [best[start]]

    # Conservative global pre-pass: if input appears URL-encoded, add an
    # unquoted variant as an initial candidate so chains like URL -> base32 are
    # discovered early without destroying original behavior.
    try:
        if '%' in start or '+' in start:
            unq = urllib.parse.unquote(start)
            unq = unq.strip()
            if unq and unq != start and not mostly_binary(unq) and unq not in best:
                best[unq] = Candidate(text=unq, chain=("url",), score=score_text(unq) + VALIDATED_DECODE_BONUS)
                frontier.append(best[unq])
    except Exception:
        pass

    for _ in range(max_depth):
        next_frontier: list[Candidate] = []
        for candidate in frontier:
            for scheme, decoded in decode_once(candidate.text, candidate.chain):
                if decoded in best:
                    continue
                # ไม่มีการบวกโบนัสตามความยาว chain อีกต่อไป (ของเดิมคือ
                # + len(candidate.chain) * 0.2) เพราะสร้างแรงจูงใจผิดๆ ให้
                # ระบบชอบ chain ที่ยาวกว่าทั้งที่คุณภาพข้อความแย่กว่า
                # (โดยเฉพาะกับ rot/rot47/atbash ที่ decode สำเร็จเสมอ)
                # ตอนนี้ตัดสินจากคุณภาพข้อความล้วนๆ ผ่าน score_text()
                base_score = score_text(decoded)
                bonus = 0.0
                # Give validated-decode bonus to decoders that reliably fail on invalid input
                if gets_validated_bonus(scheme):
                    bonus += VALIDATED_DECODE_BONUS
                else:
                    # For weak schemes (base36/base58/base62), give a small
                    # conditional bonus if the decoded text looks plausibly structured
                    if scheme in {"base36", "base58", "base62"}:
                        if (
                            len(decoded) >= 6
                            and any(ch.isalpha() for ch in decoded)
                            and not mostly_binary(decoded)
                            and ("_" in decoded or "{" in decoded or decoded.isalnum())
                        ):
                            # stronger bonus for structured results (flags, underscores, mixed alnum)
                            bonus += VALIDATED_DECODE_BONUS

                new_candidate = Candidate(
                    text=decoded,
                    chain=candidate.chain + (scheme,),
                    score=base_score + bonus,
                )
                best[decoded] = new_candidate
                next_frontier.append(new_candidate)

        if not next_frontier:
            break

        frontier = sorted(next_frontier, key=lambda item: item.score, reverse=True)[:beam_size]

    # เรียงตามคะแนนก่อน แล้วถ้าคะแนนเท่ากันให้ chain สั้นกว่าชนะ (Occam's razor
    # — คำตอบที่ต้องผ่านหลายชั้นน้อยกว่าน่าเชื่อถือกว่าเมื่อคุณภาพเท่ากัน)
    return sorted(best.values(), key=lambda item: (item.score, -len(item.chain)), reverse=True)

def read_payload(args: argparse.Namespace) -> str:
    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    if args.value:
        return args.value
    raise SystemExit("Provide an encoded value or use -f/--file.")

def run_interactive(max_depth: int, beam_size: int, show_candidates: bool) -> None:
    print_banner()

    while True:
        print(divider())
        try:
            payload = input(cyan("encoded> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print(dim("bye"))
            return

        if not payload:
            continue
        if payload.lower() in {"q", "quit", "exit"}:
            print(dim("bye"))
            return
        if payload.lower() == "c":
            clear_screen()
            continue
        if payload.lower() in {"h", "help", "?"}:
            print_help()
            continue

        candidates = auto_decode(payload, max_depth=max_depth, beam_size=beam_size)
        print_result(candidates, show_candidates=show_candidates)
        print()

def main() -> None:
    parser = argparse.ArgumentParser(description="God-Tier Auto-decode multi-layer encoded text.")
    parser.add_argument("value", nargs="?", help="Encoded text to decode")
    parser.add_argument("-f", "--file", help="Read encoded text from a file")
    parser.add_argument("-m", "--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="Maximum decode layers")
    parser.add_argument("-b", "--beam-size", type=int, default=DEFAULT_BEAM_SIZE, help="Number of candidates to keep per layer")
    parser.add_argument("--show-candidates", action="store_true", help="Print top candidate results")
    args = parser.parse_args()

    if not args.value and not args.file:
        run_interactive(
            max_depth=args.max_depth,
            beam_size=args.beam_size,
            show_candidates=False,
        )
        return

    payload = read_payload(args)
    candidates = auto_decode(payload, max_depth=args.max_depth, beam_size=args.beam_size)
    print_result(candidates, show_candidates=args.show_candidates, candidate_count=10)

if __name__ == "__main__":
    main()