```
    🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑
    ████████╗███████╗ █████╗ ███╗   ███╗   ██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗    [ SYSTEM: ONLINE   ] 
    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝    [ ENCRYPTION: ACTIVE ] 
       ██║   █████╗  ███████║██╔████╔██║   ██║  ██║█████╗  ██║     ██║   ██║██║  ██║█████╗      [ CONNECTION: SECURE ] 
       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║   ██║  ██║██╔══╝  ██║     ██║   ██║██║  ██║██╔══╝      [ ACCESS: GRANTED    ] 
       ██║   ███████╗██║  ██║██║ ╚═╝ ██║   ██████╔╝███████╗╚██████╗╚██████╔╝██████╔╝███████╗    [ ROOT@TEAM-DECODE:~ ] 
       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝   ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝    
    🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑
```

# Auto Multibase Decode

CRYPTO UTILITY — SECURE MULTIBASE DECODER 🔑  /   20+ encodings • smart heuristics • safe preview

เครื่องมือ Python สำหรับถอดรหัสข้อความที่เข้ารหัสหรือบีบอัดซ้อนกันหลายชั้นในสไตล์ CTF/Cybersec

## Overview

`auto_multibase_decode.py` คือ utility ที่ออกแบบมาให้สามารถรับ input เป็นสตริง encoded หลายชั้น แล้วพยายามถอดกลับจนได้ plaintext ที่อ่านออกได้โดยอัตโนมัติ

- รองรับการถอดแบบ multi-layer
- ใช้ heuristics และ scoring เพื่อคัด candidate ที่เป็นไปได้มากที่สุด
- ไม่ต้องรู้ล่วงหน้าว่า encoder ไหนถูกใช้
- เหมาะสำหรับงาน CTF, reverse engineering, forensic และ pentest

## Features

- รองรับ encoding/decoding หลายรูปแบบ
- รองรับ compression format ยอดนิยม
- ระบบ scoring อัจฉริยะที่ชั่งน้ำหนักความเป็นไปได้
- Beam search เพื่อค้นหา chain ที่ยาวอย่างมีประสิทธิภาพ
- โหมด interactive CLI
- `--show-candidates` เพื่อดู candidate อันดับต้น

## Supported Encoding Schemes

### Base / Radix
- `base2`
- `base16`
- `base32` (standard + forgiving separators + unpadded)
- `base32hex`
- `base36`
- `base45`
- `base58`
- `base62`
- `base64`
- `base64url`

### High-radix / ASCII encodings
- `base85`
- `ascii85`
- `z85`
- `base91`
- `base92`

### Compression
- `gzip`
- `zlib`
- `bzip2`
- `xz`
- `zstd` (optional)

### Text / Substitution
- `morse`
- `url`
- `rotN` / all ROT shifts
- `rot47`
- `atbash`

## Installation

1. Clone หรือ copy ไฟล์ไปไว้ใน repository ของคุณ
2. ตรวจสอบ Python 3.11+ หรือ Python 3.13 ขึ้นไป
3. ติดตั้ง optional dependency สำหรับ zstandard (ถ้าต้องการ)

```bash
python -m pip install zstandard
```

`zstandard` เป็น dependency เสริม ถ้าไม่มีเครื่องมือยังทำงานได้โดยไม่ต้องติดตั้ง

## Usage

### Run interactive mode

```bash
python auto_multibase_decode.py
```

### Decode from command line

```bash
python auto_multibase_decode.py "<encoded string>"
```

### Read from file

```bash
python auto_multibase_decode.py -f encoded.txt
```

### ปรับความลึกและ beam size

```bash
python auto_multibase_decode.py "<encoded string>" -m 15 -b 320
```

### แสดง candidate เพิ่มเติม

```bash
python auto_multibase_decode.py "<encoded string>" --show-candidates
```

## Magic Mode

โหมด "Magic Mode" ในที่นี้หมายถึงชุด heuristics ที่ออกแบบมาเพื่อจับ pattern CTF/Cyber ได้ดีขึ้น:

- ให้โบนัสกับข้อความที่มีลักษณะ `CTF{...}` และคำสำคัญทางความปลอดภัย
- ให้คะแนนสูงขึ้นกับสตริงที่มีตัวอักษร+ตัวเลขพร้อม `_`, `-`, `{`, `}`
- ลดน้ำหนัก chain ที่ไม่ใช่ plaintext ยาว ๆ แต่ไม่มี structure
- เรียงลำดับ decoder แบบ base64/base32/url ก่อน เพื่อจับลำดับ decoding ที่เป็นไปได้มากที่สุด

## Notes

- ผลลัพธ์ขึ้นอยู่กับค่าพารามิเตอร์ `max_depth` และ `beam_size`
- ถ้าต้องการจัดการ chain ยาว ๆ ให้เพิ่ม `-m` และ `-b`
- ระบบนี้ออกแบบมาให้เสถียร ไม่เพิ่ม XOR หรือ brute-force แบบไม่จำกัด

## License

This project is provided under the `SPT License`.

```
SPT License

Copyright (c) 2026

 # Auto Multibase Decode

CRYPTO UTILITY — SECURE MULTIBASE DECODER 🔑  /   20+ encodings • smart heuristics • safe preview

Python tool to automatically decode multi-layer encoded and compressed strings commonly seen in CTF and cyber/security workflows.

## Overview

`auto_multibase_decode.py` is a utility designed to accept an input string that may be encoded and/or compressed across multiple layers and attempt to recover a human-readable plaintext automatically.

- Multi-layer decoding support
- Heuristics and scoring to rank likely plaintext candidates
- No prior knowledge required of which encoders were used
- Suitable for CTFs, reverse engineering, forensics, and penetration testing

## Features

- Wide support for encodings and decoders
- Common compression formats supported
- Smart scoring engine to rate candidate plaintexts
- Beam search to explore multi-step decode chains efficiently
- Interactive CLI mode
- `--show-candidates` to inspect top-scoring candidates

## Supported Encoding Schemes

### Base / Radix
- `base2`
- `base16`
- `base32` (standard + forgiving separators + unpadded)
- `base32hex`
- `base36`
- `base45`
- `base58`
- `base62`
- `base64`
- `base64url`

### High-radix / ASCII encodings
- `base85`
- `ascii85`
- `z85`
- `base91`
- `base92`

### Compression
- `gzip`
- `zlib`
- `bzip2`
- `xz`
- `zstd` (optional)

### Text / Substitution
- `morse`
- `url`
- `rotN` / all ROT shifts
- `rot47`
- `atbash`

## Installation

1. Clone or copy the files into your repository.
2. Use Python 3.11+ (Python 3.13 recommended).
3. Install the optional `zstandard` dependency if you want zstd support:

```bash
python -m pip install zstandard
```

`zstandard` is optional — the tool runs without it but will skip zstd decompression.

## Usage

### Run interactive mode

```bash
python auto_multibase_decode.py
```

### Decode from command line

```bash
python auto_multibase_decode.py "<encoded string>"
```

### Read from file

```bash
python auto_multibase_decode.py -f encoded.txt
```

### Adjust depth and beam size

```bash
python auto_multibase_decode.py "<encoded string>" -m 15 -b 320
```

### Show more candidates

```bash
python auto_multibase_decode.py "<encoded string>" --show-candidates
```

## Magic Mode

"Magic Mode" refers to the set of heuristics aimed at improving detection of typical CTF/cyber patterns:

- Bonus awarded for recognizable CTF flag patterns like `CTF{...}` and security-related keywords
- Higher score for strings containing mixed alphanumeric patterns with `_`, `-`, `{`, `}`
- Penalize long chains that produce unstructured plaintext-like outputs
- Prioritize decoders such as `base64`/`base32`/`url` early in the decode order to discover likely decoding paths

## Notes

- Results depend on the `max_depth` and `beam_size` parameters.
- For longer or deeper chains, increase `-m` and `-b` to explore more possibilities.
- This tool deliberately avoids adding brute-force XOR or unlimited brute-force methods.

## License

This project is provided under the `SPT License`.

```
SPT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

