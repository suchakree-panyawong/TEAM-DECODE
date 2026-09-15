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

# TEAM-DECODE

CRYPTO UTILITY — SECURE MULTIBASE DECODER 🔑  /   20+ encodings • smart heuristics • safe preview

Current release: `v1.3.0`

เครื่องมือ Python สำหรับถอดรหัสข้อความที่เข้ารหัสหรือบีบอัดซ้อนกันหลายชั้นในสไตล์ CTF / Cybersec

## Overview

TEAM-DECODE.py คือ utility ที่ออกแบบมาเพื่อรับ input เป็นข้อความที่ถูกเข้ารหัสหรือบีบอัดหลายชั้น แล้วพยายามถอดกลับจนได้ plaintext ที่อ่านออกได้โดยอัตโนมัติ

- รองรับการถอดแบบ multi-layer
- ใช้ heuristics และ scoring เพื่อคัด candidate ที่มีโอกาสเป็น plaintext มากที่สุด
- ไม่ต้องรู้ล่วงหน้าว่า encoder หรือ compression format ไหนถูกใช้
- เหมาะสำหรับงาน CTF, reverse engineering, forensic และ pentest

## Features ใหม่

- รองรับการถอดแบบอัตโนมัติหลายชั้นแบบเรียงลำดับ candidate
- รองรับ encoding/decoding มากกว่า 20 รูปแบบ
- รองรับ compression format ยอดนิยม เช่น gzip, zlib, bzip2, xz, zstd
- รองรับ base100, quoted-printable, xor single-byte, reverse, rot47 และ atbash
- มีโหมด interactive CLI สำหรับใช้งานแบบสด ๆ
- มีคำสั่ง manual สำหรับ railfence, vigenere และ columnar
- มีตัวเลือก `--show-candidates` เพื่อดู candidate อันดับต้นแบบละเอียด
- มีระบบ scoring และ bonus ที่ช่วยให้ผลลัพธ์ที่เป็น flag-style น่าเชื่อถือขึ้น

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
- `base100`

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
- `quoted_printable`
- `rotN` / all ROT shifts
- `rot47`
- `atbash`
- `xor_singlebyte`
- `reverse`

### Manual Commands
- `railfence <rails> <text>`
- `vigenere <key> <text>`
- `columnar <width> <text>`

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
python TEAM-DECODE.py
```

### Decode from command line

```bash
python TEAM-DECODE.py "<encoded string>"
```

### Read from file

```bash
python TEAM-DECODE.py -f encoded.txt
```

### Read from stdin and restrict schemes

```bash
cat encoded.txt | python TEAM-DECODE.py --stdin --scheme base64 --json
python TEAM-DECODE.py "SGVsbG8=" --scheme base64 --max-results 3 --explain
```

JSON output includes a `confidence` label (`high`, `medium`, or `low`) based on
the score gap between the top candidates. Use `--show-candidates` to inspect
the alternatives and `--max-results` to control how many are returned.

The v1.3 scoring update improves ranking for Thai plaintext, quoted-printable
Unicode payloads, and short base32 values that were previously vulnerable to
speculative decoder chains.

### ปรับความลึกและ beam size

```bash
python TEAM-DECODE.py "<encoded string>" -m 15 -b 320
```

### แสดง candidate เพิ่มเติม

```bash
python TEAM-DECODE.py "<encoded string>" --show-candidates
```

## Magic Mode

โหมด "Magic Mode" ในที่นี้หมายถึงชุด heuristics ที่ออกแบบมาเพื่อจับ pattern CTF/Cyber ได้ดีขึ้น:

- ให้โบนัสกับข้อความที่มีลักษณะ `CTF{...}` และคำสำคัญทางความปลอดภัย
- ให้คะแนนสูงขึ้นกับสตริงที่มีตัวอักษร+ตัวเลขพร้อม `_`, `-`, `{`, `}`
- ลดน้ำหนัก chain ที่ไม่ใช่ plaintext ยาว ๆ แต่ไม่มี structure
- ปรับแต่งกลไกให้ชอบ chain ที่มีโอกาสเป็น flag แบบ multi-layer มากขึ้น
- ควบคุมการใช้ substitution-heavy chain ให้ไม่ลุกลามเกินไป

## Notes

- ผลลัพธ์ขึ้นอยู่กับค่าพารามิเตอร์ `max_depth` และ `beam_size`
- ถ้าต้องการจัดการ chain ยาว ๆ ให้เพิ่ม `-m` และ `-b`
- ระบบนี้ออกแบบมาให้เสถียร และมุ่งเน้นการค้นหาคำตอบที่เป็นไปได้มากกว่า brute-force แบบไม่จำกัด

## AI Verifier

โหมดถอดรหัส + ตรวจคำตอบด้วย AI ตัวเล็ก (GBM, เทรนจากข้อมูลที่ generator สร้างเอง):

```bash
python TEAM-DECODE.py --verify "<payload>"
```

- ความแม่นยำเพิ่มจาก **65.4% → 70.7%** (top1, benchmark 950 เคส) โดย inference ใช้เวลา ~2-3 มิลลิวินาที
- โมเดลเก็บที่ `core/verifier_gbm.pkl` (สำรอง: `core/verifier_weights.json` แบบ logistic)
- เทรนใหม่: `python benchmarks/gen_training_data.py --seed 777 --out benchmarks/reports/verifier_train.jsonl` แล้ว `python -m core.verifier benchmarks/reports/verifier_train.jsonl`
- เทรนนิ่ง/ไม่ใช้ sklearn ก็ยังถอดรหัสได้ปกติ (จะ fallback เป็นลำดับเดิมของ engine)

## Project Structure

```
TEAM-DECODE/
├── TEAM-DECODE.py      # CLI entry point
├── run_tests.py        # quality gate — รันก่อน/หลังแก้ทุกครั้ง
├── core/               # engine (beam search), heuristics (scoring), registry, verifier (AI)
├── decoders/           # decoder ทั้ง 47 ตัว แยกตามหมวด
├── tests/              # unit regressions + system test
├── benchmarks/         # benchmark 950 เคส + generator ข้อมูลเทรน AI + รายงาน
└── archive/            # สคริปต์ debug เก่า + snapshot สำรอง (ไม่ใช้ใน production)
```

## Development Workflow

**กฎเหล็ก: แก้อะไรก็ตาม รัน `python run_tests.py` ก่อนและหลังเสมอ** — เขียว = ไปต่อได้ แดง = ห้าม ship

- `python run_tests.py` — unit + system test (เร็ว ~10 วินาที)
- `python run_tests.py --smoke` — เพิ่ม benchmark ตัวอย่าง 60 เคส
- แก้ core/decoders งานใหญ่ → รัน benchmark เต็มเทียบ baseline:

```bash
python benchmarks/benchmark_1000.py --workers 6   # ~15 นาที
```

- baseline ล่าสุด (950 เคส, depth 8 / beam 40): **engine อย่างเดียว 65.4% / เปิด --verify 70.7%** — ตัวเลขนี้ห้ามตกเมื่อแก้ scoring
  (รอบแรก 42.1% → 65.8% จากการตัด bonus ของขยะ, plaintext shield, beam 320→64;
  รอบสองปรับ ngram corpus, dictionary weighting แบบหลักฐาน, evidence gate สำหรับ
  compression/xor_multikey — สกอร์เท่าเดิมแต่กันการเกมระบบ และเป็น foundation ให้ AI verifier)

## License

This project is released under the [MIT License](LICENSE).

