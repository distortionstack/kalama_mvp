# Kalama

Kalama เป็น pipeline สำหรับตรวจสอบ CVE แบบ **exploitation-validated** — ไม่ใช่แค่บอกว่า
scanner (Trivy) เจอ CVE ไหนใน image แต่ **ลองยิง exploit จริง** เพื่อยืนยันว่า
CVE ที่ scanner รายงานว่าเจอนั้น "ยิงติดจริง" หรือไม่ แล้ว **แพตช์ + ยิงซ้ำ** เพื่อ
ยืนยันว่าหลังแพตช์แล้ว "ยิงไม่ติดแล้วจริง" — จุดประสงค์คือวัด Precision/Recall/F1
ของ scanner เทียบกับ ground truth ที่พิสูจน์ได้จริง (ใช้เป็นส่วนหนึ่งของธีสิส)

## Pipeline ทำอะไรบ้าง (1 รอบ ต่อ 1 CVE)

```
scan(before) → victim up → exploit(before) → patch → scan(after) → victim up → exploit(after)
```

1. **scan(before)** — เช็คว่า Trivy เจอ CVE นี้ใน image จริงไหม (ถ้าไม่เจอ ตัดจบ ไม่ลอง exploit)
2. **exploit(before)** — สร้าง victim container จาก image ที่ระบุ แล้วลองยิง exploit จริง
   (ผ่าน Metasploit หรือ raw socket แล้วแต่ CVE) — มี **oracle** ตัดสินว่า SUCCESS/FAIL
3. **patch** — ดาวน์โหลด dependency เวอร์ชันที่แพตช์แล้ว rebuild image ใหม่
4. **scan(after)** — เช็คว่า Trivy ยังเจอ CVE นี้ใน image ที่แพตช์แล้วไหม (ควรจะไม่เจอ)
5. **exploit(after)** — ยิง exploit ซ้ำกับ image ที่แพตช์แล้ว (ควรจะ FAIL)
6. ผลทั้งหมดถูกบันทึกกลับเข้า `results.csv` แล้วคำนวณ Precision/Recall/F1 ได้

## โครงสร้าง config ต่อ 1 CVE (3 ไฟล์แยกกัน)

| ไฟล์ | หน้าที่ |
|---|---|
| `cve_meta/{CVE-ID}.yaml` | index — CVE นี้กระทบ dependency ไหน, version range ไหนบ้าง |
| `attack/{strategy}/{CVE-ID}.yaml` | exploit mechanism + oracle (วิธียิง + วิธีตัดสิน SUCCESS/FAIL) |
| `patch/{dependency}/{fixed_version}.yaml` | วิธีแพตช์ dependency นี้ไปเวอร์ชันนี้ |

โค้ดอ่าน 3 ไฟล์นี้มาประกอบเป็น config เดียวตอนรันจริง (`resolve_case_config`) — ดู
[AGENT_README.md](AGENT_README.md) สำหรับรายละเอียด internal / สิ่งที่ยังเป็น stub

**ตอนนี้มี CVE ที่ทำงานครบ end-to-end แค่ตัวเดียว:** `CVE-2015-1427`
(Elasticsearch 1.4.2 Groovy scripting sandbox bypass RCE)

## เตรียมสภาพแวดล้อมก่อนใช้งาน (ทำครั้งเดียว)

ต้องมี Docker ใช้งานได้ก่อน แล้วรัน:

```bash
./setup-workbench.sh
```

สคริปต์นี้สร้าง:
- `kalama-workbench` container — มี `docker` (sibling, ผ่าน docker.sock), `trivy`,
  `curl`, `git` ฯลฯ ให้ scan/patch stage เรียกใช้
- `kalama-net` — docker network ที่ victim container + exploit tool (MSF) ต้องอยู่ร่วมกัน

เช็คว่าเครื่องมือครบไหมด้วย:

```bash
./check-env.sh
```

**Python บน host** ต้องมี `pyyaml`, `requests`, `pandas`, `scikit-learn` (ใช้โดย
`report` สำหรับคำนวณ P/R/F1) — ถ้ายังไม่มีติดตั้งด้วย:

```bash
pip3 install --user --break-system-packages pyyaml requests pandas scikit-learn
```

## วิธีใช้งาน

รันคำสั่งทั้งหมดจาก root ของ repo (`kalama-mvp/`) และต้องตั้ง `PYTHONPATH` ก่อนเสมอ
(package `kalama` อยู่ที่ `src/app/kalama/` ไม่ใช่ root ตรงๆ):

```bash
export PYTHONPATH=src/app
```

หรือใส่นำหน้าทุกคำสั่งแทนก็ได้ (ไม่ persist ข้าม session):

```bash
PYTHONPATH=src/app python3 -m kalama.main <subcommand> ...
```

### `list` — สแกน image เต็ม, score ทุก CVE, เช็คว่าตัวไหนพร้อมยิงจริง

```bash
python3 -m kalama.main list --image vulhub/elasticsearch:1.4.2
```

รัน Trivy scan เต็ม image → คำนวณ score จาก CVSS + EPSS + KEV → เรียง top N →
เช็คว่าแต่ละ CVE มี adapter ครบไหม (`cve_meta` + `attack` strategy + `patch` module)
→ เขียนผลลง `output/results.csv` (ทุก CVE ที่เจอ ไม่ใช่แค่ที่ยิงได้)

### `scan` — เช็คเฉพาะ 1 CVE ว่า scanner เจอในเมจนี้ไหม (เร็ว ไม่ exploit จริง)

```bash
python3 -m kalama.main scan --cve CVE-2015-1427 --image vulhub/elasticsearch:1.4.2
```

### `exploit` — victim up → exploit เดี่ยวๆ (ไม่ patch ต่อ)

```bash
python3 -m kalama.main exploit --cve CVE-2015-1427 --image vulhub/elasticsearch:1.4.2 --port 9200
```

สร้าง victim container จาก image ที่ระบุอัตโนมัติ (ไม่ต้องรันเองก่อน) → ยิง exploit
จริง → ตัดสิน SUCCESS/FAIL — ถ้า SUCCESS จะบอกให้รัน `patch` ต่อ

### `patch` — แพตช์เดี่ยวๆ (ต้องมี state จาก `exploit` มาก่อน)

```bash
python3 -m kalama.main patch --cve CVE-2015-1427
```

### `full` — รันครบทุก stage รวดเดียว (แนะนำ)

```bash
python3 -m kalama.main full --cve CVE-2015-1427 --image vulhub/elasticsearch:1.4.2 --port 9200
```

รัน scan(before) → exploit(before) → patch → scan(after) → exploit(after) ครบ
แล้ว**เขียนผลกลับเข้า `output/results.csv`** (ต้องรัน `list` มาก่อนหน้าอย่างน้อย 1
ครั้งกับ image เดียวกัน ไม่งั้นจะไม่มี row ของ CVE นี้ให้อัปเดต)

### `report` — คำนวณ Precision/Recall/F1 จากผลที่มีอยู่

```bash
python3 -m kalama.main report
```

คำนวณเฉพาะแถวที่ `included_in_metrics == true` (คือ CVE ที่ทั้งมี adapter ครบ
และ oracle ยืนยันผลแบบ deterministic แล้ว — ไม่ใช่ CVE ทั้งหมดที่ scanner เจอ)

## ตัวอย่าง flow เต็ม (CVE-2015-1427)

```bash
export PYTHONPATH=src/app

# 1. สแกน + score (ต้องรันก่อน full ถ้าอยากให้ผลไปรวม P/R/F1)
python3 -m kalama.main list --image vulhub/elasticsearch:1.4.2

# 2. รันครบ exploit→patch→re-exploit แล้วเขียนผลกลับ results.csv
python3 -m kalama.main full --cve CVE-2015-1427 --image vulhub/elasticsearch:1.4.2 --port 9200

# 3. ดูตัวเลข P/R/F1
python3 -m kalama.main report
```

## หมายเหตุ

- ทุกอย่างรันบน **host โดยตรง** (ไม่ใช่ผ่าน `docker exec` เข้า `kalama-workbench`)
  — `kalama-workbench` ใช้แค่เป็นตัวรัน `trivy`/`docker compose` (sibling container)
  ไม่ได้ mount โค้ด `kalama-mvp` เข้าไป
- `output/` เก็บ state (`state.json` ต่อ CVE), scan results, patch build artifacts —
  ไฟล์ใหญ่ (ES tarball ที่ patch ดาวน์โหลดมาหลัก GB) ไม่ควร commit เข้า git
- สถานะ dev-internal / สิ่งที่ยังเป็น stub หรือยังไม่ทดสอบ ดูที่
  [AGENT_README.md](AGENT_README.md)
