# Kalama MVP Skeleton — สถานะและสิ่งที่ต้องต่อ

โครงนี้ทดสอบแล้วว่า **import ครบ, config 3 ไฟล์ประกอบกันได้จริง, CLI parser
route ถูก** (รันบน sandbox โดยไม่มี docker/trivy/msf จริงให้ทดสอบ end-to-end)
สิ่งที่ยังไม่ได้ทดสอบคือการรันจริงกับ container/network/scanner

## โครงสร้าง

```
src/app/kalama/
├── core.py           # StopPipeline, CaseState, run(), load_yaml() — ทุกไฟล์ import จากที่นี่
├── main.py            # CLI: list / scan / exploit / patch / full / report
├── scan/scan.py        # resolve_case_config() (ประกอบ 3 ไฟล์), stage_scan(), stage_trivy_full_scan()
├── exploit/exploit.py  # stage_victim_up, setup_steps dispatch, exploit dispatch, oracle classify
├── update/update.py    # stage_patch — fixed_version_strategy -> upstream_fallback_strategy
├── list/scoring.py     # score_and_filter, adapter coverage check
└── summary/summary.py  # results.csv, compute_metrics (P/R/F1)
```

## พร้อมใช้จริง (ported ตรงจากโค้ดเดิมที่ verified แล้ว)

- `core.CaseState` / `StopPipeline` — เหมือน before_patch_pipeline.py เดิมทุกจุด
- `exploit.stage_victim_up` — เหมือนเดิม, ต่างแค่ไม่มี vulhub_case_path (ดู "ต้องตัดสินใจ" ด้านล่าง)
- `exploit._run_setup_steps` — รองรับทั้ง schema เก่า (url_template) และใหม่ (requests: [...])
- `exploit._classify_oracle` — เหมือนเดิม, เพิ่มการอ่าน `evidence_path_pattern` จาก config แทน hardcode `.jar`
- `exploit._wait_for_http` — race condition fix จาก lab note CVE-2015-1427 (ES boot ไม่ทัน)
- `scan.stage_scan` — wrap scan_verify.sh เหมือนเดิม
- `scan.resolve_case_config` — **ทดสอบแล้วว่าประกอบ 3 ไฟล์ถูกต้อง** (cve_meta + attack + patch)

## ยังเป็น stub / ต้องทำต่อ

1. **`update._install_prebuilt_download`** — เขียนแล้วแต่ยังไม่เคยรันจริงกับ
   network จริง (curl + tar) ต้องทดสอบกับ elastic artifacts URL จริง

2. **`update.INSTALL_METHOD_DISPATCH`** — มีแค่ `prebuilt_download` (fix_type B)
   `build_from_source` (fix_type A, สำหรับ CVE-2017-5645/5638) และ `os_package`
   (fix_type C, สำหรับ CVE-2014-0160) ยังไม่ implement — ต้อง port มาจาก
   `patch_stage.py` เดิม (tier_1/tier_2 split สำหรับ build_from_source)

3. **`_write_dockerfile`** ใน update.py — ใช้ `eval()` สำหรับ `applies_when`
   condition (เช่น `"major_version >= 8"`) — **ใช้ eval() ชั่วคราวเท่านั้น
   ต้องเปลี่ยนเป็น safe parser ก่อน production** (ถึงแม้ input มาจาก config
   ที่เราเขียนเอง ไม่ใช่จาก user แต่ eval() เป็นนิสัยไม่ดี)

4. **`list.check_adapter_coverage` version range matching** — ตอนนี้ MVP
   เช็คแค่ `verified: true` ตัวแรกที่เจอ ไม่ได้เทียบ semver range จริงกับ
   installed_version — ต้องเพิ่ม semver parser ถ้าจะรองรับหลาย version range
   ต่อ CVE จริงจัง (ตอนนี้ทุก CVE มีแค่ 1 range พอ)

5. **`list._resolve_latest_upstream_version`** — `latest_version_lookup`
   endpoint ใน patch YAML เป็น placeholder (ดู `****` ในไฟล์ 1.4.3.yaml)
   ยังไม่ยืนยัน endpoint จริงของ elastic ที่คืน "latest version" เป็น JSON —
   ตอนนี้ fallback ไปใช้ `verified_case` (lab note ที่ manual-confirm ไว้แล้ว)

6. **`exploit.stage_victim_up`** — เปลี่ยนจาก `run-case.sh` (vulhub compose)
   เป็น `docker run` ตรงจาก image เดียว **ต้องตัดสินใจ**: ถ้า vulhub case
   ไหนยังต้องใช้ compose (multi-container เช่น มี db แยก) ต้องเพิ่ม field
   บอกว่า "image เดียว" vs "ต้องใช้ compose" ใน config ไม่งั้น multi-container
   case จะพังเงียบๆ

7. **`cmd_patch` ใน main.py** — ต้องการ `--image`/`--port` ซ้ำเพื่อ
   resolve_case_config ใหม่ ทั้งที่ patch ไม่ควรต้องรู้เรื่อง image/port เลย
   (เป็น dependency-centric) — ควรแยก resolve_case_config ให้ patch อ่านแค่
   ส่วน patch config โดยไม่ต้องพ่วง image/port เข้ามา (ตอนนี้เป็น workaround
   ชั่วคราว)

8. **`update_exploit_result` ใน summary.py** — เก็บ exploited/included_in_metrics
   ไว้ใน `cve.__dict__["_exploited"]` แทนที่จะเป็น field จริงใน `ScoredCVE`
   dataclass — ควร refactor ให้เป็น field จริง (ตอนนี้ workaround กันแก้
   schema ScoredCVE กลางทาง)

9. **reachability check** — `reachable` ใน scoring เป็น `False` เสมอ
   (ไม่มี reachability tool ต่ออยู่จริง) ตาม recent_updates ที่บันทึกไว้ว่า
   **จงใจไม่เพิ่ม static reachability analysis** เป็น pre-exploit gate —
   ดังนั้น field นี้อาจจะไม่มีวันถูก implement ตาม decision เดิม เก็บไว้
   เป็น False ตลอดก็ได้ถ้า Atthapol ไม่เปลี่ยนใจ

## ทดสอบแล้ว (ในนี้)

```
✅ import ทุก module ผ่าน
✅ resolve_case_config('CVE-2015-1427', ...) ประกอบ 3 ไฟล์ถูกต้อง
✅ CLI parser route ทุก subcommand ถูก handler
```

## ยังไม่ได้ทดสอบ (ต้องมี docker/trivy/msf จริง)

```
❌ stage_victim_up จริง (docker run + network connect + IP lookup)
❌ stage_exploit จริง (setup_steps + MSF/raw_socket + oracle classify)
❌ stage_patch จริง (curl download + docker build)
❌ stage_trivy_full_scan จริง (ต้องมี kalama-workbench container)
❌ compute_metrics บน results.csv จริงที่มีข้อมูล exploited แล้ว
```

## คำสั่งทดสอบที่แนะนำก่อนรันจริง

```bash
cd kalama-mvp
export PYTHONPATH=src/app
python3 -m kalama.main exploit --cve CVE-2015-1427 --image vulhub/elasticsearch:1.4.2 --port 9200
```
ต้องมี kalama-workbench + kalama-net ตั้งไว้แล้ว (setup-workbench.sh)

## Regression ที่เจอและแก้แล้ว — check-gate ต้องเป็น opt-in ต่อ CVE (2026-08-24)

ตอนเพิ่ม dual-signal oracle (check() ก่อน แล้วลอง `exploit -z` เฉพาะถ้า check
ผ่าน) ให้ CVE-2015-1427 — `_exploit_msf()` เขียนให้ check-gate ทำงานกับ**ทุก**
CVE ที่ `tool: msf` โดยไม่แยกว่า CVE นั้นตั้ง `oracle.verdict_source: msf_check`
ไว้จริงไหม ผลคือ CVE-2017-5638 (legacy oracle, marker_path, ไม่มี
`check_success_pattern`) โดน skip การยิง exploit จริงไปเลย ทั้งที่ MSF `check()`
ตอบว่า vulnerable จริง (`check_passed` ถูก hardcode เป็น `False` เพราะไม่มี
pattern ให้ match)

**แก้แล้ว:** check-gate ทำงานเฉพาะเมื่อ `oracle.verdict_source == "msf_check"`
เท่านั้น ([exploit.py](src/app/kalama/exploit/exploit.py) `_exploit_msf`) ถ้าไม่ได้
ตั้งไว้ ยิง `exploit -z` ตรงๆ เหมือนพฤติกรรมเดิมก่อนมี dual-signal — regression
test แล้วทั้งสองฝั่ง: CVE-2015-1427 (check-gate ใช้จริง) ยัง SUCCESS เหมือนเดิม,
CVE-2017-5638 (ไม่มี check-gate) ยิงผ่าน `/tmp/success` ถูกสร้างจริง

**บทเรียน:** behavior gate ที่เพิ่มเข้า shared dispatch function (เช่น
`_exploit_msf`, `_classify_oracle`, `INSTALL_METHOD_DISPATCH`) ต้อง opt-in ต่อ
CVE ผ่าน config field ที่ชัดเจนเสมอ ห้ามสมมติว่า "ถ้า field ไม่มี = false/fail"
ในกรณีที่ field ไม่มีควรแปลว่า "feature นี้ไม่เกี่ยวกับ CVE นี้ ใช้ behavior เดิม"
แทน — และต้อง regression-test ฝั่งที่ **ไม่ได้** ใช้ feature ใหม่ด้วยเสมอ ไม่ใช่
แค่ฝั่งที่ตั้งใจแก้
