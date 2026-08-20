"""
core.py — สิ่งที่ทุก module ใน kalama ใช้ร่วมกัน

หลักการที่ยกมาจาก before_patch_pipeline.py / patch_stage.py เดิม (ห้ามเบี่ยงจากนี้):
  - StopPipeline: ทุกเหตุผลที่หยุด ต้องมี evidence แนบเสมอ ไม่ raise เปล่าๆ
  - state.json: บันทึกก่อน raise เสมอ ไม่ใช่หลัง (กันข้อมูลหายตอน exception)
  - run(): print คำสั่งที่รันจริงทุกครั้ง (ตรวจสอบย้อนหลังได้ — evidence-first)
  - victim container: ชื่อตายตัว ไม่พึ่งชื่อจาก compose file
  - kalama-net: connect ก่อนดึง IP เสมอ (ไม่ใช่ network แรกที่ docker คืนมา)
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

# ---------------------------------------------------------------------------
# ค่าคงที่ระดับโปรเจกต์ — ห้าม hardcode ซ้ำในไฟล์อื่น ให้ import จากที่นี่ที่เดียว
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[3]  # .../kalama-mvp/  (core.py is at src/app/kalama/core.py)
SCRIPT_DIR = PROJECT_ROOT  # check-env.sh, run-case.sh, scan_verify.sh อยู่ root ของโปรเจกต์
LOG_DIR = PROJECT_ROOT / "log"
OUTPUT_DIR = PROJECT_ROOT / "output"
CVE_META_DIR = PROJECT_ROOT / "cve_meta"
ATTACK_DIR = PROJECT_ROOT / "attack"
PATCH_DIR = PROJECT_ROOT / "patch"

WORKBENCH_CONTAINER = "kalama-workbench"
VICTIM_CONTAINER = "victim"
KALAMA_NETWORK = "kalama-net"


class StopPipeline(Exception):
    """เหตุผลที่ต้องหยุด — ไม่ว่าจะเป็น scan ไม่ติด, exploit ไม่ผ่าน, adapter ไม่ครบ,
    หรือ script พัง ทุกเหตุผลต้องมี evidence แนบและถูกเขียนลง state.json ก่อนโยน
    exception เสมอ ไม่ปล่อยให้เงียบ

    status:
        STOPPED  — ผิดคาด ต้องมีคนมาดู
        SKIPPED  — ตามเกณฑ์ที่ freeze ไว้ (เช่น scan ไม่เจอ, adapter ไม่ครบ) ไม่ใช่ error
    """

    def __init__(self, reason: str, status: str = "STOPPED", evidence: Optional[dict[str, Any]] = None):
        self.reason = reason
        self.status = status
        self.evidence = evidence or {}
        super().__init__(reason)


@dataclass
class CaseState:
    """โหลด config 1 เคส + จัดการ output/<CVE-ID>/state.json (resumable)

    ต่างจาก before_patch_pipeline.py เดิมตรงที่ config มาจาก 3 ไฟล์แยกกันแล้ว
    (cve_meta + attack strategy + patch module) ไม่ใช่ cve_config.yaml ไฟล์เดียว —
    ดู resolve_case_config() ใน list.py สำหรับ logic ประกอบไฟล์เหล่านี้เข้าด้วยกัน
    """

    cve_id: str
    config: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)
    state_path: Path = field(init=False)

    def __post_init__(self):
        self.state_path = OUTPUT_DIR / self.cve_id / "state.json"
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if self.state_path.exists():
            self.state = json.loads(self.state_path.read_text())
        else:
            self.state = {"cve_id": self.cve_id, "current_stage": None, "history": []}

    def record(self, stage: str, result: dict[str, Any]) -> None:
        entry = {
            "stage": stage,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
        }
        self.state["history"].append(entry)
        self.state["current_stage"] = stage
        self._save()

    def _save(self) -> None:
        self.state_path.write_text(json.dumps(self.state, indent=2, ensure_ascii=False))


def run(cmd: list[str], description: str, check: bool = True) -> subprocess.CompletedProcess:
    """wrapper รอบ subprocess.run — print คำสั่งที่รันจริงเสมอ (evidence-first,
    ตรวจสอบย้อนหลังได้ — ตาม pattern เดิมใน before_patch_pipeline.py)
    """
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"  [stderr] {result.stderr.strip()}")
    return result


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise StopPipeline(
            f"ไฟล์ config ไม่พบ: {path}",
            status="STOPPED",
            evidence={"missing_path": str(path)},
        )
    return yaml.safe_load(path.read_text()) or {}
