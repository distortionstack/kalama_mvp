"""
summary/summary.py — เขียน results.csv + คำนวณ Precision/Recall/F1

สำคัญ: metrics คำนวณเฉพาะแถวที่ included_in_metrics == True เท่านั้น
(ตาม scoring_config.metrics_calculation.filter) — CVE ที่ adapter_status ==
no_adapter จะอยู่ใน results.csv (ไม่ถูกลบทิ้ง) แต่ไม่ถูกนับในตัวเลข P/R/F1
เพราะ predicted_high=1 ที่ยิงไม่ได้ ไม่ใช่ "ความอันตรายลดลง" — เป็นแค่
ข้อจำกัดของเครื่องมือ ต้องแยกสอง concept นี้เด็ดขาด (ตามที่ตกลงกันไว้)
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from ..core import PROJECT_ROOT
from ..list.scoring import ScoredCVE, load_scoring_config


def write_results_csv(scored_cves: list[ScoredCVE], output_path: Path) -> Path:
    config = load_scoring_config()
    columns = config["results_output"]["columns"]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for cve in scored_cves:
            writer.writerow(cve.to_row())

    print(f"  [OK] wrote {len(scored_cves)} rows -> {output_path}")
    return output_path


def update_exploit_result(scored_cves: list[ScoredCVE], cve_id: str, exploited: bool, oracle_status: str) -> None:
    """อัปเดต ScoredCVE ในลิสต์หลังยิง exploit จริงแล้ว (เรียกจาก main.py orchestration)

    included_in_metrics = True ก็ต่อเมื่อ adapter_status == "available" AND
    oracle_status == "confirmed" (ไม่ใช่ pending_signoff) — เคสแบบ CVE-2015-1427
    ที่ oracle ยังไม่ sign-off จะ "ยิงได้จริง" แต่ยังไม่นับใน metrics หลัก
    """
    for cve in scored_cves:
        if cve.cve_id != cve_id:
            continue
        cve_row = cve.to_row()
        cve_row["exploited"] = int(exploited)
        cve_row["included_in_metrics"] = (
            cve.adapter_status == "available" and oracle_status == "confirmed"
        )
        # เขียนกลับเข้า object ผ่าน attribute ตรงๆ (ScoredCVE ไม่มี field exploited/
        # included_in_metrics ใน dataclass เดิม — เก็บเป็น dict เสริมแทนตอนนี้
        # เพื่อไม่ต้องแก้ schema ScoredCVE กลางทาง)
        cve.__dict__["_exploited"] = int(exploited)
        cve.__dict__["_included_in_metrics"] = cve_row["included_in_metrics"]
        cve.__dict__["_oracle_status"] = oracle_status


def compute_metrics(csv_path: Path) -> dict[str, Any]:
    """คำนวณ Precision/Recall/F1 จาก results.csv — filter included_in_metrics
    ก่อนเสมอ ตาม scoring_config.metrics_calculation.filter
    """
    import pandas as pd
    from sklearn.metrics import precision_score, recall_score, f1_score

    df = pd.read_csv(csv_path)

    # normalize bool string จาก csv (True/False string -> bool)
    if df["included_in_metrics"].dtype == object:
        df["included_in_metrics"] = df["included_in_metrics"].astype(str).str.lower() == "true"

    filtered = df[df["included_in_metrics"] == True]  # noqa: E712

    excluded_count = len(df) - len(filtered)

    if filtered.empty or filtered["exploited"].isna().all():
        return {
            "precision": None,
            "recall": None,
            "f1": None,
            "sample_size": 0,
            "excluded_no_adapter_or_pending": excluded_count,
            "note": "ไม่มี CVE ที่ included_in_metrics=True และมีผล exploited จริง — คำนวณไม่ได้",
        }

    y_pred = filtered["predicted_high"].astype(int)
    y_true = filtered["exploited"].astype(int)

    return {
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "sample_size": len(filtered),
        "excluded_no_adapter_or_pending": excluded_count,
        "note": (
            "Sample คือ CVE ที่ adapter ครบและ oracle confirmed เท่านั้น — "
            "ไม่ใช่ CVE ทั้งหมดที่ scanner เจอ ต้องระบุเป็น limitation ในธีสิส"
        ),
    }


def print_report(metrics: dict[str, Any]) -> None:
    print("=" * 60)
    print(" Kalama MVP — Metrics Report")
    print("=" * 60)
    if metrics["precision"] is None:
        print(f"  [PENDING] {metrics['note']}")
    else:
        print(f"  Precision: {metrics['precision']:.3f}")
        print(f"  Recall:    {metrics['recall']:.3f}")
        print(f"  F1:        {metrics['f1']:.3f}")
        print(f"  Sample size (included_in_metrics): {metrics['sample_size']}")
    print(f"  Excluded (no_adapter / pending_signoff): {metrics['excluded_no_adapter_or_pending']}")
    print(f"  Note: {metrics['note']}")
    print("=" * 60)
