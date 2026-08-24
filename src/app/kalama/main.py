#!/usr/bin/env python3
"""
main.py — Kalama CLI entrypoint

Usage:
    python3 main.py list --image <docker-image>
        รัน full trivy scan -> score -> top N -> adapter filter -> print eligible CVEs

    python3 main.py scan --cve CVE-2015-1427 --image vulhub/elasticsearch:1.4.2 --port 9200
        scan_verify.sh เฉพาะ CVE เดียว (สำหรับเช็คก่อน exploit)

    python3 main.py exploit --cve CVE-2015-1427 --image vulhub/elasticsearch:1.4.2 --port 9200
        victim_up -> scan gate -> setup_steps -> exploit -> oracle

    python3 main.py patch --cve CVE-2015-1427
        patch stage เดี่ยว ๆ (ต้องมี state.json จาก exploit stage มาก่อน — อ่าน
        dependency+fixed_version จาก config เดียวกัน)

    python3 main.py full --cve CVE-2015-1427 --image vulhub/elasticsearch:1.4.2 --port 9200
        รันครบ 1 CVE เดี่ยว: exploit(before) -> patch -> exploit(after) -> บันทึกลง results.csv
        (สำหรับ debug/manual override CVE เดียว — ไม่ต้องระบุ --cve ถ้าจะยิงหลายตัว
        พร้อมกัน ดู run-eligible ด้านล่าง)

    python3 main.py run-eligible --image vulhub/elasticsearch:1.4.2 --port 9200
        list (scan+score+adapter check) -> full loop ให้ทุก CVE ที่ adapter_status ==
        "available" ทีละตัว (ไม่ยิงพร้อมกัน กัน port/container ชื่อ victim ชนกัน)
        ตัวไหน SKIPPED/STOPPED ไป log แล้วไปต่อตัวถัดไป ไม่ทำ batch หยุดทั้งชุด

    python3 main.py report --csv output/results.csv
        คำนวณ P/R/F1 จาก results.csv ที่มีอยู่ (filter included_in_metrics)

Design note: แต่ละ subcommand เรียก module เดียวกับที่ agent จะไปต่อยอด (scan/,
exploit/, update/, list/, summary/) — ไม่มี logic ซ้ำในไฟล์นี้ ทำหน้าที่แค่
parse args + orchestrate call order + จัดการ StopPipeline
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import CaseState, StopPipeline, PROJECT_ROOT, OUTPUT_DIR
from .scan import resolve_case_config, stage_scan, stage_trivy_full_scan
from .exploit import stage_victim_up, stage_victim_down, stage_exploit
from .update import stage_patch
from .list import score_and_filter, eligible_cases, load_scored_cves_from_csv
from .summary import write_results_csv, update_exploit_result, compute_metrics, print_report


def cmd_list(args: argparse.Namespace) -> int:
    print(f"=== LIST: scoring CVEs for image {args.image} ===")
    scan_json_path = OUTPUT_DIR / "_scoring_scans" / f"{args.image.replace('/', '_').replace(':', '_')}.json"
    stage_trivy_full_scan(args.image, scan_json_path)

    scored = score_and_filter(scan_json_path)
    eligible = eligible_cases(scored)

    print(f"\nTop {len(scored)} CVE ตาม score:")
    for c in scored:
        flag = "✅ eligible" if c.adapter_status == "available" else f"⏭ {c.adapter_status}"
        print(f"  {c.cve_id:<20} score={c.score:<6} predicted_high={c.predicted_high}  {flag}")

    print(f"\n{len(eligible)} / {len(scored)} CVE พร้อมยิงจริง (adapter ครบ)")

    csv_path = OUTPUT_DIR / "results.csv"
    write_results_csv(scored, csv_path)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    print(f"=== SCAN: {args.cve} on {args.image} ===")
    try:
        result = stage_scan(args.cve, args.image, phase="before")
        print(f"[OK] found={result['found']}")
        return 0
    except StopPipeline as e:
        print(f"[{e.status}] {e.reason}")
        return 0 if e.status == "SKIPPED" else 1


def _load_case(cve_id: str, image: str, port: int) -> CaseState:
    config = resolve_case_config(cve_id, image, port)
    case = CaseState(cve_id=cve_id, config=config)
    return case


def cmd_exploit(args: argparse.Namespace) -> int:
    print(f"=== EXPLOIT: {args.cve} ===")
    try:
        # scan ต้องมาก่อน load_case เสมอ (evidence-first) — ไม่โหลด/resolve
        # exploit config (cve_meta+attack+patch 3 ไฟล์) จนกว่าจะยืนยันว่า scanner
        # เจอ CVE นี้ในอิมเมจเป้าหมายจริง ไม่ใช่พึ่ง StopPipeline(SKIPPED) ตัด flow เฉยๆ
        stage_scan(args.cve, args.image, phase="before")

        case = _load_case(args.cve, args.image, args.port)

        target_ip = stage_victim_up(case)
        case.record("victim_up", {"target_ip": target_ip})

        result = stage_exploit(case, target_ip)

        if result["oracle_result"] != "SUCCESS":
            raise StopPipeline(
                "EXPLOIT ไม่ SUCCESS — ห้ามไป PATCH ต่อ",
                status="STOPPED",
                evidence=result,
            )

        print(f"[DONE] exploit SUCCESS — พร้อม patch ต่อ (python3 main.py patch --cve {args.cve})")
        case.record("ready_for_patch", {"status": "READY"})
        return 0

    except StopPipeline as e:
        print(f"\n[{e.status}] {e.reason}")
        return 0 if e.status == "SKIPPED" else 1


def cmd_patch(args: argparse.Namespace) -> int:
    print(f"=== PATCH: {args.cve} ===")
    try:
        # patch อ่าน config เดิมจาก resolve_case_config อีกครั้ง (ต้องมี --image/--port
        # ซ้ำ เพราะ dependency มาจาก cve_meta ไม่ใช่จาก state.json)
        case = _load_case(args.cve, args.image or "unknown", args.port or 0)
        result = stage_patch(case, OUTPUT_DIR)
        print(f"[DONE] patch เสร็จ — image={result['image_tag']}")
        return 0
    except StopPipeline as e:
        print(f"\n[{e.status}] {e.reason}")
        return 0 if e.status == "SKIPPED" else 1


def _run_full_loop(cve_id: str, image: str, port: int | None) -> dict:
    """exploit(before) -> patch -> exploit(after, ใช้ image ที่ patch แล้ว) -> results.csv

    entrypoint จริงของ full loop 1 CVE — แยกออกมาจาก cmd_full เดิมเพื่อให้
    cmd_full (single-CVE CLI) และ cmd_run_eligible (multi-CVE loop) เรียกใช้
    logic เดียวกันได้ ไม่ duplicate — StopPipeline ปล่อยให้ propagate ออกไปเสมอ
    ให้ caller เป็นคนจัดการ (cmd_full catch เพื่อแปลงเป็น exit code,
    cmd_run_eligible catch ต่อ CVE ในลูปเพื่อไปต่อตัวถัดไปโดยไม่ทำทั้ง batch พัง)

    บันทึกผลลง results.csv 1 แถวสำหรับ CVE นี้ (ต้องรัน `list` มาก่อนให้มี row
    อยู่แล้ว ไม่ re-score ใหม่ตรงนี้)
    """
    print(f"=== FULL LOOP: {cve_id} ===")

    # scan ต้องมาก่อน load_case เสมอ (evidence-first) — ไม่โหลด/resolve
    # exploit config (cve_meta+attack+patch 3 ไฟล์) จนกว่าจะยืนยันว่า scanner
    # เจอ CVE นี้ในอิมเมจเป้าหมายจริง ไม่ใช่พึ่ง StopPipeline(SKIPPED) ตัด flow เฉยๆ
    stage_scan(cve_id, image, phase="before")

    case = _load_case(cve_id, image, port)

    target_ip = stage_victim_up(case)
    case.record("victim_up", {"target_ip": target_ip})

    before_result = stage_exploit(case, target_ip)
    if before_result["oracle_result"] != "SUCCESS":
        raise StopPipeline("EXPLOIT (before) ไม่ SUCCESS — หยุด full loop", status="STOPPED", evidence=before_result)

    patch_result = stage_patch(case, OUTPUT_DIR)

    scan_after_result = stage_scan(case.cve_id, patch_result["image_tag"], phase="after")
    case.record("scan_after", scan_after_result)

    stage_victim_down(case)
    case.config["before_patch"]["image"] = patch_result["image_tag"]
    target_ip_after = stage_victim_up(case)

    after_result = stage_exploit(
        case, target_ip_after, wait_for_target=True,
        target_version=patch_result["used_version"],
    )

    exploited_before = before_result["oracle_result"] == "SUCCESS"
    exploited_after = after_result["oracle_result"] == "SUCCESS"

    print(f"\n[DONE] full loop: before={exploited_before} after={exploited_after}")
    case.record("full_loop_complete", {
        "exploited_before": exploited_before,
        "exploited_after": exploited_after,
        "patch_strategy_used": patch_result["used_strategy"],
    })

    # --- เขียนผล exploited (before) กลับเข้า results.csv (ต้องมี row ของ CVE นี้
    # อยู่แล้วจาก `main.py list` มาก่อน — ไม่ re-score ใหม่ตรงนี้) ---
    csv_path = OUTPUT_DIR / "results.csv"
    if not csv_path.exists():
        print(f"  [WARN] {csv_path} ไม่พบ — รัน `main.py list --image <image>` ก่อนถ้าต้องการให้ผลนี้ไปรวม P/R/F1 ได้")
    else:
        scored = load_scored_cves_from_csv(csv_path)
        if not any(c.cve_id == case.cve_id for c in scored):
            print(f"  [WARN] {case.cve_id} ไม่มีอยู่ใน {csv_path} — รัน `main.py list --image <image>` ก่อนถ้าต้องการให้ผลนี้ไปรวม P/R/F1 ได้")
        else:
            update_exploit_result(scored, case.cve_id, exploited_before, before_result["oracle_status"])
            write_results_csv(scored, csv_path)
            print(f"  [OK] อัปเดต {case.cve_id} เข้า {csv_path} — exploited={exploited_before} oracle_status={before_result['oracle_status']}")

    return {
        "exploited_before": exploited_before,
        "exploited_after": exploited_after,
        "patch_strategy_used": patch_result["used_strategy"],
    }


def cmd_full(args: argparse.Namespace) -> int:
    """CLI เดี่ยว — 1 CVE ที่ระบุตรงผ่าน --cve (ใช้สำหรับ debug/manual override)"""
    try:
        _run_full_loop(args.cve, args.image, args.port)
        return 0
    except StopPipeline as e:
        print(f"\n[{e.status}] {e.reason}")
        return 0 if e.status == "SKIPPED" else 1


def cmd_run_eligible(args: argparse.Namespace) -> int:
    """list (scan+score+adapter check) -> full loop ทีละ CVE สำหรับทุกตัวที่
    adapter_status == "available" — ไม่ยิงพร้อมกัน (กัน port/container ชื่อ
    'victim' ชนกัน) แต่ละ CVE fail แล้วต้องไม่ทำทั้ง batch หยุด — log แล้วไปต่อ
    ตัวถัดไปเสมอ ไม่ว่าจะ StopPipeline (SKIPPED/STOPPED) หรือ exception อื่นที่
    ไม่คาดคิด (กัน batch รันข้ามคืนแล้วตายเพราะ CVE ตัวเดียวพังกลางทาง)
    """
    print(f"=== RUN-ELIGIBLE: full loop ทุก CVE ที่ adapter พร้อม (image={args.image}) ===")
    scan_json_path = OUTPUT_DIR / "_scoring_scans" / f"{args.image.replace('/', '_').replace(':', '_')}.json"
    stage_trivy_full_scan(args.image, scan_json_path)

    scored = score_and_filter(scan_json_path)
    eligible = eligible_cases(scored)

    csv_path = OUTPUT_DIR / "results.csv"
    write_results_csv(scored, csv_path)

    print(f"\n{len(eligible)} / {len(scored)} CVE พร้อมยิงจริง (adapter ครบ) — จะรัน full loop ทีละตัว")

    success: list[str] = []
    skipped: list[str] = []
    stopped: list[str] = []

    for cve in eligible:
        print(f"\n{'=' * 70}\n>>> {cve.cve_id}\n{'=' * 70}")
        try:
            _run_full_loop(cve.cve_id, args.image, args.port)
            success.append(cve.cve_id)
        except StopPipeline as e:
            print(f"[{e.status}] {e.reason}")
            (skipped if e.status == "SKIPPED" else stopped).append(cve.cve_id)
        except Exception as e:  # noqa: BLE001 — เจตนา: CVE เดียวพังไม่ควรทำทั้ง batch หยุด
            print(f"[ERROR] {cve.cve_id}: exception ที่ไม่คาดคิด: {e}")
            stopped.append(cve.cve_id)

    print(f"\n{'=' * 70}")
    print(" RUN-ELIGIBLE SUMMARY")
    print(f"{'=' * 70}")
    print(f"  ผ่านจริง (SUCCESS): {len(success)} — {success}")
    print(f"  SKIPPED:            {len(skipped)} — {skipped}")
    print(f"  STOPPED/ERROR:      {len(stopped)} — {stopped}")
    print(f"{'=' * 70}")

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"[ERROR] ไม่พบ {csv_path} — รัน `main.py list` ก่อน")
        return 1
    metrics = compute_metrics(csv_path)
    print_report(metrics)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kalama", description="Kalama exploitation-validated CVE pipeline")
    sub = p.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="scan image -> score -> top N -> adapter filter")
    p_list.add_argument("--image", required=True)
    p_list.set_defaults(func=cmd_list)

    p_scan = sub.add_parser("scan", help="scan_verify.sh สำหรับ 1 CVE")
    p_scan.add_argument("--cve", required=True)
    p_scan.add_argument("--image", required=True)
    p_scan.set_defaults(func=cmd_scan)

    p_exploit = sub.add_parser("exploit", help="victim_up -> exploit -> oracle")
    p_exploit.add_argument("--cve", required=True)
    p_exploit.add_argument("--image", required=True)
    p_exploit.add_argument("--port", type=int, default=None)
    p_exploit.set_defaults(func=cmd_exploit)

    p_patch = sub.add_parser("patch", help="patch stage เดี่ยว")
    p_patch.add_argument("--cve", required=True)
    p_patch.add_argument("--image", default=None)
    p_patch.add_argument("--port", type=int, default=None)
    p_patch.set_defaults(func=cmd_patch)

    p_full = sub.add_parser("full", help="exploit(before) -> patch -> exploit(after) — CVE เดียว (debug/override)")
    p_full.add_argument("--cve", required=True)
    p_full.add_argument("--image", required=True)
    p_full.add_argument("--port", type=int, default=None)
    p_full.set_defaults(func=cmd_full)

    p_run_eligible = sub.add_parser(
        "run-eligible", help="list -> full loop ทีละตัวให้ทุก CVE ที่ adapter พร้อม (ไม่ต้องระบุ --cve)"
    )
    p_run_eligible.add_argument("--image", required=True)
    p_run_eligible.add_argument("--port", type=int, default=None)
    p_run_eligible.set_defaults(func=cmd_run_eligible)

    p_report = sub.add_parser("report", help="คำนวณ P/R/F1 จาก results.csv")
    p_report.add_argument("--csv", default=str(PROJECT_ROOT / "output" / "results.csv"))
    p_report.set_defaults(func=cmd_report)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
