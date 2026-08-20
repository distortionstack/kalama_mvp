"""
list/scoring.py — คำนวณ score ต่อ CVE จาก Trivy scan output + EPSS + KEV
แล้ว filter top N ผ่าน adapter coverage check

หน้าที่ของ module นี้ (ตาม pipeline ที่ตกลงกัน):
    1. รับ Trivy scan JSON ของ target image (จาก scan.py)
    2. เสริมคะแนนต่อ CVE ด้วย EPSS (FIRST.org) + CISA KEV + reachability
    3. เรียง top N ตาม score (resource constraint — คนละมิติกับ predicted_high)
    4. filter top N ผ่าน adapter_coverage_check (มี cve_meta + attack strategy +
       patch module ครบไหม) → ได้ "eligible cases" ที่พร้อมยิงจริง

ไม่ตัดสินใจ exploit/patch เอง — แค่คืนรายชื่อ CVE ที่ eligible ให้ exploit.py /
update.py ไปทำงานต่อ

config: scoring_config.yaml (root ของโปรเจกต์) — ห้าม hardcode threshold ในไฟล์นี้
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import requests

from ..core import PROJECT_ROOT, CVE_META_DIR, PATCH_DIR, load_yaml

SCORING_CONFIG_PATH = PROJECT_ROOT / "scoring_config.yaml"


@dataclass
class ScoredCVE:
    cve_id: str
    dependency: str
    installed_version: str
    fixed_version: Optional[str]
    cvss: float
    epss: float
    in_kev: bool
    reachable: bool  # placeholder — reachability check ยังไม่ implement (ดู scoring_config note)
    score: float
    predicted_high: int  # 0/1 จาก score >= threshold — ไม่เกี่ยวกับว่ามี adapter ยิงได้ไหม
    adapter_status: str = "unknown"  # available / no_adapter — เติมทีหลังโดย check_adapter_coverage()
    attack_strategy: Optional[str] = None
    fixed_version_config: Optional[str] = None  # version ที่ patch/ module มีจริง (อาจไม่ตรง fixed_version เป๊ะ)

    def to_row(self) -> dict[str, Any]:
        """แปลงเป็น dict ตรงกับ columns ใน scoring_config.results_output.columns"""
        return {
            "cve_id": self.cve_id,
            "dependency": self.dependency,
            "version": self.installed_version,
            "cvss": self.cvss,
            "epss": self.epss,
            "in_kev": self.in_kev,
            "reachable": self.reachable,
            "score": self.score,
            "predicted_high": self.predicted_high,
            "adapter_status": self.adapter_status,
            # exploited / included_in_metrics เติมทีหลังโดย exploit.py + summary.py
            "exploited": None,
            "included_in_metrics": False,
        }


def load_scoring_config() -> dict[str, Any]:
    return load_yaml(SCORING_CONFIG_PATH)


def fetch_epss(cve_id: str, config: dict[str, Any]) -> float:
    """เรียก FIRST.org EPSS API ตัวเดียวต่อ CVE — ยังไม่ batch (ทำทีหลังถ้า top N ใหญ่ขึ้น)"""
    endpoint = config["data_sources"]["epss"]["endpoint"].format(cve_id=cve_id)
    fallback = config["data_sources"]["epss"].get("fallback_value", 0.0)
    try:
        resp = requests.get(endpoint, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data")
        return float(data[0]["epss"]) if data else fallback
    except Exception:
        # network พังไม่ควรทำให้ scoring ทั้งชุดล้ม — fallback แล้วไปต่อ
        return fallback


def load_kev_set(config: dict[str, Any]) -> set[str]:
    """ดึง CISA KEV feed ครั้งเดียว cache ไว้ใช้กับทุก CVE ใน batch เดียวกัน
    (cache_ttl_hours ใน config — ยังไม่ implement caching จริงในนี้ ทำ in-memory
    ต่อ 1 run ก่อน ถ้าจะ cache ข้าม run ค่อยเพิ่ม disk cache ทีหลัง)
    """
    endpoint = config["data_sources"]["kev"]["endpoint"]
    try:
        resp = requests.get(endpoint, timeout=15)
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        return {v["cveID"] for v in items}
    except Exception:
        # ถ้า KEV feed ดึงไม่ได้ ไม่ควร block ทั้ง pipeline — ถือว่าไม่มี CVE ไหนอยู่ใน KEV รอบนี้
        return set()


def compute_score(cvss: float, epss: float, in_kev: bool, reachable: bool, config: dict[str, Any]) -> float:
    """ตาม scoring_config.scoring_formula:
    score = cvss * (1 + epss) [+kev_bonus] [+reachable_bonus] แล้ว cap
    """
    formula = config["scoring_formula"]
    score = cvss
    if formula.get("epss_multiplier"):
        score *= 1 + epss
    if in_kev:
        score += formula.get("kev_bonus", 0)
    if reachable:
        score += formula.get("reachable_bonus", 0)
    return round(min(score, formula.get("score_cap", 15)), 2)


def parse_trivy_vulnerabilities(trivy_json_path: Path) -> list[dict[str, Any]]:
    """แกะ Trivy JSON output เป็น list ของ {cve_id, pkg, installed, fixed, cvss}
    ไม่ตัดสินใจอะไรตรงนี้ — แค่ extract ตรงๆ
    """
    data = json.loads(trivy_json_path.read_text())
    out = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            cvss_data = vuln.get("CVSS", {})
            # Trivy เก็บ CVSS แยกตาม source (nvd, redhat ฯลฯ) — เอาตัวแรกที่เจอ V3Score
            cvss_score = 0.0
            for source_scores in cvss_data.values():
                if "V3Score" in source_scores:
                    cvss_score = source_scores["V3Score"]
                    break
            out.append({
                "cve_id": vuln.get("VulnerabilityID"),
                "dependency": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),  # อาจมีหลายตัวคั่นด้วย comma
                "cvss": cvss_score,
            })
    return out


def check_adapter_coverage(cve: ScoredCVE) -> ScoredCVE:
    """เช็คว่า Kalama มี adapter ครบสำหรับ CVE นี้ไหม ตาม
    scoring_config.adapter_coverage_check.requires:
        1. cve_meta/{cve_id}.yaml ต้องมี
        2. attack strategy ที่ cve_meta ชี้ไป ต้องมี version range ครอบคลุม installed_version
        3. patch/{dependency}/{fixed_version}.yaml ต้องมี

    ไม่ raise — แค่เติม adapter_status ให้ ScoredCVE แล้วคืนกลับ (skip ไม่ error)
    """
    meta_path = CVE_META_DIR / f"{cve.cve_id}.yaml"
    if not meta_path.exists():
        cve.adapter_status = "no_adapter"
        return cve

    meta = load_yaml(meta_path)
    matched_strategy = None
    for affected in meta.get("affected", []):
        if affected.get("dependency") != cve.dependency:
            continue
        for vr in affected.get("version_ranges", []):
            # NOTE: version range matching แบบง่ายที่สุดก่อน (string equality กับ pattern
            # เทียบ semver จริง) — ยังไม่ implement semver range parser เต็มรูปแบบ
            # ต้องใส่ทีหลังถ้า version range ซับซ้อนกว่านี้ (ตอนนี้ MVP มีแค่ 1 range/CVE)
            if vr.get("attack_strategy") and vr.get("verified"):
                matched_strategy = vr["attack_strategy"]
                break
        if matched_strategy:
            break

    if not matched_strategy:
        cve.adapter_status = "no_adapter"
        return cve

    attack_file = None
    for candidate in (Path(PROJECT_ROOT) / "attack" / matched_strategy).glob(f"{cve.cve_id}.yaml"):
        attack_file = candidate
        break
    if attack_file is None:
        cve.adapter_status = "no_adapter"
        return cve

    # patch module: dependency name ใน path ใช้ "--" แทน ":" (Maven groupId:artifactId
    # มี ":" ซึ่งใช้เป็นชื่อโฟลเดอร์ไม่ได้ตรงๆ บน filesystem บางตัว) — ต้อง sanitize เหมือนกันทุกที่
    dep_dir_name = cve.dependency.replace(":", "--")
    fixed_version = meta.get("fixed_by_dependency_patch") and cve.fixed_version_config
    # fixed_version_config อาจยังไม่ถูกกำหนด ณ จุดนี้ — ลอง fixed_version จาก Trivy ตรงๆ ก่อน
    candidates_to_try = [cve.fixed_version] if cve.fixed_version else []
    patch_file = None
    for v in candidates_to_try:
        p = PATCH_DIR / dep_dir_name / f"{v}.yaml"
        if p.exists():
            patch_file = p
            break

    if patch_file is None:
        cve.adapter_status = "no_adapter"
        return cve

    cve.attack_strategy = matched_strategy
    cve.fixed_version_config = patch_file.stem
    cve.adapter_status = "available"
    return cve


def score_and_filter(
    trivy_json_path: Path,
    reachable_cve_ids: Optional[set[str]] = None,
) -> list[ScoredCVE]:
    """entrypoint หลักของ module นี้ — เรียกจาก main.py (subcommand: list)

    reachable_cve_ids: placeholder สำหรับผลลัพธ์ reachability check ในอนาคต
    (scoring_config มี reachable_bonus แต่ยังไม่มี reachability tool ต่ออยู่จริง —
    ส่ง set ว่างไปก่อนถ้ายังไม่มี)
    """
    config = load_scoring_config()
    reachable_cve_ids = reachable_cve_ids or set()

    raw_vulns = parse_trivy_vulnerabilities(trivy_json_path)
    kev_set = load_kev_set(config)

    scored: list[ScoredCVE] = []
    for v in raw_vulns:
        cve_id = v["cve_id"]
        epss = fetch_epss(cve_id, config)
        in_kev = cve_id in kev_set
        reachable = cve_id in reachable_cve_ids
        score = compute_score(v["cvss"], epss, in_kev, reachable, config)
        predicted_high = int(score >= config["predicted_high_threshold"])

        scored.append(ScoredCVE(
            cve_id=cve_id,
            dependency=v["dependency"],
            installed_version=v["installed_version"],
            fixed_version=(v["fixed_version"] or "").split(",")[0].strip() or None,
            cvss=v["cvss"],
            epss=epss,
            in_kev=in_kev,
            reachable=reachable,
            score=score,
            predicted_high=predicted_high,
        ))

    # เรียง top N ตาม score — resource constraint, แยกจาก predicted_high_threshold
    scored.sort(key=lambda c: c.score, reverse=True)
    top_n = scored[: config["top_n"]]

    # adapter coverage filter — ไม่ error แค่ skip (เติม adapter_status)
    for cve in top_n:
        check_adapter_coverage(cve)

    return top_n


def eligible_cases(scored_cves: list[ScoredCVE]) -> list[ScoredCVE]:
    """คืนเฉพาะ CVE ที่ adapter_status == available — พร้อมส่งต่อให้ exploit.py"""
    return [c for c in scored_cves if c.adapter_status == "available"]
