"""
scan/scan.py — เรียก scan_verify.sh (ไม่เขียน scanner logic ใหม่) + ประกอบ
config 1 เคสจาก 3 ไฟล์แยกกัน (cve_meta / attack strategy / patch module)

resolve_case_config() คือจุดต่อสำคัญ: แทนที่จะมี cve_config.yaml ไฟล์เดียวแบบเดิม
ตอนนี้ config กระจายอยู่ 3 ที่ตาม design ใหม่ (§ cve_meta ทำหน้าที่ index,
attack ทำหน้าที่ exploit+oracle, patch ทำหน้าที่ remediation) — module นี้
ประกอบให้เป็น dict เดียวที่ CaseState ใช้งานได้เหมือน config เดิม
"""

from __future__ import annotations

import operator
import re
from pathlib import Path
from typing import Any, Callable, Optional

from ..core import (
    SCRIPT_DIR, CVE_META_DIR, ATTACK_DIR, PATCH_DIR,
    StopPipeline, run, load_yaml,
)


_VALID_DEPLOYMENT_MODES = ("single_image", "vulhub_compose")
_VULHUB_COMPOSE_REQUIRED_FIELDS = ("vulhub_case_path", "victim_service")


# ---------------------------------------------------------------------------
# version range matching — ใช้เช็คว่า target version (เช่น หลัง patch) ยังอยู่ใน
# version_range ที่ cve_meta บอกว่ามี attack_strategy รองรับไหม (ดู
# resolve_attack_strategy_for_version) เทียบแบบ tuple ตัวเลขง่ายๆ ไม่ใช่ semver
# parser เต็มรูปแบบ ("ง่ายที่สุดก่อน" ตาม pattern เดียวกับ update._eval_applies_when)
# ---------------------------------------------------------------------------

_RANGE_OPS: dict[str, Callable[[tuple, tuple], bool]] = {
    ">=": operator.ge, "<=": operator.le, ">": operator.gt, "<": operator.lt, "==": operator.eq,
}
_RANGE_CLAUSE_RE = re.compile(
    r"^(" + "|".join(re.escape(op) for op in _RANGE_OPS) + r")\s*([\w.\-]+)$"
)


def _parse_version(version: str) -> tuple[int, ...]:
    """'9.5.1' -> (9,5,1) / '1.4.2' -> (1,4,2) — ตัด suffix ที่ไม่ใช่ตัวเลขนำทิ้ง
    (pre-release/build tag) ไม่รองรับ semver เต็มรูปแบบ พอสำหรับเทียบ major.minor.patch
    """
    parts = []
    for chunk in version.split("."):
        digits = ""
        for ch in chunk:
            if not ch.isdigit():
                break
            digits += ch
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _version_in_range(version: str, range_str: str) -> bool:
    """range_str เช่น '>=1.3.0,<=1.4.2' หรือ '>=1.4.3' (comma = AND ของทุกเงื่อนไข)"""
    v = _parse_version(version)
    for clause in range_str.split(","):
        clause = clause.strip()
        match = _RANGE_CLAUSE_RE.match(clause)
        if not match:
            raise StopPipeline(
                f"version_range clause รูปแบบไม่รองรับ: {clause!r} ใน {range_str!r} "
                f"(รองรับแค่ {list(_RANGE_OPS)})",
                status="STOPPED",
                evidence={"range_str": range_str, "clause": clause},
            )
        op_str, bound_str = match.groups()
        bound = _parse_version(bound_str)
        width = max(len(v), len(bound))
        v_padded = v + (0,) * (width - len(v))
        bound_padded = bound + (0,) * (width - len(bound))
        if not _RANGE_OPS[op_str](v_padded, bound_padded):
            return False
    return True


def resolve_attack_strategy_for_version(cve_id: str, version: str) -> Optional[str]:
    """หา attack_strategy ที่ใช้ได้จริงกับ version ที่ระบุ (ต่างจาก resolve_case_config
    ที่เอา 'verified: true' ตัวแรกที่เจอโดยไม่สนใจ version — ตัวนี้เทียบ version_range
    จริง) คืน None ถ้าไม่ match range ไหนเลย หรือ match range ที่ attack_strategy: null
    (แปลว่า exploit path ที่มีไม่มีความหมายกับ version นี้แล้ว — ไม่ใช่ error)
    """
    meta_path = CVE_META_DIR / f"{cve_id}.yaml"
    meta = load_yaml(meta_path)
    for affected in meta.get("affected", []):
        for vr in affected.get("version_ranges", []):
            if _version_in_range(version, vr["range"]):
                return vr.get("attack_strategy")
    return None


def _resolve_deployment_config(
    cve_id: str, attack_path: Path, attack_cfg: dict[str, Any],
) -> dict[str, Any]:
    """บังคับให้ attack config ต้องระบุ deployment.mode ชัดเจน (ไม่มี default) —
    ตาม decision ข้อ 6 ใน AGENT_README: ถ้าไม่มีจะไปพังเงียบๆ ตอน stage_victim_up
    เดา single_image ผิด (เช่น CVE ที่จริงๆ ต้องใช้ vulhub compose หลาย container)
    ดีกว่าหยุดตรงนี้พร้อมบอกว่าต้องเติม field ไหนใน attack YAML ไฟล์ไหน
    """
    deployment_cfg = attack_cfg.get("deployment")
    if not deployment_cfg or "mode" not in deployment_cfg:
        raise StopPipeline(
            f"{cve_id}: attack config ขาด field 'deployment.mode' — เพิ่ม block นี้ใน "
            f"{attack_path}:\n\n"
            f"  deployment:\n"
            f"    mode: single_image   # หรือ vulhub_compose\n\n"
            f"(single_image = docker run image เดียวตรงๆ, vulhub_compose = ต้องเพิ่ม "
            f"vulhub_case_path + victim_service ด้วย — ดู AGENT_README ข้อ 6)",
            status="STOPPED",
            evidence={"attack_source_path": str(attack_path), "missing_field": "deployment.mode"},
        )

    mode = deployment_cfg["mode"]
    if mode not in _VALID_DEPLOYMENT_MODES:
        raise StopPipeline(
            f"{cve_id}: deployment.mode = {mode!r} ใน {attack_path} ไม่รู้จัก — "
            f"รองรับแค่ {_VALID_DEPLOYMENT_MODES}",
            status="STOPPED",
            evidence={"attack_source_path": str(attack_path), "deployment_mode": mode},
        )

    if mode == "vulhub_compose":
        missing = [f for f in _VULHUB_COMPOSE_REQUIRED_FIELDS if not deployment_cfg.get(f)]
        if missing:
            raise StopPipeline(
                f"{cve_id}: deployment.mode = vulhub_compose ใน {attack_path} แต่ขาด field "
                f"{missing} — ต้องเพิ่มทั้งคู่ใต้ 'deployment:' เช่น\n\n"
                f"  deployment:\n"
                f"    mode: vulhub_compose\n"
                f"    vulhub_case_path: \"log4j/CVE-xxxx-xxxx\"\n"
                f"    victim_service: \"<compose service name ของ container เป้าหมาย>\"",
                status="STOPPED",
                evidence={"attack_source_path": str(attack_path), "missing_fields": missing},
            )

    return deployment_cfg


def resolve_case_config(cve_id: str, target_image: str, target_port: int) -> dict[str, Any]:
    """ประกอบ config เดียวจาก cve_meta + attack + patch ให้ CaseState ใช้

    target_image / target_port มาจาก scan/user input โดยตรง (ตามที่ตกลง — ไม่มี
    scan_input.yaml ล่วงหน้า ผู้ใช้/scan.py เป็นคนบอก image ตอนรันจริง)
    """
    meta_path = CVE_META_DIR / f"{cve_id}.yaml"
    meta = load_yaml(meta_path)

    # หา attack strategy ที่ verified แล้วตัวแรก (MVP: ยังไม่ match version range
    # ละเอียด — เอาตัวที่ verified: true ตัวแรกไปก่อน ตาม "ง่ายที่สุดก่อน")
    matched = None
    for affected in meta.get("affected", []):
        for vr in affected.get("version_ranges", []):
            if vr.get("verified") and vr.get("attack_strategy"):
                matched = (affected["dependency"], vr["attack_strategy"])
                break
        if matched:
            break

    if matched is None:
        raise StopPipeline(
            f"cve_meta ของ {cve_id} ไม่มี attack strategy ที่ verified — ยิงไม่ได้",
            status="SKIPPED",
            evidence={"cve_meta_path": str(meta_path)},
        )

    dependency, strategy = matched
    attack_path = ATTACK_DIR / strategy / f"{cve_id}.yaml"
    attack_cfg = load_yaml(attack_path)
    deployment_cfg = _resolve_deployment_config(cve_id, attack_path, attack_cfg)

    # patch module: หา fixed_version.yaml ที่ตรงกับ dependency นี้ — MVP เอาไฟล์แรกที่เจอ
    # ในโฟลเดอร์ dependency (ยังไม่มี logic เลือกระหว่างหลาย fixed_version)
    dep_dir_name = dependency.replace(":", "--")
    patch_dir = PATCH_DIR / dep_dir_name
    patch_cfg: Optional[dict[str, Any]] = None
    patch_path: Optional[Path] = None
    if patch_dir.exists():
        candidates = sorted(patch_dir.glob("*.yaml"))
        if candidates:
            patch_path = candidates[0]
            patch_cfg = load_yaml(patch_path)

    return {
        "cve_id": cve_id,
        "dependency": dependency,
        "attack_strategy": strategy,
        "deployment": deployment_cfg,
        "before_patch": {
            "image": target_image,
            "port": target_port,
        },
        "setup_steps": attack_cfg.get("setup_steps", []),
        "exploit": attack_cfg.get("exploit", {}),
        "oracle": attack_cfg.get("oracle", {}),
        "patch": patch_cfg,
        "patch_source_path": str(patch_path) if patch_path else None,
        "meta_source_path": str(meta_path),
        "attack_source_path": str(attack_path),
    }


def stage_scan(cve_id: str, image: str, phase: str = "before") -> dict[str, Any]:
    """เรียก scan_verify.sh <before|after> <CVE-ID> <image> แล้ว parse ผล
    (logic เดียวกับ stage_scan_before เดิมใน before_patch_pipeline.py)
    """
    print(f"[scan:{phase}] scan_verify.sh {phase} {cve_id} {image}")

    result = run(
        ["bash", str(SCRIPT_DIR / "scan_verify.sh"), phase, cve_id, image],
        f"scan_verify {phase}",
    )
    if result.returncode != 0:
        raise StopPipeline(
            f"scan_verify.sh ตัวมันเองพัง (ไม่ใช่เรื่อง CVE เจอ/ไม่เจอ): {result.stderr.strip()}",
            status="STOPPED",
            evidence={"stderr": result.stderr},
        )

    stdout = result.stdout
    found = "[FOUND]" in stdout
    scan_result = {"found": found, "raw_output_tail": stdout[-2000:]}

    if phase == "before" and not found:
        # ตาม freeze: scan ไม่ติด CVE เลย = ตัดจบทันที ไม่ retry
        raise StopPipeline(
            f"scan_verify.sh (before) ไม่พบ {cve_id} ใน {image} — ตัด case นี้ทิ้ง",
            status="SKIPPED",
            evidence=scan_result,
        )

    print(f"  [OK] scan ({phase}) found={found}")
    return scan_result


def stage_trivy_full_scan(image: str, output_json_path: Path) -> Path:
    """รัน trivy scan เต็ม image (ไม่ filter CVE เดียว) สำหรับ list.py ใช้ scoring
    ต่างจาก stage_scan() ตรงที่ตัวนี้เอา JSON ทั้งไฟล์ ไม่ query CVE เดียวด้วย jq

    หมายเหตุ: scan_verify.sh เดิม design มาสำหรับ query ทีละ CVE — ฟังก์ชันนี้
    เรียก trivy ตรงในตัว workbench container แทน ไม่ผ่าน scan_verify.sh
    (scan_verify.sh ไม่รองรับ mode "คืนทั้งไฟล์" ตาม CVE เดียว — ต้องเรียก trivy เอง)
    """
    from ..core import WORKBENCH_CONTAINER

    json_filename = output_json_path.name
    container_path = f"/workspace/{json_filename}"

    result = run(
        ["docker", "exec", WORKBENCH_CONTAINER, "bash", "-c",
         f"trivy image --timeout 15m -f json -o '{json_filename}' '{image}'"],
        "trivy full scan",
    )
    if result.returncode != 0:
        raise StopPipeline(
            f"trivy full scan ล้มเหลวสำหรับ image {image}",
            status="STOPPED",
            evidence={"stderr": result.stderr},
        )

    output_json_path.parent.mkdir(parents=True, exist_ok=True)
    cp_result = run(
        ["docker", "cp", f"{WORKBENCH_CONTAINER}:{container_path}", str(output_json_path)],
        "copy scan result to host",
    )
    if cp_result.returncode != 0 or not output_json_path.exists():
        raise StopPipeline(
            "docker cp ผลลัพธ์ trivy ล้มเหลว",
            status="STOPPED",
            evidence={"stderr": cp_result.stderr},
        )

    return output_json_path
