"""
update/update.py — PATCH stage, dependency-centric (ไม่รู้จัก CVE เลย)

ต่างจาก patch_stage.py เดิม (ที่ผูกกับ Struts/tier_1-tier_2 เฉพาะ build-from-source)
ตัวนี้ generalize ตาม patch/{dependency}/{version}.yaml schema ใหม่:
    1. ลอง fixed_version_strategy ก่อนเสมอ (ตรงจาก Trivy FixedVersion)
    2. ถ้า "ติดตั้งไม่ได้จริง" (ไม่ใช่แค่ declared EOL) → fallback ไป
       upstream_fallback_strategy โดยอัตโนมัติ ตาม hybrid policy ที่ตกลงไว้
    3. บันทึกว่าใช้ strategy ไหนจริง ลง state.json (verified_case tracking)

"ติดตั้งไม่ได้จริง" ตัดสินโดยโค้ด (operational check) ไม่ใช่ config บอกไว้ล่วงหน้า
— ตาม principle ที่คุยกัน: "declared EOL ยังอาจ install ได้ผ่าน archive mirror"
ดังนั้นต้องลองจริงก่อนถึงจะ fallback ไม่ใช่เช็คแค่ label

install_method ที่รองรับตอนนี้: prebuilt_download (fix_type B)
build_from_source / os_package (fix_type A/C) ยังเป็น stub — ต้องเพิ่ม handler
เองใน INSTALL_METHOD_DISPATCH ก่อนใช้กับ CVE ที่เป็น fix_type A/C
"""

from __future__ import annotations

import operator
import re
import subprocess
from pathlib import Path
from string import Template
from typing import Any, Callable, Optional

from ..core import CaseState, StopPipeline, VICTIM_CONTAINER, KALAMA_NETWORK, run


# ---------------------------------------------------------------------------
# applies_when — safe parser แทน eval() (ดู AGENT_README ข้อ 3)
# รองรับแค่รูปแบบ "major_version <op> <int>" เท่านั้น ตามที่ config ใช้จริงตอนนี้
# ไม่ตีความ syntax อื่น — ถ้าไม่ match ให้ raise ตรงๆ ไม่เดา
# ---------------------------------------------------------------------------

_APPLIES_WHEN_OPS: dict[str, Callable[[int, int], bool]] = {
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    "<": operator.lt,
}
_APPLIES_WHEN_RE = re.compile(
    r"^major_version\s*(" + "|".join(re.escape(op) for op in _APPLIES_WHEN_OPS) + r")\s*(\d+)$"
)


def _eval_applies_when(applies_when: str, major_version: int) -> bool:
    if applies_when == "always":
        return True
    match = _APPLIES_WHEN_RE.match(applies_when.strip())
    if not match:
        raise StopPipeline(
            f"applies_when รูปแบบไม่รองรับ: {applies_when!r} "
            f"(รองรับแค่ 'always' หรือ 'major_version <op> <int>')",
            status="STOPPED",
            evidence={"applies_when": applies_when},
        )
    op_str, rhs = match.groups()
    return _APPLIES_WHEN_OPS[op_str](major_version, int(rhs))


# ---------------------------------------------------------------------------
# install method handlers — dispatch table, เพิ่มตัวใหม่ที่นี่เมื่อรองรับ fix_type อื่น
# ---------------------------------------------------------------------------

def _url_reachable(url: str) -> bool:
    """HEAD request เช็คว่า url ยังอยู่จริงไหม — ใช้ตัดสินว่า
    fixed_version_strategy "ติดตั้งไม่ได้จริง" หรือไม่ (ไม่ใช่แค่ดูว่าเก่า)
    """
    result = run(["curl", "-sf", "-I", "--max-time", "10", url], "check URL reachable", check=False)
    return result.returncode == 0


def _install_prebuilt_download(strategy: dict[str, Any], version: str, workdir: Path) -> dict[str, Any]:
    """install_method: prebuilt_download — ดาวน์โหลด tarball แล้ว extract
    ทับ install_path (ใช้ template string ธรรมดา ไม่ generate logic ซับซ้อน —
    field มาจาก config ทั้งหมด โค้ดแค่ execute)
    """
    url_template = strategy["source_url_template"]
    url = Template(url_template.replace("${", "$").replace("}", "")).safe_substitute(
        ES_VERSION=version, LATEST_VERSION=version,
    )
    # NOTE: bash-style ${VAR} ใน YAML ต้อง normalize เป็น Python string.Template ($VAR)
    # ก่อน — ถ้า URL template มีตัวแปรอื่นนอกจาก ES_VERSION/LATEST_VERSION ต้องเพิ่มที่นี่

    if not _url_reachable(url):
        return {"success": False, "reason": "url_not_reachable", "url": url}

    workdir.mkdir(parents=True, exist_ok=True)
    dl_result = run(
        ["bash", "-c", f"curl -sfL '{url}' | tar zx --strip-components 1 -C '{workdir}'"],
        "download + extract tarball",
    )
    if dl_result.returncode != 0:
        return {"success": False, "reason": "download_or_extract_failed", "stderr": dl_result.stderr}

    return {"success": True, "url": url, "install_dir": str(workdir)}


INSTALL_METHOD_DISPATCH: dict[str, Callable] = {
    "prebuilt_download": _install_prebuilt_download,
    # "build_from_source": ...  # TODO: port จาก patch_stage.py เดิม (tier_1/tier_2 split)
    # "os_package": ...          # TODO: apt install ผ่าน archive mirror + [trusted=yes]
}


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def _try_strategy(
    strategy_name: str, strategy_cfg: dict[str, Any], version: str, workdir: Path,
) -> dict[str, Any]:
    install_method = strategy_cfg["install_method"]
    handler = INSTALL_METHOD_DISPATCH.get(install_method)
    if handler is None:
        return {
            "success": False,
            "reason": "unsupported_install_method",
            "install_method": install_method,
        }
    result = handler(strategy_cfg, version, workdir)
    result["strategy_name"] = strategy_name
    result["install_method"] = install_method
    return result


def _resolve_latest_upstream_version(strategy_cfg: dict[str, Any]) -> Optional[str]:
    """query latest_version_lookup ตาม config — ยังไม่ verified endpoint จริง
    (ดู note ใน patch YAML: latest_version_lookup.url/field เป็น placeholder)
    ถ้า config ไม่มี lookup หรือ query fail ให้คืน None แล้วให้ caller ตัดสินใจต่อ
    (raise StopPipeline บอกว่าต้องกรอก version ตายตัวแทน)
    """
    lookup = strategy_cfg.get("latest_version_lookup")
    if not lookup:
        return None
    try:
        import requests
        resp = requests.get(lookup["url"], timeout=10)
        resp.raise_for_status()
        data = resp.json()
        field = lookup["version_field"]
        # field path แบบง่าย ๆ ("latest") — ไม่รองรับ nested path ซับซ้อนตอนนี้
        return data.get(field)
    except Exception:
        return None


def stage_patch(case: CaseState, workdir_root: Path) -> dict[str, Any]:
    """entrypoint หลัก — เรียกจาก main.py subcommand 'patch'

    ลำดับ:
        1. ลอง fixed_version_strategy ด้วย fixed_version จาก config
        2. ถ้า fail (ติดตั้งไม่ได้จริง) → ลอง upstream_fallback_strategy
           โดย resolve latest version ก่อน (หรือใช้ verified_case ที่เคยบันทึกไว้
           ถ้ามี — ดู note ด้านล่าง)
        3. build image, rebuild victim container (patch-as-rebuild policy)
    """
    patch_cfg = case.config.get("patch")
    if patch_cfg is None:
        raise StopPipeline(
            f"{case.cve_id}: ไม่มี patch config (dependency ไม่มี patch/ module) — ยิงไม่ได้",
            status="SKIPPED",
            evidence={},
        )

    dependency = patch_cfg["dependency"]
    fixed_version = patch_cfg["fixed_version"]
    workdir = workdir_root / case.cve_id / "patch_workdir"

    print(f"[patch] dependency={dependency} fixed_version={fixed_version}")

    # --- 1. ลอง fixed_version_strategy ก่อนเสมอ ---
    fixed_strategy = patch_cfg.get("fixed_version_strategy")
    attempt_log = []

    used_strategy = None
    used_version = None
    install_result = None

    if fixed_strategy:
        result = _try_strategy("fixed_version", fixed_strategy, fixed_version, workdir)
        attempt_log.append(result)
        if result.get("success"):
            used_strategy = "fixed_version"
            used_version = fixed_version
            install_result = result

    # --- 2. fallback ถ้า fixed_version ติดตั้งไม่ได้จริง ---
    if install_result is None:
        fallback_strategy = patch_cfg.get("upstream_fallback_strategy")
        if fallback_strategy is None:
            raise StopPipeline(
                f"{case.cve_id}: fixed_version_strategy ล้มเหลว และไม่มี upstream_fallback_strategy",
                status="STOPPED",
                evidence={"attempts": attempt_log},
            )

        # ลอง resolve latest version — ถ้า resolve ไม่ได้ ใช้ verified_case ที่เคย
        # บันทึกไว้ก่อนหน้า (manual-confirmed version) เป็น fallback ของ fallback
        latest_version = _resolve_latest_upstream_version(fallback_strategy)
        if latest_version is None:
            verified = patch_cfg.get("verified_case", [])
            if verified and verified[0].get("fallback_used") and verified[0].get("actual_version_installed"):
                latest_version = verified[0]["actual_version_installed"]
                print(f"  [WARN] latest_version_lookup ล้มเหลว — ใช้ verified_case ที่เคย manual-confirm: {latest_version}")
            else:
                raise StopPipeline(
                    f"{case.cve_id}: resolve latest upstream version ไม่ได้ และไม่มี verified_case ให้ fallback",
                    status="STOPPED",
                    evidence={"attempts": attempt_log},
                )

        result = _try_strategy("upstream_fallback", fallback_strategy, latest_version, workdir)
        attempt_log.append(result)
        if not result.get("success"):
            raise StopPipeline(
                f"{case.cve_id}: ทั้ง fixed_version และ upstream_fallback strategy ล้มเหลว",
                status="STOPPED",
                evidence={"attempts": attempt_log},
            )
        used_strategy = "upstream_fallback"
        used_version = latest_version
        install_result = result

    # --- 3. build + rebuild container (patch-as-rebuild) ---
    build_cfg = patch_cfg.get("build", {})
    dockerfile_path = _write_dockerfile(case.cve_id, workdir_root, install_result, build_cfg, patch_cfg, used_version)
    image_tag = f"kalama-patched-{case.cve_id.lower()}-{used_version}"

    build_result = run(
        ["docker", "build", "-t", image_tag, str(dockerfile_path.parent)],
        "docker build patched image",
    )
    if build_result.returncode != 0:
        raise StopPipeline(
            f"{case.cve_id}: docker build patched image ล้มเหลว",
            status="STOPPED",
            evidence={"stderr": build_result.stderr[-2000:]},
        )

    result = {
        "used_strategy": used_strategy,
        "used_version": used_version,
        "image_tag": image_tag,
        "attempts": attempt_log,
        "causal_attribution_note": (
            "same_branch minimal patch" if used_strategy == "fixed_version"
            else "cross-major fallback — ดู remediation.causal_attribution ใน patch config สำหรับข้อความมาตรฐาน"
        ),
    }
    case.record("patch", result)
    print(f"  [OK] patch เสร็จ — strategy={used_strategy} version={used_version} image={image_tag}")
    return result


def _write_dockerfile(
    cve_id: str, workdir_root: Path, install_result: dict[str, Any],
    build_cfg: dict[str, Any], patch_cfg: dict[str, Any], version: str,
) -> Path:
    """สร้าง Dockerfile ธรรมดา ไม่ generate logic ซับซ้อน — field มาจาก
    build_cfg.required_config_overrides ทั้งหมด (โค้ดไม่ hardcode config เอง)
    """
    base_image = build_cfg.get("base_image", "debian:bookworm-slim")
    install_path = build_cfg.get("install_path", "/opt/app")

    overrides_lines = []
    major_version = int(version.split(".")[0]) if version[0].isdigit() else 0
    for override in patch_cfg.get("upstream_fallback_strategy", {}).get("known_config_overrides_required", []):
        applies_when = override.get("applies_when", "always")
        if _eval_applies_when(applies_when, major_version):
            overrides_lines.append(f'echo "{override["key"]}: {override["value"]}"')

    config_append = " && ".join(overrides_lines) if overrides_lines else "true"

    dockerfile_dir = workdir_root / cve_id / "patch_build"
    dockerfile_dir.mkdir(parents=True, exist_ok=True)

    content = f"""FROM {base_image}
COPY patch_workdir {install_path}
RUN {config_append}
"""
    dockerfile_path = dockerfile_dir / "Dockerfile"
    dockerfile_path.write_text(content)
    return dockerfile_path
