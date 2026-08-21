#!/usr/bin/env bash
# ==============================================================================
# Kalama Environment Check
# ------------------------------------------------------------------------------
# เช็คว่า workbench มีเครื่องมือครบตามไกด์ GUIDE-1 หรือยัง
# รันก่อนเริ่มงานทุกครั้ง หรือหลัง setup-workbench.sh ใหม่
# ==============================================================================
set -uo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-kalama-workbench}"
PASS=0
FAIL=0

check() {
  local label="$1"
  local cmd="$2"
  if docker exec "$CONTAINER_NAME" sh -c "$cmd" >/dev/null 2>&1; then
    printf "  [OK]   %s\n" "$label"
    PASS=$((PASS+1))
  else
    printf "  [MISS] %s\n" "$label"
    FAIL=$((FAIL+1))
  fi
}

if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
  echo "ไม่พบ container $CONTAINER_NAME — รัน ./setup-workbench.sh ก่อน"
  exit 1
fi

echo "==> ตรวจสอบเครื่องมือใน $CONTAINER_NAME (ตามไกด์ GUIDE-1 หมวด 'เครื่องมือทั้งหมด')"
echo ""
echo "-- ตัวรัน container --"
check "docker (sibling, ผ่าน docker.sock)" "docker --version"
check "docker compose"                     "docker compose version"

echo ""
echo "-- source control / ภาษา --"
check "git"        "git --version"
check "python3"    "python3 --version"
check "pip3"       "pip3 --version"

echo ""
echo "-- Python libraries --"
check "requests"      "python3 -c 'import requests'"
check "pyyaml"        "python3 -c 'import yaml'"
check "pandas"        "python3 -c 'import pandas'"
check "scikit-learn"  "python3 -c 'import sklearn'"
check "streamlit"     "python3 -c 'import streamlit'"

echo ""
echo "-- scanner (oracle) --"
check "trivy" "trivy --version"
check "grype (เสริม, เทียบผลกับ trivy)" "grype version"
check "kubescape (เสริม, ตามไกด์ — ไม่ใช่ core scope)" "kubescape version"

echo ""
echo "-- exploitation helper (ตามไกด์ ไม่ใช่ core, เผื่อใช้) --"
check "netcat"      "which nc"
check "java (jre)"  "java -version"
check "searchsploit (ExploitDB)" "searchsploit --help"

echo ""
echo "-- Metasploit (รันเป็น container แยก ไม่ได้อยู่ใน workbench) --"
if docker image inspect metasploitframework/metasploit-framework:latest >/dev/null 2>&1; then
  printf "  [OK]   metasploit image พร้อมใช้ (docker run --rm -it metasploitframework/metasploit-framework msfconsole)\n"
  PASS=$((PASS+1))
else
  printf "  [MISS] metasploit image — รัน ./setup-workbench.sh เพื่อดึง image\n"
  FAIL=$((FAIL+1))
fi
echo ""
echo "-- Nuclei (รันเป็น container แยก) --"
if docker image inspect projectdiscovery/nuclei:latest >/dev/null 2>&1; then
  printf "  [OK]   nuclei image พร้อมใช้\n"
  PASS=$((PASS+1))
else
  printf "  [MISS] nuclei image — รัน ./setup-workbench.sh เพื่อดึง image\n"
  FAIL=$((FAIL+1))
fi

echo ""
echo "=================================================================="
echo " ผ่าน $PASS / เสีย $FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo " มีเครื่องมือขาด — รัน ./setup-workbench.sh อีกครั้งเพื่อติดตั้งซ้ำ"
  exit 1
else
  echo " สภาพแวดล้อมพร้อม เริ่มงานได้"
fi
echo "=================================================================="
