#!/usr/bin/env bash
# ==============================================================================
# Kalama Run-Case
# ------------------------------------------------------------------------------
# รัน vulhub CVE scenario จาก host โดยสั่งผ่าน workbench container
# ตัวอย่าง: ./run-case.sh log4j/CVE-2017-5645 up
#           ./run-case.sh log4j/CVE-2017-5645 down
#           ./run-case.sh log4j/CVE-2017-5645 ip     (ดู container IP ของ case นั้น)
# ==============================================================================
set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-kalama-workbench}"
CASE_PATH="${1:-}"
ACTION="${2:-up}"

if [ -z "$CASE_PATH" ]; then
  echo "ใช้งาน: ./run-case.sh <vulhub-case-path> [up|down|ip|logs]"
  echo "ตัวอย่าง: ./run-case.sh log4j/CVE-2017-5645 up"
  exit 1
fi

CASE_DIR="/workspace/vulhub/$CASE_PATH"

case "$ACTION" in
  up)
    echo "==> docker compose up -d ที่ $CASE_DIR"
    docker exec -w "$CASE_DIR" "$CONTAINER_NAME" docker compose up -d
    ;;
  down)
    echo "==> docker compose down ที่ $CASE_DIR"
    docker exec -w "$CASE_DIR" "$CONTAINER_NAME" docker compose down
    ;;
  ip)
    SVC_CONTAINER=$(docker exec -w "$CASE_DIR" "$CONTAINER_NAME" docker compose ps -q | head -n1)
    if [ -z "$SVC_CONTAINER" ]; then
      echo "ไม่พบ container ที่รันอยู่ ลอง up ก่อน"
      exit 1
    fi
    docker inspect "$SVC_CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
    ;;
  logs)
    docker exec -w "$CASE_DIR" "$CONTAINER_NAME" docker compose logs -f
    ;;
  *)
    echo "ไม่รู้จัก action: $ACTION (ใช้ up|down|ip|logs)"
    exit 1
    ;;
esac
