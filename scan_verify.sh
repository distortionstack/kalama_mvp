#!/usr/bin/env bash
#
# scan_verify.sh — Kalama scan pipeline (before-patch / after-patch)
#
# Usage:
#   ./scan_verify.sh <before|after> <CVE-XXXX-XXXXX> <image_name>
#
# Example:
#   ./scan_verify.sh before CVE-2017-5645 log4j-tcpserver:vulnerable
#   ./scan_verify.sh after  CVE-2017-5645 log4j-tcpserver:patched
#
# Notes:
#   - "kalama-workbench" is assumed as the fixed scanner container name
#     (per project convention: sibling container via docker socket mount).
#   - Output dirs follow the existing project layout:
#       output/scan/before-patch/trivy/
#       output/scan/after-patch/trivy/
#   - Does NOT auto-guess FixedVersion; only reports what Trivy found.
#   - Trivy scan timeout defaults to 15m (Trivy's own default of 5m is too
#     short for Java/jar-heavy images). Override with TRIVY_TIMEOUT=20m ./scan_verify.sh ...

set -uo pipefail

WORKBENCH_CONTAINER="kalama-workbench"
BASE_OUTPUT_DIR="${HOME}/kalama-labs-area/kalama-recovered/kalama/output/scan"
TRIVY_TIMEOUT="${TRIVY_TIMEOUT:-15m}"

# ---------- argument parsing ----------
if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <before|after> <CVE-ID> <image_name>" >&2
  exit 1
fi

PHASE="$1"
CVE_ID="$2"
IMAGE="$3"

case "$PHASE" in
  before)
    PHASE_DIR="before-patch"
    SUFFIX="bf"
    ;;
  after)
    PHASE_DIR="after-patch"
    SUFFIX="af"
    ;;
  *)
    echo "[ERROR] phase must be 'before' or 'after', got: $PHASE" >&2
    exit 1
    ;;
esac

# Normalize CVE id for filename (strip "CVE-" prefix if user included it, keep the rest)
CVE_NUM="${CVE_ID#CVE-}"

JSON_FILENAME="${CVE_NUM}-${SUFFIX}.json"
CONTAINER_WORKSPACE_PATH="/workspace/${JSON_FILENAME}"
HOST_OUTPUT_DIR="${BASE_OUTPUT_DIR}/${PHASE_DIR}/trivy"
HOST_OUTPUT_PATH="${HOST_OUTPUT_DIR}/${JSON_FILENAME}"

echo "=================================================================="
echo " Kalama scan_verify — phase: ${PHASE}"
echo " CVE:      CVE-${CVE_NUM}"
echo " Image:    ${IMAGE}"
echo " Output:   ${HOST_OUTPUT_PATH}"
echo "=================================================================="

mkdir -p "$HOST_OUTPUT_DIR"

# ---------- 1. Run trivy scan inside kalama-workbench ----------
echo
echo "[1/4] Running trivy scan in ${WORKBENCH_CONTAINER}..."
docker exec "$WORKBENCH_CONTAINER" bash -c \
  "trivy image --timeout '${TRIVY_TIMEOUT}' -f json -o '${JSON_FILENAME}' '${IMAGE}'"
SCAN_EXIT=$?

if [[ $SCAN_EXIT -ne 0 ]]; then
  echo "[FAIL] trivy scan exited with code ${SCAN_EXIT}"
  exit 1
fi

# Verify the file actually exists inside the container before copying
docker exec "$WORKBENCH_CONTAINER" test -f "$CONTAINER_WORKSPACE_PATH"
if [[ $? -ne 0 ]]; then
  echo "[FAIL] Scan reported success but ${CONTAINER_WORKSPACE_PATH} not found in container"
  exit 1
fi
echo "[OK] Scan complete, file exists in container: ${CONTAINER_WORKSPACE_PATH}"

# ---------- 2. docker cp out to host ----------
echo
echo "[2/4] Copying result to host..."
docker cp "${WORKBENCH_CONTAINER}:${CONTAINER_WORKSPACE_PATH}" "${HOST_OUTPUT_DIR}/"
CP_EXIT=$?

if [[ $CP_EXIT -ne 0 ]]; then
  echo "[FAIL] docker cp exited with code ${CP_EXIT}"
  exit 1
fi

# ---------- 3. Verify file actually exists on host ----------
echo
echo "[3/4] Verifying file on host..."
if [[ -f "$HOST_OUTPUT_PATH" ]]; then
  FILE_SIZE=$(stat -c%s "$HOST_OUTPUT_PATH" 2>/dev/null || stat -f%z "$HOST_OUTPUT_PATH" 2>/dev/null)
  echo "[OK] File exists: ${HOST_OUTPUT_PATH} (${FILE_SIZE} bytes)"
else
  echo "[FAIL] File NOT found at ${HOST_OUTPUT_PATH} despite docker cp reporting success"
  exit 1
fi

# ---------- 4. jq query ----------
echo
echo "[4/4] Querying for CVE-${CVE_NUM}..."
echo "------------------------------------------------------------------"

QUERY_RESULT=$(jq -r '
  .Results[]?
  | .Vulnerabilities[]?
  | select(.VulnerabilityID == "CVE-'"${CVE_NUM}"'")
  | {
      id: .VulnerabilityID,
      fixedVersion: .FixedVersion,
      pkg: .PkgName,
      installed: .InstalledVersion
    }
' "$HOST_OUTPUT_PATH")
JQ_EXIT=$?

if [[ $JQ_EXIT -ne 0 ]]; then
  echo "[FAIL] jq query failed (exit ${JQ_EXIT}) — file may not be valid JSON"
  exit 1
fi

if [[ -z "$QUERY_RESULT" ]]; then
  echo "[NOT FOUND] CVE-${CVE_NUM} does not appear in ${JSON_FILENAME}"
  echo "            (This may mean: not detected, already absent, or package not scanned.)"
else
  echo "[FOUND] CVE-${CVE_NUM} matched:"
  echo "$QUERY_RESULT"
fi

echo "------------------------------------------------------------------"
echo
echo "=================================================================="
echo " SUMMARY (${PHASE_DIR})"
echo "   Scan:        OK"
echo "   Copy:        OK"
echo "   File exists: OK (${HOST_OUTPUT_PATH})"
if [[ -z "$QUERY_RESULT" ]]; then
  echo "   CVE match:   NOT FOUND"
else
  echo "   CVE match:   FOUND"
fi
echo "=================================================================="
