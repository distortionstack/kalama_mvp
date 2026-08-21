#!/usr/bin/env bash
# ==============================================================================
# Kalama Workbench Setup
# ------------------------------------------------------------------------------
# สร้าง "workbench" container ที่ mount docker.sock จาก host เข้าไป
# (sibling-container, ไม่ใช่ DinD จริง) เพื่อรัน docker compose ของ vulhub
# ได้จากข้างใน โดยไม่ต้อง nested storage driver ที่เปราะกว่า
#
# หลักการ: state ที่สำคัญ (kalama/, vulhub/, m2 cache) อยู่บน named volume
# แยกจากตัว container เสมอ -> container พังได้ volume ไม่หาย
# ==============================================================================
set -euo pipefail

# ---- ค่าตั้งต้น (แก้ได้ผ่าน env var ตอนเรียก เช่น LAB_DIR=... ./setup-workbench.sh) ----
CONTAINER_NAME="${CONTAINER_NAME:-kalama-workbench}"
LAB_DIR="${LAB_DIR:-$HOME/kalama-labs-area/kalama-recovered}"   # โฟลเดอร์ที่กู้คืนมา
VOLUME_M2="${VOLUME_M2:-kalama-m2-cache}"                        # maven cache กันโหลดซ้ำทุกครั้ง
NETWORK_NAME="${NETWORK_NAME:-kalama-net}"

echo "==> ตรวจสอบ prerequisite"
command -v docker >/dev/null 2>&1 || { echo "ไม่พบ docker บน host กรุณาลงก่อน"; exit 1; }

if [ ! -d "$LAB_DIR" ]; then
  echo "ไม่พบ $LAB_DIR — แก้ path ผ่าน LAB_DIR=/path/to/kalama-recovered ./setup-workbench.sh"
  exit 1
fi

echo "==> LAB_DIR = $LAB_DIR"
echo "    (จะถูก bind-mount เข้า container ที่ /workspace)"

echo "==> สร้าง named volume สำหรับ state ที่ต้องรอด (maven cache)"
docker volume inspect "$VOLUME_M2" >/dev/null 2>&1 || docker volume create "$VOLUME_M2"

echo "==> สร้าง network แยกสำหรับแล็ป (กัน container vulhub ชนกับของอื่นบน host)"
docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"

echo "==> ลบ workbench container เก่า (ถ้ามี) — ตัวนี้ disposable ได้เสมอ"
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo "==> สร้าง workbench container ใหม่"
docker run -d \
  --name "$CONTAINER_NAME" \
  --network "$NETWORK_NAME" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$LAB_DIR":/workspace \
  -v "$VOLUME_M2":/root/.m2 \
  -w /workspace \
  --restart unless-stopped \
  docker:cli \
  sleep infinity

echo "==> ติดตั้งเครื่องมือพื้นฐาน (bash, git, curl, docker compose)"
docker exec "$CONTAINER_NAME" sh -c "
  apk add --no-cache bash curl wget git openjdk8-jre netcat-openbsd python3 py3-pip build-base >/dev/null 2>&1
  apk add --no-cache docker-cli-compose >/dev/null 2>&1 || apk add --no-cache docker-compose >/dev/null 2>&1
"

echo "==> ติดตั้ง Python libraries ตามไกด์ (requests, pyyaml, pandas, scikit-learn, streamlit)"
echo "    (ใช้ --break-system-packages เพราะ Alpine บล็อก pip system-wide (PEP 668)"
echo "     ปลอดภัยในที่นี้เพราะ container นี้ disposable อยู่แล้ว ไม่ใช่ host จริง)"
echo "    (ติดตั้งแยกทีละตัว กันตัวที่พัง compile ลากตัวอื่นพังไปด้วย)"
docker exec "$CONTAINER_NAME" sh -c "
  pip3 install --break-system-packages --quiet requests || echo '  [WARN] requests ติดตั้งไม่สำเร็จ'
  pip3 install --break-system-packages --quiet pyyaml   || echo '  [WARN] pyyaml ติดตั้งไม่สำเร็จ'
  pip3 install --break-system-packages --quiet streamlit || echo '  [WARN] streamlit ติดตั้งไม่สำเร็จ'
"

echo "==> ติดตั้ง pandas + scikit-learn ผ่าน apk (prebuilt binary — เลี่ยงปัญหา compile จาก source บน Alpine)"
docker exec "$CONTAINER_NAME" sh -c "
  apk add --no-cache py3-pandas py3-scikit-learn >/dev/null 2>&1 || \
  echo '  [WARN] apk py3-pandas/py3-scikit-learn ไม่มีใน repo นี้ จะลอง pip แทน (อาจช้าเพราะต้อง compile)'
"
docker exec "$CONTAINER_NAME" sh -c "
  python3 -c 'import pandas' 2>/dev/null || pip3 install --break-system-packages --quiet pandas
  python3 -c 'import sklearn' 2>/dev/null || (
    apk add --no-cache py3-numpy py3-scipy openblas-dev gfortran >/dev/null 2>&1
    pip3 install --break-system-packages --quiet scikit-learn
  )
"

echo "==> ติดตั้ง Trivy (CVE scanner หลัก — ตัวเดียวที่ pipeline ใช้เป็น oracle)"
echo "    ใช้ v0.72.0 (เวอร์ชันหลัง supply-chain incident มี.ค. 2026 ที่ Aqua ยืนยันความปลอดภัยแล้ว"
echo "    ห้ามใช้เวอร์ชันเก่ากว่านี้ เพราะ release เดิมถูกลบ/บางตัวถูกฝังมัลแวร์ช่วงเหตุการณ์นั้น)"
docker exec "$CONTAINER_NAME" sh -c "
  if ! command -v trivy >/dev/null 2>&1; then
    TRIVY_VERSION=0.72.0
    ARCH=\$(uname -m)
    case \"\$ARCH\" in
      x86_64) TRIVY_ARCH=64bit ;;
      aarch64) TRIVY_ARCH=ARM64 ;;
      *) TRIVY_ARCH=64bit ;;
    esac
    cd /tmp
    curl -sfL -o trivy.tar.gz \
      \"https://github.com/aquasecurity/trivy/releases/download/v\${TRIVY_VERSION}/trivy_\${TRIVY_VERSION}_Linux-\${TRIVY_ARCH}.tar.gz\"
    curl -sfL -o trivy_checksums.txt \
      \"https://github.com/aquasecurity/trivy/releases/download/v\${TRIVY_VERSION}/trivy_\${TRIVY_VERSION}_checksums.txt\"
    if [ -s trivy.tar.gz ] && [ -s trivy_checksums.txt ]; then
      grep \"Linux-\${TRIVY_ARCH}.tar.gz\" trivy_checksums.txt | sha256sum -c - \
        && echo '  [checksum OK]' \
        || echo '  [WARN] checksum ไม่ตรง — อย่าใช้ไฟล์นี้ ตรวจสอบด้วยตนเองก่อน'
      tar -xzf trivy.tar.gz -C /usr/local/bin trivy
    else
      echo '  [WARN] ดาวน์โหลด trivy ไม่สำเร็จ'
    fi
    rm -f trivy.tar.gz trivy_checksums.txt
  fi
"

echo "==> ติดตั้ง Grype (scanner เสริม — ไว้เทียบผลกับ Trivy)"
docker exec "$CONTAINER_NAME" sh -c "
  if ! command -v grype >/dev/null 2>&1; then
    curl -sfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  fi
"

echo "==> ติดตั้ง Kubescape (ตามไกด์ — ใช้ reachability check, ไม่ใช่ core ของ Kalama scope ปัจจุบัน)"
docker exec "$CONTAINER_NAME" sh -c "
  if ! command -v kubescape >/dev/null 2>&1; then
    curl -sfL https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh -o /tmp/ks-install.sh
    bash /tmp/ks-install.sh || echo '  [WARN] kubescape ติดตั้งไม่สำเร็จ ข้ามไปก่อน'
    rm -f /tmp/ks-install.sh
  fi
"

echo "==> ติดตั้ง ExploitDB (searchsploit)"
docker exec "$CONTAINER_NAME" sh -c "
  if ! command -v searchsploit >/dev/null 2>&1; then
    apk add --no-cache exploitdb >/dev/null 2>&1 || (
      git clone --depth 1 https://github.com/offensive-security/exploitdb.git /opt/exploitdb 2>/dev/null
      ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
    )
  fi
"

echo "==> Metasploit Framework"
echo "    หมายเหตุ: ตัว omnibus installer ของ Rapid7 ทำมาสำหรับ glibc (Ubuntu/Debian/CentOS)"
echo "    เท่านั้น ไม่ compatible กับ Alpine (musl libc) ที่ workbench ใช้อยู่ — ถ้าฝืนติดตั้งในนี้"
echo "    เสี่ยงพังแบบเดาไม่ออก จึงรันเป็น container แยกต่างหากแทน (official image จาก Rapid7)"
docker pull metasploitframework/metasploit-framework:latest >/dev/null 2>&1 && \
  echo "    [OK] ดึง image metasploitframework/metasploit-framework แล้ว" || \
  echo "    [WARN] ดึง image metasploit ไม่สำเร็จ (เช็ค network/docker แยกอีกที)"
echo "==> Nuclei (template-based exploit verifier — รันเป็น container แยกเหมือน MSF)"
echo "    เหตุผลที่แยก: templates เยอะ (~9k) เก็บใน workbench จะบวม + ปนกับ state งาน"
echo "    pin เวอร์ชันไว้กัน template DSL เปลี่ยนแล้วผล reproduce ไม่ตรง (สำคัญต่อ thesis)"
docker pull projectdiscovery/nuclei:latest >/dev/null 2>&1 && \
  echo "    [OK] ดึง image projectdiscovery/nuclei แล้ว" || \
  echo "    [WARN] ดึง image nuclei ไม่สำเร็จ (เช็ค network/docker แยกอีกที)"

echo ""
echo "=================================================================="
echo " Workbench พร้อมใช้: $CONTAINER_NAME"
echo "=================================================================="
echo " เข้าไปใช้งาน:  docker exec -it $CONTAINER_NAME bash"
echo " workspace อยู่ที่ /workspace (= $LAB_DIR บน host)"
echo " เช็คเครื่องมือ:  ./check-env.sh"
echo " รัน Metasploit (แยก container):  docker run --rm -it --network $NETWORK_NAME metasploitframework/metasploit-framework msfconsole"
echo " ลบทิ้งสร้างใหม่ได้ทุกเมื่อ: ./setup-workbench.sh (state ไม่หายเพราะอยู่ volume/bind mount)"
echo "=================================================================="

