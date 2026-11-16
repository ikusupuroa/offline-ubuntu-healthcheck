#!/bin/bash
# offline-ubuntu-healthcheck｜收集腳本（collect.sh）
# 版本：0.3
#
# 在受檢主機上執行，只讀取系統資訊，產出一個 tar.gz 交給分析電腦。
# 弱點比對不在主機上做，主機上不需要安裝任何東西，也不需要連網。
#
# 設計目標（以實機測試紀錄為準）：
#   - 不安裝套件、不改設定、不重啟服務、不執行 apt update，不主動連網。
#   - 寫入的位置：系統暫存目錄（執行中暫存，結束時刪除），以及目前目錄的 hc-<代號>-<日期>.tar.gz。
#   - 注意：pro 指令本身可能寫入自己的記錄檔，已註冊的主機也可能嘗試連線原廠伺服器；
#     離線環境每個 pro 指令最多等 60 秒。
#
# 權限：一般使用者即可執行（預設）。用 sudo 執行時，另外檢查 SSH 設定、防火牆（ufw）、空密碼帳號三項；
#   沒有 sudo 時，報告會把這三項列在「未能檢查」。
#
# 不收集：密碼、金鑰、使用者家目錄、主機名稱、IP 位址、Pro 帳號與合約資訊。
#   /etc/shadow 只計算「空密碼帳號數」；連接埠只記協定與埠號；套件來源網址只保留 ubuntu.com／canonical.com，
#   其他網址的主機與路徑遮蔽為 <private-mirror>，並移除網址中的帳號密碼；來源設定檔不記檔名。
#   防火牆只記啟用狀態（不收規則）；UID 0 帳號只記數量。
#
# 用法：
#   bash collect.sh --tag H01           # 一般使用者
#   sudo bash collect.sh --tag H01      # 加做三項設定檢查
#   代號由受檢單位自訂，代號與主機的對照表只留在受檢單位。

set -u
umask 077
export LC_ALL=C

TAG="UNTAGGED"
if [ "${1:-}" = "--tag" ] && [ -n "${2:-}" ]; then TAG="$2"; else
  echo "提醒：未指定 --tag，輸出檔將以 UNTAGGED 命名。建議用 --tag H01 這類代號。"
fi
TAG="$(printf '%s' "$TAG" | tr -c 'A-Za-z0-9._-' '_')"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTNAME="hc-${TAG}-${STAMP}"
WORK="$(mktemp -d 2>/dev/null)" || { echo "無法建立暫存目錄"; exit 1; }
trap 'rm -rf "$WORK"' EXIT
D="${WORK}/${OUTNAME}"
mkdir -p "$D"

have() { command -v "$1" >/dev/null 2>&1; }
# run <輸出檔> <指令...>：執行並記錄結束碼，失敗不中斷
run() {
  local f="$1"; shift
  { "$@"; echo "__EXIT__=$?"; } > "${D}/${f}" 2>&1
}
T=""; have timeout && T="timeout 60"
# 只保留 Pro 狀態中分析需要的欄位（去掉帳號、合約資訊）
PRO_FILTER='import json,sys
raw=sys.stdin.read(); dec=json.JSONDecoder(); d={}; i=raw.find("{")
while i>=0:
    try:
        d=dec.raw_decode(raw[i:])[0]; break
    except Exception:
        i=raw.find("{",i+1)
if not isinstance(d,dict): d={}
print(json.dumps({"attached":d.get("attached"),"services":[{"name":s.get("name"),"status":s.get("status"),"entitled":s.get("entitled")} for s in d.get("services",[]) if isinstance(s,dict)]}))'

{
  echo "collector_version=0.3"
  echo "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "tag=${TAG}"
  echo "uid=$(id -u)"
} > "${D}/meta.txt"

# 1. 作業系統與版本
run os-release.txt cat /etc/os-release

# 2. 核心（不含主機名稱）
run kernel-release.txt uname -r
run uname.txt uname -srm
run uptime.txt cat /proc/uptime
[ -f /var/run/reboot-required ] && echo "yes" > "${D}/reboot-required.txt"

# 3. 已安裝套件（分析電腦會用這份清單與官方 OVAL 比對）
run dpkg.txt dpkg-query -W -f '${Package}\t${Version}\t${Status}\t${Source}\t${Architecture}\n'

# 4. 套件來源（遮蔽私有網址與帳密）與更新設定
# 網址處理：先移除帳號密碼（scheme:// 到最後一個 @），再逐一檢查主機名稱，非 ubuntu.com／canonical.com 一律遮蔽
MASK_AWK='{ for (i = 1; i <= NF; i++) { p = index($i, "://"); if (p == 0) continue;
  pre = substr($i, 1, p + 2); rest = substr($i, p + 3);
  while ((q = index(rest, "@")) > 0) rest = substr(rest, q + 1);
  s = index(rest, "/"); host = (s ? substr(rest, 1, s - 1) : rest); path = (s ? substr(rest, s) : "");
  if (host !~ /^([A-Za-z0-9-]+\.)*(ubuntu|canonical)\.com(:[0-9]+)?$/) { host = "<private-mirror>"; path = "" }
  $i = pre host path } print }'
{ n=0; for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
    [ -f "$f" ] || continue; n=$((n+1))
    case "${f##*/}" in *.sources) k=deb822 ;; *) k=list ;; esac
    echo "### 來源檔 ${n}（${k}）"   # 不記檔名：檔名可能透露單位或系統名稱
    grep -v "^[[:space:]]*#" "$f"
  done | awk "$MASK_AWK"; echo "__EXIT__=$?"; } > "${D}/apt-sources.txt" 2>&1
[ -f /var/lib/apt/periodic/update-success-stamp ] && run apt-update-stamp.txt stat -c '%y' /var/lib/apt/periodic/update-success-stamp
run unattended-upgrades.txt sh -c 'cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null'

# 5. Ubuntu Pro 用戶端（未註冊也能執行；舊版用戶端可能沒有 api 子指令）
PRO=""; have pro && PRO=pro; [ -z "$PRO" ] && have ua && PRO=ua
if [ -n "$PRO" ]; then
  run pro-version.txt $PRO version
  if have python3; then
    run pro-status.json sh -c "$T $PRO status --format json 2>/dev/null | python3 -c '$PRO_FILTER'"
  fi
  run pro-api-updates.json $T $PRO api u.pro.packages.updates.v1
  run pro-api-summary.json $T $PRO api u.pro.packages.summary.v1
fi

# 6. 基本設定
if have sshd; then
  run sshd.txt sh -c 'out=$(sshd -T 2>&1); rc=$?; printf "%s\n" "$out" | grep -Ei "^(permitrootlogin|passwordauthentication|permitemptypasswords) "; exit $rc'
fi
# 只留第一行「Status: active／inactive」：防火牆規則常含來源 IP 或網段，不收
have ufw && run ufw.txt sh -c 'out=$(ufw status 2>&1); rc=$?; printf "%s\n" "$out" | head -n 1; exit $rc'
have ss && run listen.txt sh -c "ss -tuln | awk 'NR>1{n=split(\$5,a,\":\"); print \$1, a[n]}' | sort -u"
# 只記 UID 為 0 的帳號數量，不記帳號名稱
run uid0.txt sh -c "awk -F: '\$3==0{c++} END{print \"uid0_accounts=\" c+0}' /etc/passwd"
if [ -r /etc/shadow ]; then
  echo "empty_password_accounts=$(awk -F: '$2==""{c++} END{print c+0}' /etc/shadow)" > "${D}/shadow-summary.txt"
fi

# 打包
if tar -czf "./${OUTNAME}.tar.gz" -C "$WORK" "$OUTNAME"; then
  echo "完成：$(pwd)/${OUTNAME}.tar.gz"
  echo "檔案內含套件清單與設定摘要，請依機關資料分級規定保管。"
else
  echo "打包失敗，請確認目前目錄可以寫入。"; exit 1
fi
