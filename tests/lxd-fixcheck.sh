#!/bin/bash
# offline-ubuntu-healthcheck｜「只修這一則」指令的 LXD 驗證（tests/lxd-fixcheck.sh）
# 版本：0.6
#
# 驗證 v0.6 報告「重大與高風險公告」附的兩行指令：
#   sudo pro fix USN-…                                   （主機要能連到 Canonical）
#   sudo apt update && sudo apt install --only-upgrade …  （只升級這則公告點名的套件）
#
# 每個版本建一台測試機，做這些事：
#   1. 把 openssl 降回發行時的版本，製造一則確定存在的安全公告缺口
#   2. 在測試機裡跑 ./hc local，取出報告列的重大與高風險公告（不含核心）與指令
#   3. 記錄 pro 用戶端版本、pro fix 有沒有 --dry-run、changelog 裡第一次提到 USN 的版本
#   4. 每則公告：apt 模擬執行 --only-upgrade，記下實際會升級哪些套件、有沒有多帶相依套件
#   5. 每則公告：pro fix --dry-run 連網跑一次、斷網跑一次
#   6. 第一則公告真的用 apt --only-upgrade 升級，再用 pro fix --dry-run 確認已修好
#
# 用法：
#   tests/lxd-fixcheck.sh                    # 預設測 20.04 22.04 24.04（用容器，不需要虛擬機）
#   tests/lxd-fixcheck.sh 24.04              # 指定版本
#   tests/lxd-fixcheck.sh --cleanup          # 刪除本腳本建立的測試機（名稱開頭 hc-f-）
#
# 結果放在 test-results/fixcheck-<日期時間>/，RESULTS.md 可以直接貼回來。
# 需要：lxc、python3，以及分析電腦能上網（下載官方資料、測試機要 apt）。
# 不在測試範圍：Landscape 離線（air-gapped）環境；那需要另外架設 Landscape，本腳本只用「斷網」模擬連不到 Canonical。

set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"
PREFIX="hc-f-"
VERSIONS=()
for a in "$@"; do
  case "$a" in
    --cleanup)
      names=$(lxc list -c n --format csv 2>/dev/null | grep "^${PREFIX}" || true)
      if [ -z "$names" ]; then echo "沒有要刪除的測試機。"; exit 0; fi
      for n in $names; do lxc delete --force "$n" && echo "已刪除 $n"; done
      exit 0 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    [0-9][0-9].[0-9][0-9]) VERSIONS+=("$a") ;;
    *) echo "不認得的參數：$a"; exit 2 ;;
  esac
done
[ ${#VERSIONS[@]} -eq 0 ] && VERSIONS=(20.04 22.04 24.04)
command -v lxc >/dev/null || { echo "找不到 lxc。請先安裝：sudo snap install lxd && sudo lxd init --minimal"; exit 1; }
command -v python3 >/dev/null || { echo "找不到 python3"; exit 1; }

OUT="$ROOT/test-results/fixcheck-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/data" "$OUT/logs"
log() { echo "[$(date +%H:%M:%S)] $*"; }

log "下載官方資料"
python3 update-data.py --dest "$OUT/data" --releases "$(IFS=,; echo "${VERSIONS[*]}")" > "$OUT/logs/update.log" 2>&1 \
  || { echo "官方資料下載失敗，見 $OUT/logs/update.log"; exit 1; }

for V in "${VERSIONS[@]}"; do
  VM="${PREFIX}${V/./}"
  L="$OUT/logs/$V"
  mkdir -p "$L"
  log "[$V] 建立測試機 $VM"
  if ! lxc info "$VM" >/dev/null 2>&1; then
    lxc launch "ubuntu:$V" "$VM" > "$L/launch.log" 2>&1 || { log "[$V] 建不了測試機，見 $L/launch.log"; continue; }
  fi
  lxc start "$VM" >/dev/null 2>&1 || true
  for i in $(seq 1 60); do lxc exec "$VM" -- true >/dev/null 2>&1 && break; sleep 3; done
  lxc exec "$VM" -- cloud-init status --wait >/dev/null 2>&1 || true

  log "[$V] apt update，並把 openssl 降回發行版本"
  lxc exec "$VM" -- sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq' > "$L/apt-update.log" 2>&1
  # 發行版本：apt-cache madison 列出的最後一個版本（release pocket）
  lxc exec "$VM" -- sh -c '
    export DEBIAN_FRONTEND=noninteractive
    rel=$(apt-cache madison openssl | awk -F"|" "{gsub(/ /,\"\",\$2); v=\$2} END{print v}")
    pk=$(dpkg-query -W -f "\${Package} \${Source}\n" | awk "\$2==\"openssl\" || (\$2==\"\" && \$1==\"openssl\") {print \$1}" | grep -v -e "-dev$" )
    args=""; for p in $pk; do apt-cache madison "$p" | grep -q " $rel " && args="$args $p=$rel"; done
    echo "發行版本：$rel；降版：$args"
    apt-get install -y -qq --allow-downgrades $args' > "$L/downgrade.log" 2>&1
  lxc exec "$VM" -- sh -c 'dpkg-query -W -f "\${Package}\t\${Version}\t\${Source}\n"' > "$L/dpkg-before.txt" 2>&1

  log "[$V] 在測試機裡跑 hc local"
  lxc exec "$VM" -- rm -rf /root/hc
  lxc exec "$VM" -- mkdir -p /root/hc/data
  tar -czf - -C "$ROOT" hc analyze.py collect.sh update-data.py rules | lxc exec "$VM" -- tar -xzf - -C /root/hc
  tar -czf - -C "$OUT/data" . | lxc exec "$VM" -- tar -xzf - -C /root/hc/data
  lxc exec "$VM" -- sh -c 'cd /root/hc && python3 hc local --update no --out /root/out' > "$L/hc-local.log" 2>&1
  lxc exec "$VM" -- cat /root/out/findings.json > "$L/findings.json" 2>/dev/null

  log "[$V] pro 用戶端資訊"
  {
    echo "== pro version"; lxc exec "$VM" -- pro version 2>&1
    echo "== pro fix --help（有沒有 --dry-run）"; lxc exec "$VM" -- pro fix --help 2>&1 | grep -i -e "dry" -e "usage" -e "USN"
    echo "== changelog 裡提到 USN 的最早幾筆"
    lxc exec "$VM" -- sh -c 'for f in /usr/share/doc/ubuntu-pro-client/changelog.Debian.gz /usr/share/doc/ubuntu-advantage-tools/changelog.Debian.gz; do [ -f "$f" ] && zcat "$f"; done' 2>/dev/null \
      | awk '/^ubuntu-(advantage-tools|pro-client) \(/{ver=$2} /USN/{print ver": "$0}' | tail -n 5
  } > "$L/pro-info.txt" 2>&1

  # 每則非核心的重大／高風險公告（最多 3 則）
  python3 - "$L/findings.json" > "$L/fixes.tsv" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    sys.exit(0)
n = 0
for h in d.get("hosts", []):
    for f in h.get("crit_high_fixes", []):
        if f.get("kernel") or not f.get("binaries") or not f["usn"].startswith("USN-"):
            continue
        print("%s\t%s\t%s" % (f["usn"], " ".join(f["binaries"]), "需訂閱" if f["needs_pro"] and not f["subscribed"] else "免費"))
        n += 1
        if n >= 3:
            sys.exit(0)
PY
  if [ ! -s "$L/fixes.tsv" ]; then log "[$V] 報告沒有可測的非核心重大／高風險公告，見 $L/hc-local.log"; continue; fi

  nic=$(lxc exec "$VM" -- sh -c "ip -o route show default | awk '{print \$5; exit}'" 2>/dev/null)
  first=1
  # 從第 3 號檔案描述子讀清單：迴圈裡的 lxc exec 會讀標準輸入，不分開會把清單吃掉
  while IFS=$'\t' read -r -u 3 usn bins kind; do
    log "[$V] $usn（$bins，$kind）"
    F="$L/$usn"
    lxc exec "$VM" -- sh -c "apt-get -s install --only-upgrade $bins" > "$F-apt-sim.txt" 2>&1
    lxc exec "$VM" -- sh -c "pro fix $usn --dry-run" > "$F-profix-online.txt" 2>&1; echo "__EXIT__=$?" >> "$F-profix-online.txt"
    if [ -n "$nic" ]; then
      lxc exec "$VM" -- ip link set "$nic" down
      lxc exec "$VM" -- sh -c "timeout 300 pro fix $usn --dry-run" > "$F-profix-offline.txt" 2>&1; echo "__EXIT__=$?" >> "$F-profix-offline.txt"
      lxc exec "$VM" -- ip link set "$nic" up; sleep 5
    fi
    if [ $first = 1 ] && [ "$kind" = 免費 ]; then
      lxc exec "$VM" -- sh -c "export DEBIAN_FRONTEND=noninteractive; apt-get install -y --only-upgrade $bins" > "$F-apt-real.txt" 2>&1
      lxc exec "$VM" -- sh -c "pro fix $usn --dry-run" > "$F-profix-after.txt" 2>&1; echo "__EXIT__=$?" >> "$F-profix-after.txt"
      first=0
    fi
  done 3< "$L/fixes.tsv"
done

# 整理結果
python3 - "$OUT" "${VERSIONS[@]}" > "$OUT/RESULTS.md" <<'PY'
import os, re, sys
out, vers = sys.argv[1], sys.argv[2:]
def rd(p):
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""
def ex(t):
    m = re.search(r"__EXIT__=(\d+)", t)
    return m.group(1) if m else "-"
def brief(t, n=160):
    t = re.sub(r"__EXIT__=\d+", "", t).strip().replace("\n", " ／ ").replace("|", "／")
    return t[-n:] if t else "（沒有輸出）"
print("# lxd-fixcheck 結果\n")
for v in vers:
    L = os.path.join(out, "logs", v)
    print("## %s\n" % v)
    info = rd(os.path.join(L, "pro-info.txt"))
    print("```\n%s\n```\n" % info.strip())
    print("降版：%s\n" % brief(rd(os.path.join(L, "downgrade.log")), 300))
    fx = [l.split("\t") for l in rd(os.path.join(L, "fixes.tsv")).splitlines() if l.strip()]
    if not fx:
        print("沒有可測的公告（見 logs/%s/hc-local.log）\n" % v)
        continue
    print("| 公告 | 報告列的套件 | apt 模擬實際升級 | 多出的套件 | pro fix 連網（結束碼／結尾） | pro fix 斷網（結束碼／結尾） | 真的升級後 pro fix |")
    print("|---|---|---|---|---|---|---|")
    for usn, bins, kind in fx:
        F = os.path.join(L, usn)
        sim = rd(F + "-apt-sim.txt")
        inst = sorted(set(re.findall(r"^Inst (\S+)", sim, re.M)))
        extra = sorted(set(inst) - set(bins.split()))
        on, off, after = rd(F + "-profix-online.txt"), rd(F + "-profix-offline.txt"), rd(F + "-profix-after.txt")
        print("| %s（%s） | %s | %s | %s | %s：%s | %s：%s | %s |" % (
            usn, kind, bins, " ".join(inst) or "（無）", " ".join(extra) or "無",
            ex(on), brief(on), ex(off), brief(off), (ex(after) + "：" + brief(after)) if after else "未測"))
    print()
PY
log "完成：$OUT/RESULTS.md"
echo "測試機保留著，可以進去看：lxc exec ${PREFIX}2404 -- bash；不用了就執行 tests/lxd-fixcheck.sh --cleanup"
