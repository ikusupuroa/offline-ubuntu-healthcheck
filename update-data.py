#!/usr/bin/env python3
"""offline-ubuntu-healthcheck｜官方資料更新（update-data.py）

版本：0.4
在「能上網」的電腦執行（Python 3.6 以上，只用標準函式庫）。從 Canonical 官方網站下載
套件清單版的 OVAL 弱點資料，並留下來源紀錄，方便帶進離線環境後核對。

用法：
  python3 update-data.py                     # 下載所有 LTS 版本到 data/（已是最新就跳過）
  python3 update-data.py --releases 20.04,22.04     # 用版本號或代號（focal,jammy）都可以
  python3 update-data.py --verify            # 核對 data/ 內檔案與下載紀錄是否一致（離線環境也能跑）
  python3 update-data.py --list              # 列出目前資料的日期

產出（data/ 資料夾）：
  oci.com.ubuntu.<代號>.usn.oval.xml.bz2   官方原始檔，未經修改
  SOURCES.json                              每個檔案的下載網址、官方更新時間、下載時間、SHA-256
  SHA256SUMS                                可用 `sha256sum -c SHA256SUMS` 核對

資料來源：https://security-metadata.canonical.com/oval/
說明文件：https://documentation.ubuntu.com/security/security-updates/oval/
需要經過 Proxy 時，設定環境變數 https_proxy 即可。
"""
import argparse
import bz2
import datetime

import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request

VERSION = "0.4"
BASE = "https://security-metadata.canonical.com/oval/"
# LTS 版本代號與版本號（使用者多半記版本號，畫面上兩個一起顯示）
LTS_VERSIONS = {"trusty": "14.04", "xenial": "16.04", "bionic": "18.04", "focal": "20.04",
                "jammy": "22.04", "noble": "24.04", "resolute": "26.04"}
LTS = list(LTS_VERSIONS)


def label(code):
    v = LTS_VERSIONS.get(code)
    return "%s（%s）" % (code, v) if v else code


def label_of_file(name):
    m = re.match(r"oci\.com\.ubuntu\.([a-z]+)\.", name)
    return label(m.group(1)) if m else name
HERE = os.path.dirname(os.path.abspath(__file__))


def fname(code):
    return "oci.com.ubuntu.%s.usn.oval.xml.bz2" % code


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_sources(dest):
    p = os.path.join(dest, "SOURCES.json")
    if os.path.isfile(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except ValueError:
            pass
    return {"source": BASE, "files": {}}


def save_sources(dest, src):
    p = os.path.join(dest, "SOURCES.json")
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        json.dump(src, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(p + ".tmp", p)
    with open(os.path.join(dest, "SHA256SUMS"), "w", encoding="utf-8") as f:
        for n, r in sorted(src["files"].items()):
            f.write("%s  %s\n" % (r["sha256"], n))


def check_content(path):
    """確認是可解壓、套件清單版的官方 OVAL；回傳官方產生時間。"""
    head = b""
    d = bz2.BZ2Decompressor()
    with open(path, "rb") as f:
        while len(head) < 4000:
            chunk = f.read(65536)
            if not chunk:
                break
            head += d.decompress(chunk)
    text = head.decode("utf-8", "replace")
    if "<oval_definitions" not in text:
        raise ValueError("內容不是 OVAL 資料")
    m = re.search(r"<oval:timestamp>([^<]+)</oval:timestamp>", text)
    # 完整解壓一次，確保檔案沒有截斷，並確認是套件清單版
    with bz2.open(path, "rb") as f:
        tail_ok = False
        manifest = False
        prev = b""
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            buf = prev + chunk  # 保留上一段的結尾，避免標記剛好被切開
            if b"<ind-def:filename>manifest</ind-def:filename>" in buf:
                manifest = True
            if b"</oval_definitions>" in buf:
                tail_ok = True
            prev = chunk[-64:]
    if not tail_ok:
        raise ValueError("檔案不完整")
    if not manifest:
        raise ValueError("不是套件清單版（oci.）的 OVAL")
    return m.group(1) if m else ""


def download(code, dest, src, timeout, quiet):
    name = fname(code)
    url = BASE + name
    rec = src["files"].get(name, {})
    target = os.path.join(dest, name)
    req = urllib.request.Request(url, headers={"User-Agent": "offline-ubuntu-healthcheck/%s" % VERSION})
    if rec.get("last_modified") and os.path.isfile(target) and sha256(target) == rec.get("sha256"):
        req.add_header("If-Modified-Since", rec["last_modified"])
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        if e.code == 304:
            if not quiet:
                print("  %s 已是最新（官方更新時間 %s）" % (label(code), rec.get("last_modified")))
            return True
        print("  %s 下載失敗：HTTP %d" % (label(code), e.code), file=sys.stderr)
        return False
    except (urllib.error.URLError, OSError) as e:
        print("  %s 下載失敗：%s" % (label(code), e), file=sys.stderr)
        return False
    fd, tmp = tempfile.mkstemp(prefix=".dl-", dir=dest)
    try:
        with os.fdopen(fd, "wb") as f:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        stamp = check_content(tmp)
        os.chmod(tmp, 0o644)  # mkstemp 預設 0600；改成其他帳號也能讀，方便放在共用分析主機
        os.replace(tmp, target)
    except Exception as e:
        os.path.exists(tmp) and os.remove(tmp)
        print("  %s 內容檢查失敗，保留舊檔：%s" % (label(code), e), file=sys.stderr)
        return False
    src["files"][name] = {
        "url": url,
        "last_modified": resp.headers.get("Last-Modified", ""),
        "downloaded_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator_timestamp": stamp,
        "size": os.path.getsize(target),
        "sha256": sha256(target),
    }
    if not quiet:
        print("  %s 已下載（官方產生時間 %s）" % (label(code), stamp))
    return True


def verify(dest):
    src = load_sources(dest)
    if not src["files"]:
        print("找不到下載紀錄（%s/SOURCES.json）" % dest, file=sys.stderr)
        return 1
    bad = 0
    for name, r in sorted(src["files"].items()):
        p = os.path.join(dest, name)
        if not os.path.isfile(p):
            print("  缺檔    %s　%s" % (label_of_file(name), name))
            bad += 1
        elif sha256(p) != r.get("sha256"):
            print("  不一致  %s　%s（檔案在下載後被改過或損毀，請重新下載）" % (label_of_file(name), name))
            bad += 1
        else:
            print("  一致    %s　官方產生時間 %s" % (label_of_file(name), r.get("generator_timestamp", "?")))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description="下載或核對 Canonical 官方 OVAL 弱點資料")
    ap.add_argument("--dest", default=os.path.join(HERE, "data"), help="存放資料的資料夾（預設：程式旁的 data/）")
    ap.add_argument("--releases", default=",".join(LTS), help="版本號或代號，以逗號分隔，例如 20.04,22.04（預設：全部 LTS）")
    ap.add_argument("--verify", action="store_true", help="只核對，不下載")
    ap.add_argument("--list", action="store_true", help="列出目前資料的日期")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--quiet", action="store_true", help="只輸出錯誤（排程用）")
    args = ap.parse_args()

    os.makedirs(args.dest, exist_ok=True)
    if args.verify:
        return verify(args.dest)
    if args.list:
        for n, r in sorted(load_sources(args.dest)["files"].items()):
            print("%s　官方產生 %s　下載 %s" % (label_of_file(n), r.get("generator_timestamp", "?"), r.get("downloaded_at", "?")))
        return 0
    by_ver = {v: c for c, v in LTS_VERSIONS.items()}
    codes = [by_ver.get(c.strip(), c.strip()) for c in args.releases.split(",") if c.strip()]
    bad = [c for c in codes if not re.match(r"^[a-z]+$", c)]
    if bad:
        ap.error("看不懂的版本：%s（請用 20.04 這類版本號或 focal 這類代號）" % ", ".join(bad))
    src = load_sources(args.dest)
    if not args.quiet:
        print("來源：%s" % BASE)
    fail = 0
    for c in codes:
        if not download(c, args.dest, src, args.timeout, args.quiet):
            fail += 1
        save_sources(args.dest, src)
    if not args.quiet:
        print("完成。資料夾：%s（帶進離線環境後，執行 --verify 核對）" % args.dest)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
