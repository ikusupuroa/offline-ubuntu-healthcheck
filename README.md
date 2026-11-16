# offline-ubuntu-healthcheck

給離線環境用的 Ubuntu 主機資安健檢工具。

受檢主機上只跑一支唯讀的收集腳本，不安裝任何東西，也不需要連網。收集到的檔案帶到另一台電腦，用 **Canonical 官方的 OVAL 弱點資料**比對，產出中文報告。報告會標出每個問題「訂閱 Ubuntu Pro 能不能解決」。

[English README](README.en.md)

> 本專案不是 Canonical 的官方工具，與 Canonical 沒有隸屬關係，也未經其背書。Ubuntu 是 Canonical Ltd. 的商標。

---

## 適合誰用

- 主機在隔離網段、不能連網，又需要知道「缺了哪些安全修補」的單位。
- 想知道舊版 Ubuntu 主機的維護狀態，以及哪些缺口靠 Ubuntu Pro 就能補上的人。
- 想把健檢結果交給自己的 AI 工具，產出資安建議的人（見 [ai-skill/](ai-skill/SKILL.md)）。

支援版本：Ubuntu 14.04、16.04、18.04、20.04、22.04、24.04、26.04 LTS。非 LTS 版本只會提示升級。

## 運作方式

```
[能上網的電腦] update-data.py：下載官方 OVAL，記錄雜湊值
        │
        │  data/ 資料夾（隨身碟或單位的匯入程序）
        ▼
[分析電腦（可離線）] analyze.py：官方 OVAL 比對 ＋ 判讀規則 → report.md、findings.json
        ▲
        │  hc-代號-時間.tar.gz
        │
[受檢主機（離線）] collect.sh：只讀取，不安裝、不連網
```

官方資料只帶進分析電腦，不必帶進受檢主機。

1. **更新官方資料**：在能上網的電腦執行 `update-data.py`，從 `security-metadata.canonical.com` 下載各版本的 OVAL 檔，並記錄官方更新時間與 SHA-256 雜湊值。
2. **收集**：在受檢主機執行 `collect.sh`，產出一個 tar.gz，裡面有套件清單、版本、核心與少數設定摘要。
3. **分析**：在分析電腦執行 `analyze.py`。程式把套件清單和官方 OVAL 比對，再依判讀規則分類，產出 `report.md` 和 `findings.json`。

比對引擎可以二選一：

- **OpenSCAP（`oscap`）**：Canonical 文件示範使用的開源工具。分析電腦是 Ubuntu 時建議安裝：24.04 以後裝 `openscap-scanner`，22.04 以前裝 `libopenscap8`。
- **內建比對**：沒有 `oscap` 時自動使用。依同一份官方 OVAL 的判斷條件實作，Windows、macOS 也能跑。

加上 `--engine both` 會兩個都跑並比較結果，可以用來驗證內建比對。

### 與 Canonical sec-cvescan 的關係

本工具參考 Canonical 的 [sec-cvescan](https://github.com/canonical/sec-cvescan)「在主機產出套件清單，帶到別處離線比對」的做法。sec-cvescan 已停止維護，它使用的弱點資料也已不再更新，所以本工具改用 Canonical 仍持續更新的官方 OVAL 資料（套件清單版），並以 OpenSCAP 比對。

本工具沒有使用 sec-cvescan 的程式碼。

## 快速開始

需要 Python 3.6 以上，只用標準函式庫，不必另外安裝套件。

```bash
git clone https://github.com/ikusupuroa/offline-ubuntu-healthcheck.git
cd offline-ubuntu-healthcheck
```

**1. 下載官方資料**（能上網的電腦）

```bash
python3 update-data.py
```

**2. 在受檢主機收集**（把 `collect.sh` 複製過去）

```bash
bash collect.sh --tag H01
```

**3. 分析**（把 `hc-H01-*.tar.gz` 帶回分析電腦）

```bash
python3 analyze.py hc-H01-*.tar.gz hc-H02-*.tar.gz --agency "受檢單位" --assessor "執行單位"
```

產出三個檔案，都在 `hc-report/`：

- `report.md`：報告
- `findings.json`：結構化摘要，可交給 AI 分析
- `oval-detail.json`：每則公告的完整比對明細

先用示範資料試跑（三台虛構主機）：

```bash
python3 update-data.py --releases xenial,focal,jammy
python3 analyze.py samples/demo-ap01 samples/demo-db01 samples/demo-web01 --out demo-report
```

已跑好的示範報告在 [samples/demo-report/report.md](samples/demo-report/report.md)。

## 權限：預設不需要 sudo

| 檢查項目 | 一般使用者 | 需要 sudo |
|---|---|---|
| 版本、核心、套件清單、待重開機、對外埠號 | ✓ | |
| Ubuntu Pro 狀態與更新清單 | ✓（以實機測試為準） | |
| SSH 設定（`sshd -T`） | | ✓ |
| 防火牆（`ufw status`） | | ✓ |
| 空密碼帳號（讀 `/etc/shadow` 只計數） | | ✓ |

不用 sudo 時，後三項會列在報告的「未能檢查」，不會被當成沒有問題。

## 報告怎麼分類

| 類別 | 說明 | Ubuntu Pro 能否解決 |
|---|---|---|
| A | 修補取不到：官方 OVAL 標示修補來自 esm-infra、esm-apps 等延伸維護 | 是 |
| B | 修補需要停機：已裝新核心但沒重開機、長期未重開機 | 部分（Livepatch 只處理高風險核心漏洞） |
| C | 合規與設定基準：未使用 CIS／DISA-STIG 稽核工具 | 部分（USG 要人力設定） |
| D | 與 Ubuntu Pro 無關：免費修補沒套用、SSH 與帳號設定等 | 否 |

「需不需要 Ubuntu Pro」不是靠版本號猜的，而是直接讀官方 OVAL 比對條件裡標示的修補來源（例如 `esm-infra/focal`）。

D 類同樣完整列出，讓受檢單位掌握所有風險。

## 進一步說明

- [docs/how-it-works.md](docs/how-it-works.md)：比對原理、資料來源、可信度怎麼確認
- [docs/offline-data.md](docs/offline-data.md)：離線環境怎麼更新官方資料（自動與手動）
- [docs/custom-rules.md](docs/custom-rules.md)：自訂判讀規則與建議文字
- [docs/testing-lxd.md](docs/testing-lxd.md)：用 LXD 虛擬機測試各版本
- [ai-skill/SKILL.md](ai-skill/SKILL.md)：把 `findings.json` 交給 AI 分析時用的指引

## 收集什麼、不收集什麼

**收集**：作業系統版本、核心版本、已安裝套件清單、開機時間、是否待重開機、套件來源設定（私有網址會遮蔽）、自動更新設定、Ubuntu Pro 狀態（只留服務名稱與啟用狀態）、SSH 三項設定、防火牆是否啟用（不收規則）、對外埠號（只記協定與埠號）、UID 為 0 的帳號數、空密碼帳號數。套件來源只保留 ubuntu.com 與 canonical.com 的網址，其他網址整段遮蔽，來源設定檔不記檔名。

**不收集**：主機名稱、IP 位址、密碼、金鑰、使用者家目錄、Pro 帳號與合約資訊。

收集檔仍含有套件清單與設定摘要，請依所屬單位的資料分級規定保管。交給雲端 AI 分析前，請用 `--deidentify` 產出去識別化的版本。

## 已知限制

- 只比對 Ubuntu 官方套件庫的套件，第三方軟體不在範圍內。
- 官方 OVAL 以「已安裝的套件版本」比對，舊核心套件若留在系統上也可能被列入；實際執行中的核心看 B 類。
- 以下項目尚待實機驗證：未註冊主機上的 `pro api` 輸出、14.04／16.04 的 Pro 用戶端是否支援 `pro api`、收集時 pro 指令是否寫入記錄檔或嘗試連網、內建比對與 OpenSCAP 的結果是否完全一致。

## 授權

程式碼以 [Apache License 2.0](LICENSE) 授權。

官方 OVAL 資料的著作權屬於 Canonical Ltd.。本專案不附帶原始資料檔，請用 `update-data.py` 直接向官方下載。`samples/demo-report/` 內的公告標題、CVE 編號與版本號，摘錄自 2026-11-13 產生的官方 OVAL。
