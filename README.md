# offline-ubuntu-healthcheck

離線環境也能用的 Ubuntu 主機資安健檢工具。

它會告訴你三件事：主機的版本還有沒有官方維護、缺了哪些安全修補，以及哪些缺口訂閱 Ubuntu Pro 就能補上。比對用的是 **Canonical 官方的 OVAL 弱點資料**，受檢主機上不必安裝任何東西。

[English README](README.en.md)

> 本專案不是 Canonical 的官方工具，與 Canonical 沒有隸屬關係，也沒有經過 Canonical 背書。Ubuntu 是 Canonical Ltd. 的商標。

---

## 一個指令就好

先下載工具（需要 Python 3.6 以上，不必另外安裝套件）：

```bash
git clone https://github.com/ikusupuroa/offline-ubuntu-healthcheck.git
cd offline-ubuntu-healthcheck
./hc update
```

`./hc update` 會從 Canonical 官方網站下載弱點資料，只有這一步需要網路。

接著依你的情況選一種：

| 情況 | 指令 |
|---|---|
| 這台電腦可以 SSH 到要檢查的主機 | `./hc scan hosts.txt` |
| 只能請主機管理者自己跑，再把結果交給你 | 主機上：`bash collect.sh --tag H01`<br>你的電腦：`./hc report hc-H01-*.tar.gz` |
| 只想檢查這台電腦自己 | `./hc local` |

跑完之後，畫面會列出每台主機的摘要，以及報告放在哪裡。用瀏覽器打開 `report.html` 就能看。

### hosts.txt 怎麼寫

每行一台主機，寫「代號」和「SSH 登入目標」：

```
# 代號   SSH 目標            其他 ssh 參數（可省略）
H01      admin@10.0.0.5
H02      ops@db.internal     -p 2222
```

報告上只會出現代號，不會出現 IP 或主機名稱。這份清單請留在自己的單位。

收集時，腳本會透過 SSH 直接送進主機執行，結果直接傳回你的電腦，**主機上不會留下任何檔案**。

### 要不要用 sudo

預設不用。一般使用者就能檢查版本、套件、核心和 Ubuntu Pro 狀態。

加上 `--sudo` 的話，會多檢查三項：SSH 設定、防火牆、空密碼帳號。`./hc scan --sudo` 需要主機上的帳號可以免密碼 sudo，不行時會自動改用一般權限。沒檢查到的項目會在報告上列為「未能檢查」，不會被當成沒問題。

---

## 報告怎麼看

| 類別 | 意思 | 訂閱 Ubuntu Pro 能不能解決 |
|---|---|---|
| A | 修補拿不到：官方資料標示修補只放在延伸維護（esm-infra、esm-apps） | 能 |
| B | 修補要重開機才生效：裝了新核心卻沒重開機、很久沒重開機 | 部分（Livepatch 只處理高風險核心漏洞） |
| C | 沒有用 CIS／DISA-STIG 的自動稽核工具 | 部分（USG 仍要人去設定） |
| D | 跟 Ubuntu Pro 無關：免費修補沒裝、SSH 與帳號設定等 | 不能 |

「需不需要 Pro」直接看官方資料裡寫的修補來源，不從版本號推測。D 類也會完整列出。

每次分析會產出四個檔案：

| 檔案 | 用途 |
|---|---|
| `report.html` | 報告，用瀏覽器打開 |
| `report.md` | 同一份報告的文字版，方便修改後交付 |
| `findings.json` | 結構化結果，可以交給 AI 分析（見 [ai-skill/SKILL.md](ai-skill/SKILL.md)） |
| `oval-detail.json` | 每則安全公告的完整比對明細 |

想先看看長什麼樣子，可以用三台虛構主機試跑：

```bash
./hc report samples/demo-ap01 samples/demo-db01 samples/demo-web01
```

已經跑好的範例在 [samples/demo-report/](samples/demo-report/report.md)。

---

## 官方資料多新

開始收集前，工具會先檢查官方資料，有超過 7 天的就問你要不要先更新。分析前，畫面會列出這次用到的各版本資料是哪一天產生的。

- 更新全部：`./hc update`
- 只更新部分版本：`./hc update --releases 20.04,22.04`
- 改用自己保管的資料：在指令後面加上 `--data 資料夾路徑`
- 帶進離線環境後確認檔案沒被改過：`./hc update --verify`

離線環境的做法見 [docs/offline-data.md](docs/offline-data.md)。

## 支援的版本

Ubuntu 14.04、16.04、18.04、20.04、22.04、24.04、26.04 LTS。非 LTS 版本只會提示升級。

## 收集什麼、不收集什麼

**會收集**：作業系統版本、核心版本、已安裝的套件清單、開機時間、是否等待重開機、套件來源設定、自動更新設定、Ubuntu Pro 狀態（只留服務名稱與啟用狀態）、SSH 的三項設定、防火牆有沒有啟用、對外開放的埠號（只記協定與埠號）、UID 為 0 的帳號數、空密碼帳號數。

套件來源只保留 ubuntu.com 與 canonical.com 的網址，其他網址整段遮蔽，來源設定檔也不記檔名。

**不收集**：主機名稱、IP 位址、密碼、金鑰、使用者家目錄、防火牆規則、Pro 的帳號與合約資訊。

收集結果裡還是有套件清單與設定摘要，請依單位的資料分級規定保管。要交給雲端 AI 分析時，請加上 `--deidentify`，主機代號會改成 H01、H02。

## 比對是怎麼做的

工具用 Canonical 官方 OVAL 的「套件清單版」（檔名開頭是 `oci.`），只需要主機的套件清單就能比對，所以可以在另一台電腦離線進行。

比對引擎有兩個：

- **OpenSCAP（`oscap`）**：Canonical 文件示範的工具。分析電腦是 Ubuntu 的話建議裝：24.04 以後裝 `openscap-scanner`，22.04 以前裝 `libopenscap8`。
- **內建比對**：沒有 `oscap` 時自動使用，按照同一份官方資料的判斷條件計算，Windows、macOS 也能跑。

加上 `--engine both` 會兩個都跑，並列出差異。實測三台主機，兩邊結果完全一致。

細節見 [docs/how-it-works.md](docs/how-it-works.md)。

### 和 Canonical sec-cvescan 的關係

做法參考了 Canonical 的 [sec-cvescan](https://github.com/canonical/sec-cvescan)：在主機上產出套件清單，拿到別處離線比對。sec-cvescan 已經停止維護，弱點資料也不再更新，所以本工具改用 Canonical 持續更新的官方 OVAL 資料，並以 OpenSCAP 比對。本工具沒有使用 sec-cvescan 的程式碼。

## 其他文件

- [docs/offline-data.md](docs/offline-data.md)：離線環境怎麼更新官方資料
- [docs/custom-rules.md](docs/custom-rules.md)：調整分類、建議文字與門檻
- [docs/testing-lxd.md](docs/testing-lxd.md)：用 LXD 虛擬機一次測試多個版本
- [docs/how-it-works.md](docs/how-it-works.md)：比對原理與可信度

## 已知限制

- 只比對 Ubuntu 官方套件庫的套件，自行安裝的第三方軟體不在範圍內。
- 舊核心套件如果還留在系統上，也可能被列入；實際執行中的核心看 B 類。
- 核心公告常常一則就涵蓋上千個 CVE，所以報告中的 CVE 數只算核心以外的套件。
- 還沒在實機上確認的事：14.04 與 16.04 上的 Pro 用戶端是否支援 `pro api`、收集時 pro 指令會不會寫入記錄檔。

## 授權

程式碼採用 [Apache License 2.0](LICENSE)。

官方 OVAL 資料的著作權屬於 Canonical Ltd.，授權為 CC BY-SA 4.0。本專案不附帶原始資料檔，請用 `./hc update` 向官方下載。`samples/demo-report/` 裡的公告標題、CVE 編號與版本號，摘錄自 2026-11-13 產生的官方 OVAL。
