# 自訂判讀規則

分類、嚴重度、建議文字、維護時程、門檻值，都寫在 [rules/default-rules.json](../rules/default-rules.json)，程式本身不寫死。

## 做法

不要直接改 `default-rules.json`，否則更新工具時會被蓋掉。請另外建一個檔案，**只寫要改的欄位**：

```json
{
  "thresholds": {"uptime_days_warn": 180, "data_max_age_days": 3},
  "findings": {
    "ssh_password_auth": {"enabled": false},
    "ufw_inactive": {"severity": "高", "action": "依本單位資安規範啟用主機防火牆，並記錄例外"}
  }
}
```

執行時加上 `--rules`：

```bash
python3 analyze.py hc-*.tar.gz --rules my-rules.json
```

程式會把自訂檔覆蓋在預設值上：物件逐層合併，清單整個取代。報告表頭會註明有使用自訂規則。

## 可以調整的內容

| 欄位 | 用途 |
|---|---|
| `lifecycle` | 各版本的標準維護、ESM、Legacy 結束月份。官方時程有異動時在這裡更新 |
| `categories` | A 到 D 四類的名稱，以及「Ubuntu Pro 能否解決」的寫法 |
| `thresholds.uptime_days_warn` | 連續運作幾天以上要提醒（預設 90） |
| `thresholds.data_max_age_days` | 官方資料超過幾天要警告（預設 7） |
| `thresholds.detail_rows_per_host` | 附錄每台主機列幾則公告（預設 30） |
| `usg_versions` | 哪些版本要提出 C 類「未使用 USG」建議 |
| `severity_names` | 官方嚴重度的中文名稱 |
| `findings.<代號>` | 每一種發現的開關、類別、嚴重度、標題、說明、建議 |
| `report_text` | 報告標題、年限說明、建議處理順序、限制說明 |

## 發現代號一覽

| 代號 | 預設類別 | 什麼時候出現 |
|---|---|---|
| `os_esm_period` | A | 已過標準維護期，且沒有啟用 esm-infra |
| `os_legacy_period` | A | 已過 ESM 期限，在 Legacy 期間 |
| `os_no_support` | D | 所有維護都結束，或非 LTS 版本 |
| `oval_needs_pro` | A | 官方 OVAL：修補來自延伸維護，主機沒有啟用 |
| `oval_pro_not_applied` | D | 官方 OVAL：已訂閱也已啟用，但還沒套用 |
| `oval_free_not_applied` | D | 官方 OVAL：免費修補沒有套用 |
| `pro_client_pending` | A | 沒有官方 OVAL 時，改用 Pro 用戶端的待取得清單 |
| `pro_client_not_applied` | D | 同上，已訂閱但未套用 |
| `pro_client_free_not_applied` | D | 同上，免費更新未套用 |
| `kernel_not_running_newest` | B | 已安裝新核心但還在跑舊核心 |
| `reboot_required` | B | 系統標示需要重開機 |
| `long_uptime` | B | 連續運作超過門檻天數，且沒有 Livepatch |
| `usg_not_used` | C | 支援 USG 的版本沒有安裝 USG |
| `ssh_root_login`、`ssh_empty_passwords`、`ssh_password_auth` | D | SSH 設定（需要 sudo 收集） |
| `ufw_inactive` | D | 防火牆未啟用（需要 sudo 收集） |
| `extra_uid0` | D | root 以外還有 UID 0 的帳號 |
| `empty_password_accounts` | D | 有空密碼帳號（需要 sudo 收集） |
| `no_auto_updates` | D | 沒有啟用自動安全更新 |
| `third_party_packages` | D | 有非官方來源的套件 |

## 文字裡的變數

標題和說明可以用大括號帶入數字，例如 `{usns}`：

| 發現 | 可用變數 |
|---|---|
| `oval_*` | `{usns}` 公告則數、`{cves}` CVE 數、`{crit_high}` 重大與高風險公告數、`{pockets}` 修補來源（只有 `oval_needs_pro`） |
| `pro_client_pending` | `{n}`、`{infra}`、`{apps}` |
| `kernel_not_running_newest` | `{running}`、`{newest}` |
| `long_uptime` | `{days}` |
| `extra_uid0`、`empty_password_accounts`、`third_party_packages`、`pro_client_*` | `{n}` |

`oval_*` 的嚴重度預設為 `auto`：有重大或高風險公告時為「高」，否則為「中」。要固定嚴重度，直接填「高」「中」「低」即可。

## 更進一步

規則檔處理的是「分類與文字」。要依單位的資安政策產出更完整的建議，可以把 `findings.json` 交給 AI，搭配 [ai-skill/SKILL.md](../ai-skill/SKILL.md) 的指引，再加上自己單位的規範一起分析。
