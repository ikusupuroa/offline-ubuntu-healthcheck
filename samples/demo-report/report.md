# Ubuntu 主機資安健檢報告

| 項目 | 內容 |
|---|---|
| 受檢單位 | 示範單位（虛構） |
| 執行單位 | 示範執行單位（虛構） |
| 判斷基準月份 | 2026-11 |
| 受檢主機數 | 3 |
| 分析程式版本 | offline-ubuntu-healthcheck 0.3 |
| 弱點比對資料 | Canonical 官方 OVAL（security-metadata.canonical.com） |
| 比對引擎 | 內建比對（依官方 OVAL 的同一套判斷條件實作） |

**官方資料檔明細**

| 版本代號 | 檔案 | 官方產生時間 | 距分析日 | SHA-256（前 16 碼） | 與下載紀錄 |
|---|---|---|---|---|---|
| focal | oci.com.ubuntu.focal.usn.oval.xml.bz2 | 2026-11-13T08:05:53 | 3 天 | 0c19f01aa12892fb | 一致 |
| jammy | oci.com.ubuntu.jammy.usn.oval.xml.bz2 | 2026-11-13T08:05:17 | 3 天 | f607d2519c354bad | 一致 |
| xenial | oci.com.ubuntu.xenial.usn.oval.xml.bz2 | 2026-11-13T08:06:56 | 3 天 | 6ec62355ee76851f | 一致 |

## 一、摘要

- 共 3 台主機，其中 **2 台已過標準維護期**。
- 發現事項共 23 項，依「Ubuntu Pro 能否解決」分成四類：

| 類別 | 說明 | 項數 | 占比 | Ubuntu Pro 能否解決 |
|---|---|---|---|---|
| A | 修補取不到（訂閱 Ubuntu Pro 可解決） | 5 | 22% | 是 |
| B | 修補需要停機（Ubuntu Pro 的 Livepatch 可降低） | 4 | 17% | 部分 |
| C | 合規與設定基準（Ubuntu Pro 提供工具，仍需人力） | 2 | 9% | 部分 |
| D | 與 Ubuntu Pro 無關（自行處理、升級或其他服務） | 12 | 52% | 否 |

> D 類與 Ubuntu Pro 無關，本報告同樣列出，讓受檢單位掌握完整風險。

## 二、主機總覽

| 主機 | 版本 | 維護狀態 | 執行中核心 | 未重開機天數 | 需 Pro 才能取得的修補 | 未套用的免費修補 | 資料來源 |
|---|---|---|---|---|---|---|---|
| demo-ap01 | Ubuntu 20.04.6 LTS | 需 Pro（ESM） | 5.4.0-150-generic | 200 | 49 則安全公告 | 74 則安全公告 | 官方 OVAL |
| demo-db01 | Ubuntu 16.04.7 LTS | 需 Pro＋Legacy | 4.4.0-210-generic | 480 | 85 則安全公告 | 14 則安全公告 | 官方 OVAL |
| demo-web01 | Ubuntu 22.04.5 LTS | 標準維護期內 | 5.15.0-125-generic | 30 | 2 則安全公告 | 76 則安全公告 | 官方 OVAL |

維護年限說明：LTS 版本標準維護 5 年；訂閱 Ubuntu Pro（ESM）共 10 年；加購 Legacy 最長 15 年。

## 三、發現事項（依主機）

### demo-ap01（Ubuntu 20.04.6 LTS）

維護狀態：標準維護已於 2025-05 結束；訂閱 Ubuntu Pro（ESM）才有安全更新，到 2030-05

| 類別 | 嚴重度 | 發現 | 說明 | 建議 | Pro 能否解決 |
|---|---|---|---|---|---|
| A | 高 | 作業系統已過標準維護期 | 標準維護已於 2025-05 結束；訂閱 Ubuntu Pro（ESM）才有安全更新，到 2030-05 | 訂閱 Ubuntu Pro 並啟用 esm-infra，即可繼續取得安全更新；同時規劃升級時程 | 是 |
| A | 高 | 官方弱點資料：49 則安全公告的修補要訂閱 Ubuntu Pro 才拿得到 | 涉及 CVE 307 個（重大與高風險公告 24 則）；來源：esm-apps 18 則、esm-infra 31 則。主機上的 Ubuntu Pro 用戶端另外回報 5 個套件待取得，可互相對照 | 訂閱 Ubuntu Pro 並註冊主機後，用 apt 套用更新 | 是 |
| B | 高 | 已安裝新核心，但機器還在跑舊核心 | 執行中：5.4.0-150-generic；已安裝最新：5.4.0-169-generic。核心修補要重開機才生效 | 排定重開機；若停機困難，Ubuntu Pro 的 Livepatch 可在不重開機下套用高風險核心修補 | 部分 |
| B | 中 | 已連續運作 200 天沒有重開機 | 長時間不重開機，核心修補很可能沒有生效 | 確認停機限制；Ubuntu Pro 的 Livepatch 只處理高風險與重大核心漏洞，不能取代所有重開機 | 部分 |
| C | 低 | 未使用 CIS／DISA-STIG 基準的自動化稽核工具 | 沒有安裝 Ubuntu Security Guide（USG） | 若需要設定基準的稽核證據，可評估 Ubuntu Pro 內含的 USG（CIS 與 DISA-STIG 設定檔）；與各單位適用的組態基準對應需另行比對 | 部分 |
| D | 高 | 官方弱點資料：74 則安全公告有免費修補，但尚未套用 | 涉及 CVE 1273 個（重大與高風險公告 43 則）。這些修補不需要 Ubuntu Pro，是例行修補沒有執行 | 排定修補時段套用；長期可導入集中管理工具 | 否 |
| D | 高 | SSH 允許 root 直接登入 | permitrootlogin yes | 改為 no 或 prohibit-password | 否 |
| D | 中 | SSH 允許密碼登入 | passwordauthentication yes | 評估改用金鑰登入 | 否 |
| D | 中 | 主機防火牆（ufw）未啟用 | ufw status: inactive | 確認是否由網路層防火牆保護；必要時啟用 | 否 |
| D | 中 | 有 3 個非 Ubuntu 官方來源的套件 | 第三方或來源不明的套件不在 Ubuntu Pro 的修補範圍 | 盤點來源，向原廠確認更新方式 | 否 |
| D | 低 | 未啟用自動安全更新 | unattended-upgrades 未設定為每日執行 | 依單位的變更管理規定決定是否啟用 | 否 |

### demo-db01（Ubuntu 16.04.7 LTS）

維護狀態：ESM 已於 2026-05 結束；需 Ubuntu Pro 加購 Legacy，最長到 2031-05

| 類別 | 嚴重度 | 發現 | 說明 | 建議 | Pro 能否解決 |
|---|---|---|---|---|---|
| A | 高 | 作業系統已過 ESM 期限 | ESM 已於 2026-05 結束；需 Ubuntu Pro 加購 Legacy，最長到 2031-05 | 需要 Ubuntu Pro 加上 Legacy 加購；建議同步規劃升級，Legacy 適合當作遷移期的過渡 | 是 |
| A | 高 | 官方弱點資料：85 則安全公告的修補要訂閱 Ubuntu Pro 才拿得到 | 涉及 CVE 772 個（重大與高風險公告 60 則）；來源：esm-infra 75 則、esm-infra-legacy 10 則。主機上的 Ubuntu Pro 用戶端另外回報 2 個套件待取得，可互相對照 | 訂閱 Ubuntu Pro 並註冊主機後，用 apt 套用更新 | 是 |
| B | 中 | 已連續運作 480 天沒有重開機 | 長時間不重開機，核心修補很可能沒有生效 | 確認停機限制；Ubuntu Pro 的 Livepatch 只處理高風險與重大核心漏洞，不能取代所有重開機 | 部分 |
| D | 高 | 官方弱點資料：14 則安全公告有免費修補，但尚未套用 | 涉及 CVE 35 個（重大與高風險公告 3 則）。這些修補不需要 Ubuntu Pro，是例行修補沒有執行 | 排定修補時段套用；長期可導入集中管理工具 | 否 |
| D | 中 | SSH 允許密碼登入 | passwordauthentication yes | 評估改用金鑰登入 | 否 |
| D | 低 | 未啟用自動安全更新 | unattended-upgrades 未設定為每日執行 | 依單位的變更管理規定決定是否啟用 | 否 |

### demo-web01（Ubuntu 22.04.5 LTS）

維護狀態：標準維護期內（到 2027-05）

> 以一般使用者收集（預設）：SSH 設定、防火牆、空密碼帳號需要 sudo 才能檢查，列在「未能檢查」。

| 類別 | 嚴重度 | 發現 | 說明 | 建議 | Pro 能否解決 |
|---|---|---|---|---|---|
| A | 中 | 官方弱點資料：2 則安全公告的修補要訂閱 Ubuntu Pro 才拿得到 | 涉及 CVE 8 個（重大與高風險公告 0 則）；來源：esm-apps 2 則。主機上的 Ubuntu Pro 用戶端另外回報 1 個套件待取得，可互相對照 | 訂閱 Ubuntu Pro 並註冊主機後，用 apt 套用更新 | 是 |
| B | 高 | 已安裝新核心，但機器還在跑舊核心 | 執行中：5.15.0-125-generic；已安裝最新：5.15.0-130-generic。核心修補要重開機才生效 | 排定重開機；若停機困難，Ubuntu Pro 的 Livepatch 可在不重開機下套用高風險核心修補 | 部分 |
| C | 低 | 未使用 CIS／DISA-STIG 基準的自動化稽核工具 | 沒有安裝 Ubuntu Security Guide（USG） | 若需要設定基準的稽核證據，可評估 Ubuntu Pro 內含的 USG（CIS 與 DISA-STIG 設定檔）；與各單位適用的組態基準對應需另行比對 | 部分 |
| D | 高 | 官方弱點資料：76 則安全公告有免費修補，但尚未套用 | 涉及 CVE 4675 個（重大與高風險公告 43 則）。這些修補不需要 Ubuntu Pro，是例行修補沒有執行 | 排定修補時段套用；長期可導入集中管理工具 | 否 |
| D | 中 | 有 12 個非 Ubuntu 官方來源的套件 | 第三方或來源不明的套件不在 Ubuntu Pro 的修補範圍 | 盤點來源，向原廠確認更新方式 | 否 |
| D | 低 | 未啟用自動安全更新 | unattended-upgrades 未設定為每日執行 | 依單位的變更管理規定決定是否啟用 | 否 |

未能檢查的項目（不計入上表）：SSH 設定（需要 sudo，或主機未安裝 SSH 服務）；主機防火牆（ufw）狀態（需要 sudo，或主機未安裝 ufw）；空密碼帳號（需要 sudo）

## 四、建議處理順序

1. 先處理各類「高」嚴重度項目，其中 D 類的帳號與登入設定通常當天就能改。
2. 已過標準維護期的主機（A 類）：短期以 Ubuntu Pro 恢復安全更新，同時排定升級計畫。
3. 核心修補無法排停機的主機（B 類）：評估 Livepatch，並保留定期重開機的維護窗口。
4. 需要稽核證據的單位（C 類）：評估 USG，並與適用的組態基準比對。

## 五、檢查範圍與限制

- 本健檢只讀取系統資訊，不做弱點利用測試、不修改設定，不等同滲透測試。
- 只涵蓋 Ubuntu 官方套件庫的套件；第三方軟體（例如自行安裝的應用程式）的弱點不在比對範圍。
- 官方弱點資料以「已安裝的套件版本」比對：舊核心套件若仍留在系統上，也可能被列入；實際執行中的核心請看 B 類。
- 標示「未能檢查」的項目，代表收集時權限不足或主機沒有對應工具，不代表沒有問題。
- 結果反映收集當下的狀態，以及報告上所列官方資料日期之前公布的弱點。

## 附錄：官方弱點資料比對明細

每台主機最多列 30 則，需要 Ubuntu Pro 的排前面，再依嚴重度排序；完整清單在 oval-detail.json。

### demo-ap01

| 安全公告 | 嚴重度 | CVE 數 | 修補來源 | 需要 Pro | 套件（已安裝 → 修補版本） |
|---|---|---|---|---|---|
| USN-7795-1 -- Linux kernel vulnerabilities | 重大 | 5 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-222.242 |
| USN-8615-1 -- Linux kernel vulnerabilities | 重大 | 23 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-233.253 |
| USN-8666-1 -- Linux kernel vulnerabilities | 重大 | 32 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-234.254 |
| USN-8851-1 -- Linux kernel vulnerabilities | 重大 | 3 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-241.261 |
| USN-8919-1 -- Linux kernel vulnerabilities | 重大 | 9 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-242.262 |
| USN-9030-1 -- Linux kernel vulnerabilities | 重大 | 6 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-245.265 |
| USN-7585-1 -- Linux kernel vulnerabilities | 高 | 31 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-218.238 |
| USN-7604-2 -- Sudo vulnerability | 高 | 1 | esm-infra | 是 | sudo 1.8.31-1ubuntu1 → 1.8.31-1ubuntu1.5+esm1 |
| USN-7671-1 -- Linux kernel vulnerabilities | 高 | 11 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-219.239 |
| USN-7701-1 -- Linux kernel vulnerabilities | 高 | 7 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-220.240 |
| USN-7754-1 -- Linux kernel vulnerabilities | 高 | 2 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-221.241 |
| USN-7874-1 -- Linux kernel vulnerabilities | 高 | 8 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-223.243 |
| USN-7922-1 -- Linux kernel vulnerabilities | 高 | 15 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-224.244 |
| USN-7990-1 -- Linux kernel vulnerabilities | 高 | 3 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-225.245 |
| USN-8098-1 -- Linux kernel vulnerabilities | 高 | 8 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-227.247 |
| USN-8200-1 -- Linux kernel vulnerabilities | 高 | 5 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-228.248 |
| USN-8273-1 -- Linux kernel vulnerabilities | 高 | 3 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-229.249 |
| USN-8280-1 -- Linux kernel vulnerabilities | 高 | 6 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-230.250 |
| USN-8375-1 -- nginx vulnerabilities | 高 | 12 | esm-infra | 是 | nginx 1.18.0-0ubuntu1 → 1.18.0-0ubuntu1.7+esm1 |
| USN-8389-1 -- Linux kernel vulnerabilities | 高 | 3 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-231.251 |
| USN-8414-2 -- OpenSSL vulnerabilities | 高 | 5 | esm-infra | 是 | openssl 1.1.1f-1ubuntu2 → 1.1.1f-1ubuntu2.24+esm4 |
| USN-8714-1 -- Linux kernel vulnerabilities | 高 | 5 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-238.258 |
| USN-8847-2 -- OpenSSL vulnerabilities | 高 | 4 | esm-infra | 是 | openssl 1.1.1f-1ubuntu2 → 1.1.1f-1ubuntu2.24+esm6 |
| USN-8964-1 -- Linux kernel vulnerabilities | 高 | 2 | esm-infra | 是 | linux 5.4.0-150.160/5.4.0-169.179 → 5.4.0-244.264 |
| USN-5736-2 -- ImageMagick vulnerabilities | 中 | 1 | esm-apps | 是 | imagemagick 8:6.9.10.23+dfsg-2.1ubuntu11 → 8:6.9.10.23+dfsg-2.1ubuntu11.4+esm1 |
| USN-6621-1 -- ImageMagick vulnerability | 中 | 1 | esm-apps | 是 | imagemagick 8:6.9.10.23+dfsg-2.1ubuntu11 → 8:6.9.10.23+dfsg-2.1ubuntu11.9+esm2 |
| USN-7728-1 -- ImageMagick vulnerabilities | 中 | 3 | esm-apps | 是 | imagemagick 8:6.9.10.23+dfsg-2.1ubuntu11 → 8:6.9.10.23+dfsg-2.1ubuntu11.11+esm2 |
| USN-7756-1 -- ImageMagick vulnerabilities | 中 | 3 | esm-apps | 是 | imagemagick 8:6.9.10.23+dfsg-2.1ubuntu11 → 8:6.9.10.23+dfsg-2.1ubuntu11.11+esm3 |
| USN-7786-1 -- OpenSSL vulnerabilities | 中 | 1 | esm-infra | 是 | openssl 1.1.1f-1ubuntu2 → 1.1.1f-1ubuntu2.24+esm1 |
| USN-7812-1 -- ImageMagick vulnerabilities | 中 | 2 | esm-apps | 是 | imagemagick 8:6.9.10.23+dfsg-2.1ubuntu11 → 8:6.9.10.23+dfsg-2.1ubuntu11.11+esm4 |

（另有 93 則未列出）

### demo-db01

| 安全公告 | 嚴重度 | CVE 數 | 修補來源 | 需要 Pro | 套件（已安裝 → 修補版本） |
|---|---|---|---|---|---|
| USN-7332-1 -- Linux kernel vulnerabilities | 重大 | 35 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-266.300 |
| USN-7797-1 -- Linux kernel vulnerabilities | 重大 | 10 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-273.307 |
| USN-8548-2 -- Linux kernel vulnerabilities | 重大 | 20 | esm-infra-legacy | 是 | linux 4.4.0-210.220 → 4.4.0-283.317 |
| USN-8662-1 -- Linux kernel vulnerabilities | 重大 | 16 | esm-infra-legacy | 是 | linux 4.4.0-210.220 → 4.4.0-284.318 |
| USN-8725-1 -- Linux kernel vulnerabilities | 重大 | 8 | esm-infra-legacy | 是 | linux 4.4.0-210.220 → 4.4.0-287.321 |
| USN-8864-1 -- Linux kernel vulnerabilities | 重大 | 3 | esm-infra-legacy | 是 | linux 4.4.0-210.220 → 4.4.0-288.322 |
| USN-5014-1 -- Linux kernel vulnerability | 高 | 1 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-212.244 |
| USN-5039-1 -- Linux kernel vulnerability | 高 | 1 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-213.245 |
| USN-5062-1 -- Linux kernel vulnerability | 高 | 1 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-214.246 |
| USN-5211-1 -- Linux kernel vulnerability | 高 | 1 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-218.251 |
| USN-5319-1 -- Linux kernel vulnerabilities | 高 | 2 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-221.254 |
| USN-5343-1 -- Linux kernel vulnerabilities | 高 | 30 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-222.255 |
| USN-5361-1 -- Linux kernel vulnerabilities | 高 | 13 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-223.256 |
| USN-5413-1 -- Linux kernel vulnerabilities | 高 | 6 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-224.257 |
| USN-5465-1 -- Linux kernel vulnerabilities | 高 | 2 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-227.261 |
| USN-5500-1 -- Linux kernel vulnerabilities | 高 | 8 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-229.263 |
| USN-5540-1 -- Linux kernel vulnerabilities | 高 | 4 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-230.264 |
| USN-5557-1 -- Linux kernel vulnerabilities | 高 | 2 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-231.265 |
| USN-5650-1 -- Linux kernel vulnerabilities | 高 | 14 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-234.268 |
| USN-5758-1 -- Linux kernel vulnerabilities | 高 | 13 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-235.269 |
| USN-5802-1 -- Linux kernel vulnerabilities | 高 | 4 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-236.270 |
| USN-5926-1 -- Linux kernel vulnerabilities | 高 | 6 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-237.271 |
| USN-6014-1 -- Linux kernel vulnerabilities | 高 | 50 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-239.273 |
| USN-6045-1 -- Linux kernel vulnerabilities | 高 | 5 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-240.274 |
| USN-6149-1 -- Linux kernel vulnerabilities | 高 | 6 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-241.275 |
| USN-6221-1 -- Linux kernel vulnerabilities | 高 | 7 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-242.276 |
| USN-6254-1 -- Linux kernel vulnerabilities | 高 | 12 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-243.277 |
| USN-6309-1 -- Linux kernel vulnerabilities | 高 | 6 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-244.278 |
| USN-6388-1 -- Linux kernel vulnerabilities | 高 | 9 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-245.279 |
| USN-6439-1 -- Linux kernel vulnerabilities | 高 | 11 | esm-infra | 是 | linux 4.4.0-210.220 → 4.4.0-246.280 |

（另有 69 則未列出）

### demo-web01

| 安全公告 | 嚴重度 | CVE 數 | 修補來源 | 需要 Pro | 套件（已安裝 → 修補版本） |
|---|---|---|---|---|---|
| USN-6531-1 -- Redis vulnerabilities | 中 | 6 | esm-apps | 是 | redis 5:6.0.16-1ubuntu1 → 5:6.0.16-1ubuntu1+esm1 |
| USN-7321-1 -- Redis vulnerabilities | 中 | 2 | esm-apps | 是 | redis 5:6.0.16-1ubuntu1 → 5:6.0.16-1ubuntu1+esm2 |
| USN-7166-1 -- Linux kernel vulnerabilities | 重大 | 167 | jammy | 否 | linux 5.15.0-125.135 → 5.15.0-127.137 |
| USN-7387-1 -- Linux kernel vulnerabilities | 重大 | 249 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-135.146 |
| USN-7510-1 -- Linux kernel vulnerabilities | 重大 | 124 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-140.150 |
| USN-7909-1 -- Linux kernel vulnerabilities | 重大 | 178 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-163.173 |
| USN-8096-1 -- Linux kernel vulnerabilities | 重大 | 214 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-173.183 |
| USN-8493-1 -- Linux kernel vulnerabilities | 重大 | 64 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-185.195 |
| USN-8575-1 -- Linux kernel vulnerabilities | 重大 | 756 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-186.196 |
| USN-8631-1 -- Linux kernel vulnerabilities | 重大 | 18 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-187.197 |
| USN-8818-4 -- Linux kernel vulnerabilities | 重大 | 20 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-194.204 |
| USN-8875-1 -- Linux kernel vulnerabilities | 重大 | 950 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-198.208 |
| USN-8961-1 -- Linux kernel vulnerabilities | 重大 | 1068 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-202.212 |
| USN-9027-1 -- Linux kernel vulnerabilities | 重大 | 5 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-203.213 |
| USN-6429-1 -- curl vulnerabilities | 高 | 2 | jammy | 否 | curl 7.81.0-1ubuntu1.10 → 7.81.0-1ubuntu1.14 |
| USN-7179-1 -- Linux kernel vulnerabilities | 高 | 14 | jammy | 否 | linux 5.15.0-125.135 → 5.15.0-130.140 |
| USN-7235-1 -- Linux kernel vulnerabilities | 高 | 3 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-131.141 |
| USN-7288-1 -- Linux kernel vulnerabilities | 高 | 104 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-133.144 |
| USN-7327-1 -- Linux kernel vulnerability | 高 | 1 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-134.145 |
| USN-7406-1 -- Linux kernel vulnerabilities | 高 | 4 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-136.147 |
| USN-7455-1 -- Linux kernel vulnerabilities | 高 | 12 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-138.148 |
| USN-7494-1 -- Linux kernel vulnerabilities | 高 | 1 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-139.149 |
| USN-7550-1 -- Linux kernel vulnerabilities | 高 | 3 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-141.151 |
| USN-7591-1 -- Linux kernel vulnerabilities | 高 | 65 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-142.152 |
| USN-7608-1 -- Linux kernel vulnerabilities | 高 | 9 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-143.153 |
| USN-7654-1 -- Linux kernel vulnerabilities | 高 | 139 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-144.157 |
| USN-7683-1 -- Linux kernel vulnerabilities | 高 | 2 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-151.161 |
| USN-7704-1 -- Linux kernel vulnerabilities | 高 | 21 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-152.162 |
| USN-7726-1 -- Linux kernel vulnerabilities | 高 | 3 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-153.163 |
| USN-7774-1 -- Linux kernel vulnerabilities | 高 | 142 | jammy | 否 | linux 5.15.0-125.135/5.15.0-130.140 → 5.15.0-156.166 |

（另有 48 則未列出）
