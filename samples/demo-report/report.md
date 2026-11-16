# Ubuntu 主機資安健檢報告

| 項目 | 內容 |
|---|---|
| 受檢單位 | 示範單位（虛構） |
| 執行單位 | 示範執行單位（虛構） |
| 判斷基準月份 | 2026-11 |
| 受檢主機數 | 3 |
| 分析程式版本 | offline-ubuntu-healthcheck 0.5 |
| 弱點比對資料 | Canonical 官方 OVAL（security-metadata.canonical.com，CC BY-SA 4.0） |
| 比對引擎 | 內建比對（依官方 OVAL 的同一套判斷條件實作） |

**官方資料檔明細**

| 版本 | 檔案 | 官方產生時間 | 距分析日 | SHA-256（前 16 碼） | 與下載紀錄 |
|---|---|---|---|---|---|
| focal（20.04） | oci.com.ubuntu.focal.usn.oval.xml.bz2 | 2026-11-15T21:06:47 | 1 天 | d1a222aa36a2ea79 | 一致 |
| jammy（22.04） | oci.com.ubuntu.jammy.usn.oval.xml.bz2 | 2026-11-15T21:06:14 | 1 天 | e3bec427b1d302ca | 一致 |
| xenial（16.04） | oci.com.ubuntu.xenial.usn.oval.xml.bz2 | 2026-11-15T21:07:39 | 1 天 | 856c45d708e71b2c | 一致 |

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
| A | 高 | 5 個套件的安全修補，要訂閱 Ubuntu Pro 才拿得到 | 要更新的套件：linux、openssl、nginx、sudo、imagemagick。對應 49 則官方安全公告，其中重大或高風險 24 則；修補放在 esm-apps（18 則）、esm-infra（31 則），沒有訂閱的主機用 apt 也裝不到。其中包含核心更新，安裝後要重開機才生效。主機上的 Ubuntu Pro 用戶端另外回報 5 個套件待取得，可互相對照 | 訂閱 Ubuntu Pro，在主機上執行 sudo pro attach 註冊，再執行 sudo apt update 與 sudo apt upgrade | 是 |
| B | 高 | 已安裝新核心，但機器還在跑舊核心 | 執行中：5.4.0-150-generic；已安裝最新：5.4.0-169-generic。核心修補要重開機才生效 | 排定時段重開機（sudo reboot）；若停機困難，Ubuntu Pro 的 Livepatch 可在不重開機下套用高風險核心修補 | 部分 |
| B | 中 | 已連續運作 200 天沒有重開機 | 長時間不重開機，核心修補很可能沒有生效 | 確認停機限制；Ubuntu Pro 的 Livepatch 只處理高風險與重大核心漏洞，不能取代所有重開機 | 部分 |
| C | 低 | 未使用 CIS／DISA-STIG 基準的自動化稽核工具 | 沒有安裝 Ubuntu Security Guide（USG） | 若需要設定基準的稽核證據，可評估 Ubuntu Pro 內含的 USG（CIS 與 DISA-STIG 設定檔）；與各單位適用的組態基準對應需另行比對 | 部分 |
| D | 高 | 6 個套件有免費的安全修補，還沒安裝 | 要更新的套件：linux、openssl、sudo、imagemagick、nginx、bash。對應 74 則官方安全公告，其中重大或高風險 43 則。這些修補放在 Ubuntu 一般的更新來源，不需要 Ubuntu Pro。其中包含核心更新，安裝後要重開機才生效 | 在主機上執行 sudo apt update 與 sudo apt upgrade；建議排定固定的修補時段，或啟用自動安全更新 | 否 |
| D | 高 | SSH 允許 root 直接登入 | SSH 設定 PermitRootLogin 為 yes | 在 /etc/ssh/sshd_config（或 /etc/ssh/sshd_config.d/ 裡的設定檔）把 PermitRootLogin 改為 no，再執行 sudo systemctl reload ssh | 否 |
| D | 中 | SSH 允許密碼登入 | SSH 設定 PasswordAuthentication 為 yes，帳號可能被猜密碼 | 先確認每位管理者都能用金鑰登入，再把 PasswordAuthentication 改為 no，執行 sudo systemctl reload ssh | 否 |
| D | 中 | 主機防火牆（ufw）未啟用 | ufw 狀態為 inactive | 先確認是否已由網路層防火牆保護。要啟用時，先執行 sudo ufw allow OpenSSH 保留遠端登入，再執行 sudo ufw enable | 否 |
| D | 中 | 有 3 個非 Ubuntu 官方來源的套件 | 第三方或來源不明的套件，不在 Ubuntu 與 Ubuntu Pro 的修補範圍 | 在主機上執行 pro security-status --thirdparty 與 pro security-status --unavailable 列出這些套件，盤點來源並向原廠確認更新方式 | 否 |
| D | 低 | 未啟用自動安全更新 | unattended-upgrades 沒有設定為每天執行 | 依單位的變更管理規定決定是否啟用；要啟用時執行 sudo dpkg-reconfigure -plow unattended-upgrades | 否 |

### demo-db01（Ubuntu 16.04.7 LTS）

維護狀態：ESM 已於 2026-05 結束；需 Ubuntu Pro 加購 Legacy，最長到 2031-05

| 類別 | 嚴重度 | 發現 | 說明 | 建議 | Pro 能否解決 |
|---|---|---|---|---|---|
| A | 高 | 作業系統已過 ESM 期限 | ESM 已於 2026-05 結束；需 Ubuntu Pro 加購 Legacy，最長到 2031-05 | 需要 Ubuntu Pro 加上 Legacy 加購；建議同步規劃升級，Legacy 適合當作遷移期的過渡 | 是 |
| A | 高 | 5 個套件的安全修補，要訂閱 Ubuntu Pro 才拿得到 | 要更新的套件：linux、sudo、openssh、glibc、bash。對應 85 則官方安全公告，其中重大或高風險 60 則；修補放在 esm-infra（75 則）、esm-infra-legacy（10 則），沒有訂閱的主機用 apt 也裝不到。其中包含核心更新，安裝後要重開機才生效。主機上的 Ubuntu Pro 用戶端另外回報 2 個套件待取得，可互相對照 | 訂閱 Ubuntu Pro，在主機上執行 sudo pro attach 註冊，再執行 sudo apt update 與 sudo apt upgrade | 是 |
| B | 中 | 已連續運作 480 天沒有重開機 | 長時間不重開機，核心修補很可能沒有生效 | 確認停機限制；Ubuntu Pro 的 Livepatch 只處理高風險與重大核心漏洞，不能取代所有重開機 | 部分 |
| D | 高 | 4 個套件有免費的安全修補，還沒安裝 | 要更新的套件：glibc、sudo、bash、linux。對應 14 則官方安全公告，其中重大或高風險 3 則。這些修補放在 Ubuntu 一般的更新來源，不需要 Ubuntu Pro。其中包含核心更新，安裝後要重開機才生效 | 在主機上執行 sudo apt update 與 sudo apt upgrade；建議排定固定的修補時段，或啟用自動安全更新 | 否 |
| D | 中 | SSH 允許密碼登入 | SSH 設定 PasswordAuthentication 為 yes，帳號可能被猜密碼 | 先確認每位管理者都能用金鑰登入，再把 PasswordAuthentication 改為 no，執行 sudo systemctl reload ssh | 否 |
| D | 低 | 未啟用自動安全更新 | unattended-upgrades 沒有設定為每天執行 | 依單位的變更管理規定決定是否啟用；要啟用時執行 sudo dpkg-reconfigure -plow unattended-upgrades | 否 |

### demo-web01（Ubuntu 22.04.5 LTS）

維護狀態：標準維護期內（到 2027-05）

> 以一般使用者收集（預設）：SSH 設定、防火牆、空密碼帳號需要 sudo 才能檢查，列在「未能檢查」。

| 類別 | 嚴重度 | 發現 | 說明 | 建議 | Pro 能否解決 |
|---|---|---|---|---|---|
| A | 中 | 1 個套件的安全修補，要訂閱 Ubuntu Pro 才拿得到 | 要更新的套件：redis。對應 2 則官方安全公告，其中重大或高風險 0 則；修補放在 esm-apps（2 則），沒有訂閱的主機用 apt 也裝不到。主機上的 Ubuntu Pro 用戶端另外回報 1 個套件待取得，可互相對照 | 訂閱 Ubuntu Pro，在主機上執行 sudo pro attach 註冊，再執行 sudo apt update 與 sudo apt upgrade | 是 |
| B | 高 | 已安裝新核心，但機器還在跑舊核心 | 執行中：5.15.0-125-generic；已安裝最新：5.15.0-130-generic。核心修補要重開機才生效 | 排定時段重開機（sudo reboot）；若停機困難，Ubuntu Pro 的 Livepatch 可在不重開機下套用高風險核心修補 | 部分 |
| C | 低 | 未使用 CIS／DISA-STIG 基準的自動化稽核工具 | 沒有安裝 Ubuntu Security Guide（USG） | 若需要設定基準的稽核證據，可評估 Ubuntu Pro 內含的 USG（CIS 與 DISA-STIG 設定檔）；與各單位適用的組態基準對應需另行比對 | 部分 |
| D | 高 | 5 個套件有免費的安全修補，還沒安裝 | 要更新的套件：linux、curl、openssl、redis、bash。對應 76 則官方安全公告，其中重大或高風險 43 則。這些修補放在 Ubuntu 一般的更新來源，不需要 Ubuntu Pro。其中包含核心更新，安裝後要重開機才生效 | 在主機上執行 sudo apt update 與 sudo apt upgrade；建議排定固定的修補時段，或啟用自動安全更新 | 否 |
| D | 中 | 有 12 個非 Ubuntu 官方來源的套件 | 第三方或來源不明的套件，不在 Ubuntu 與 Ubuntu Pro 的修補範圍 | 在主機上執行 pro security-status --thirdparty 與 pro security-status --unavailable 列出這些套件，盤點來源並向原廠確認更新方式 | 否 |
| D | 低 | 未啟用自動安全更新 | unattended-upgrades 沒有設定為每天執行 | 依單位的變更管理規定決定是否啟用；要啟用時執行 sudo dpkg-reconfigure -plow unattended-upgrades | 否 |

未能檢查的項目（不計入上表）：SSH 設定（主機沒有安裝 SSH 服務）；主機防火牆（ufw）狀態（需要 sudo，或主機未安裝 ufw）；空密碼帳號（需要 sudo）

## 四、建議處理順序

1. 先處理各類「高」嚴重度項目，其中 D 類的帳號與登入設定通常當天就能改。
2. 已過標準維護期的主機（A 類）：短期以 Ubuntu Pro 恢復安全更新，同時排定升級計畫。
3. 核心修補無法排停機的主機（B 類）：評估 Livepatch，並保留定期重開機的維護窗口。
4. 需要稽核證據的單位（C 類）：評估 USG，並與適用的組態基準比對。

## 五、檢查範圍與限制

- 本健檢只讀取系統資訊，不做弱點利用測試、不修改設定，不等同滲透測試。
- 只涵蓋 Ubuntu 官方套件庫的套件；第三方軟體（例如自行安裝的應用程式）的弱點不在比對範圍。
- 官方弱點資料以「已安裝的套件版本」比對：舊核心套件若仍留在系統上，也可能被列入；實際執行中的核心請看 B 類。
- 建議欄的指令是一般做法，執行前請依單位的變更管理規定評估，並先在測試環境確認。
- 標示「未能檢查」的項目，代表收集時權限不足或主機沒有對應工具，不代表沒有問題。
- 結果反映收集當下的狀態，以及報告上所列官方資料日期之前公布的弱點。

## 附錄：官方弱點資料比對（依套件彙整）

免費就能修補的排前面，每一組最多列 30 個套件；逐則公告的完整清單在 oval-detail.json 與 report.html。

### demo-ap01

**免費就能修補**：6 個套件、74 則公告

| 套件（原始碼套件名稱） | 最高嚴重度 | 公告數 | 修補來源 | 已安裝 → 修補版本 |
|---|---|---|---|---|
| linux | 重大 | 41 | Ubuntu 一般更新 | 5.4.0-150.160/5.4.0-169.179 → 5.4.0-216.236 |
| openssl | 高 | 16 | Ubuntu 一般更新 | 1.1.1f-1ubuntu2 → 1.1.1f-1ubuntu2.24 |
| sudo | 高 | 3 | Ubuntu 一般更新 | 1.8.31-1ubuntu1 → 1.8.31-1ubuntu1.5 |
| imagemagick | 中 | 8 | Ubuntu 一般更新 | 8:6.9.10.23+dfsg-2.1ubuntu11 → 8:6.9.10.23+dfsg-2.1ubuntu11.11 |
| nginx | 中 | 5 | Ubuntu 一般更新 | 1.18.0-0ubuntu1 → 1.18.0-0ubuntu1.7 |
| bash | 低 | 1 | Ubuntu 一般更新 | 5.0-6ubuntu1 → 5.0-6ubuntu1.2 |

**要訂閱 Ubuntu Pro 才能修補**：5 個套件、49 則公告

| 套件（原始碼套件名稱） | 最高嚴重度 | 公告數 | 修補來源 | 已安裝 → 修補版本 |
|---|---|---|---|---|
| linux | 重大 | 20 | esm-infra | 5.4.0-150.160/5.4.0-169.179 → 5.4.0-245.265 |
| openssl | 高 | 6 | esm-infra | 1.1.1f-1ubuntu2 → 1.1.1f-1ubuntu2.24+esm6 |
| nginx | 高 | 3 | esm-infra | 1.18.0-0ubuntu1 → 1.18.0-0ubuntu1.7+esm4 |
| sudo | 高 | 2 | esm-infra | 1.8.31-1ubuntu1 → 1.8.31-1ubuntu1.5+esm2 |
| imagemagick | 中 | 18 | esm-apps | 8:6.9.10.23+dfsg-2.1ubuntu11 → 8:6.9.10.23+dfsg-2.1ubuntu11.11+esm16 |

### demo-db01

**免費就能修補**：4 個套件、14 則公告

| 套件（原始碼套件名稱） | 最高嚴重度 | 公告數 | 修補來源 | 已安裝 → 修補版本 |
|---|---|---|---|---|
| glibc | 高 | 6 | Ubuntu 一般更新 | 2.23-0ubuntu3 → 2.23-0ubuntu11.3 |
| sudo | 高 | 5 | Ubuntu 一般更新 | 1.8.16-0ubuntu1 → 1.8.16-0ubuntu1.10 |
| bash | 中 | 2 | Ubuntu 一般更新 | 4.3-14ubuntu1 → 4.3-14ubuntu1.4 |
| linux | 未分級 | 1 | Ubuntu 一般更新 | 4.4.0-210.220 → 4.4.0-210.242 |

**要訂閱 Ubuntu Pro 才能修補**：5 個套件、85 則公告

| 套件（原始碼套件名稱） | 最高嚴重度 | 公告數 | 修補來源 | 已安裝 → 修補版本 |
|---|---|---|---|---|
| linux | 重大 | 64 | esm-infra、esm-infra-legacy | 4.4.0-210.220 → 4.4.0-291.325 |
| sudo | 高 | 3 | esm-infra | 1.8.16-0ubuntu1 → 1.8.16-0ubuntu1.10+esm3 |
| openssh | 中 | 9 | esm-infra、esm-infra-legacy | 1:7.2p2-4ubuntu2.8 → 1:7.2p2-4ubuntu2.10+esm10 |
| glibc | 中 | 8 | esm-infra | 2.23-0ubuntu3 → 2.23-0ubuntu11.3+esm9 |
| bash | 低 | 1 | esm-infra | 4.3-14ubuntu1 → 4.3-14ubuntu1.4+esm1 |

### demo-web01

**免費就能修補**：5 個套件、76 則公告

| 套件（原始碼套件名稱） | 最高嚴重度 | 公告數 | 修補來源 | 已安裝 → 修補版本 |
|---|---|---|---|---|
| linux | 重大 | 41 | Ubuntu 一般更新 | 5.15.0-125.135/5.15.0-130.140 → 5.15.0-203.213 |
| curl | 高 | 18 | Ubuntu 一般更新 | 7.81.0-1ubuntu1.10 → 7.81.0-1ubuntu1.30 |
| openssl | 高 | 14 | Ubuntu 一般更新 | 3.0.2-0ubuntu1.10 → 3.0.2-0ubuntu1.30 |
| redis | 高 | 2 | Ubuntu 一般更新 | 5:6.0.16-1ubuntu1 → 5:6.0.16-1ubuntu1.2 |
| bash | 中 | 1 | Ubuntu 一般更新 | 5.1-6ubuntu1 → 5.1-6ubuntu1.1 |

**要訂閱 Ubuntu Pro 才能修補**：1 個套件、2 則公告

| 套件（原始碼套件名稱） | 最高嚴重度 | 公告數 | 修補來源 | 已安裝 → 修補版本 |
|---|---|---|---|---|
| redis | 中 | 2 | esm-apps | 5:6.0.16-1ubuntu1 → 5:6.0.16-1ubuntu1+esm2 |
