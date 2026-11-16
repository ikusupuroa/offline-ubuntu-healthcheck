# 用 LXD 虛擬機測試

用一台 Ubuntu 電腦（例如 Desktop 26.04）當測試主機，以 LXD 建立各版本的 Ubuntu Server 虛擬機，一個指令跑完所有測試。

## 1. 準備（只要做一次）

```bash
sudo snap install lxd
sudo lxd init --minimal
sudo usermod -aG lxd "$USER"
```

做完**登出再登入**，之後才能不用 sudo 執行 `lxc`。

```bash
sudo apt install -y git openscap-scanner
git clone https://github.com/ikusupuroa/offline-ubuntu-healthcheck.git
cd offline-ubuntu-healthcheck
```

`openscap-scanner` 不是必要的，裝了才能做「兩個比對引擎互相對照」。

## 2. 跑測試

在 `offline-ubuntu-healthcheck` 資料夾裡執行：

```bash
tests/lxd-quicktest.sh
```

預設測 20.04、22.04、24.04、26.04。要指定版本：

```bash
tests/lxd-quicktest.sh 18.04 20.04
```

第一次要下載映像檔、建立虛擬機，每個版本約 3 到 5 分鐘。虛擬機會保留下來，之後重跑快很多。

腳本會自動做這些事：

| 步驟 | 對應的測試項目 |
|---|---|
| 下載並核對官方資料 | T13 |
| 建立虛擬機，裝一個 Universe 套件（nginx） | |
| 一般使用者與 sudo 各收集一次 | T1、T6 |
| 檢查收集時有沒有寫入其他檔案 | T2 |
| 關掉網路再收集一次，記錄花多久 | T3 |
| 檢查收集結果裡有沒有主機名稱與 IP | T7 |
| 兩個比對引擎各算一次，比較結果 | T10、T11 |
| 26.04 的維護狀態 | T15 |

## 3. 看結果

跑完會在畫面上印出結果表，同一份內容存在 `test-results/<日期時間>/RESULTS.md`，可以直接貼進測試紀錄。

```
test-results/<日期時間>/
├── RESULTS.md          測試結果表
├── report/report.html  健檢報告，用瀏覽器打開
├── bundles/            收集到的檔案
└── logs/               每個步驟的紀錄（出問題時看這裡）
```

結果表裡標「人工核對」或「記錄」的項目，需要你看一下內容再判斷。

腳本沒辦法自動做的項目：

- **T8**：打開報告，確認每項發現和主機實際狀況相符。
- **T9**：已註冊 Ubuntu Pro 的主機。請自己在一台虛擬機裡執行 `sudo pro attach`，再重跑腳本。註冊用的 token 請自己輸入，不要寫進任何檔案。
- **T4、T5**：對照 `logs/security-status-<版本>.txt` 與收集檔裡的 `pro-api-updates.json`。

## 4. 清理

```bash
tests/lxd-quicktest.sh --cleanup
```

會刪除腳本建立的所有測試機（名稱開頭是 `hc-t-`），不會動到其他虛擬機。

## 5. 舊版本（14.04、16.04）

較舊的版本在新版 LXD 上常常建不了虛擬機，或是虛擬機開起來之後 LXD 連不進去。遇到這種情況，腳本會標示「略過」，然後繼續測其他版本。

真的要測的話，可以改用容器：

```bash
tests/lxd-quicktest.sh --allow-container 16.04
```

容器跟測試主機共用同一個核心，所以**核心版本、待重開機這些項目的結果不準**，結果表會加上註記。容器裡如果沒有網路或沒有 `ubuntu` 帳號，腳本會標示失敗並說明原因。

## 附錄：手動操作

不用腳本也可以手動測，以下指令都在 `offline-ubuntu-healthcheck` 資料夾裡執行。

```bash
mkdir -p runs
lxc launch ubuntu:22.04 t-2204 --vm
lxc exec t-2204 -- cloud-init status --wait
```

收集，不必先把腳本傳進虛擬機：

```bash
lxc exec t-2204 -- su - ubuntu -c 'bash -s -- --tag T-2204 --stdout' < collect.sh > runs/hc-T-2204.tar.gz
```

要用 sudo 的話，把 `bash -s` 換成 `sudo -n bash -s`。

分析：

```bash
./hc report runs/hc-T-2204.tar.gz --engine both
```

注意：

- `lxc console --show-log` 只能用在容器，虛擬機不能用。
- 用 cloud-init 放 SSH 公鑰，對 16.04 的虛擬機沒有效果。
