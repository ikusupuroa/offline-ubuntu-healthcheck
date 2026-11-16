# 用 LXD 虛擬機測試

這份說明用一台 Ubuntu Desktop（例如 26.04）當測試主機，以 LXD 建立各版本的 Ubuntu Server 虛擬機，再把收集腳本傳進去執行。

指令依 LXD 的一般用法撰寫；若與你的 LXD 版本不同，請以 `lxc --help` 為準。

## 1. 準備測試主機

```bash
sudo snap install lxd
sudo lxd init --minimal
sudo usermod -aG lxd "$USER"     # 之後重新登入，才能不用 sudo 執行 lxc
sudo apt install openscap-scanner git
git clone https://github.com/ikusupuroa/offline-ubuntu-healthcheck.git
cd offline-ubuntu-healthcheck
python3 update-data.py
```

## 2. 建立虛擬機

**一定要加 `--vm` 建立虛擬機，不要用容器。**容器共用測試主機的核心，核心版本、待重開機等檢查都會失真。

```bash
lxc launch ubuntu:20.04 t-2004 --vm
lxc launch ubuntu:22.04 t-2204 --vm
lxc launch ubuntu:24.04 t-2404 --vm
lxc launch ubuntu:16.04 t-1604 --vm
lxc exec t-2004 -- cloud-init status --wait
```

較舊的版本（14.04、16.04）可能沒有虛擬機映像。`launch` 失敗時，把錯誤訊息記進測試紀錄，再改用其他方式建立虛擬機。

建議每台裝一個 Universe 套件，才測得到 esm-apps：

```bash
lxc exec t-2004 -- apt-get update
lxc exec t-2004 -- apt-get install -y nginx
```

## 3. 傳入腳本並收集

```bash
lxc file push collect.sh t-2004/home/ubuntu/collect.sh

# 一般使用者（預設）
lxc exec t-2004 -- su - ubuntu -c 'bash collect.sh --tag T-2004-user'

# 用 sudo（加做 SSH、防火牆、空密碼帳號）
lxc exec t-2004 -- su - ubuntu -c 'sudo bash collect.sh --tag T-2004-sudo'
```

## 4. 取回收集檔

```bash
lxc exec t-2004 -- sh -c 'ls /home/ubuntu/hc-*.tar.gz'
lxc file pull t-2004/home/ubuntu/<上一步列出的檔名> ./runs/
```

## 5. 分析

```bash
python3 analyze.py runs/hc-T-2004-*.tar.gz --engine both --out runs/report-2004
```

`--engine both` 會同時用 OpenSCAP 與內建比對，每台主機下方會列出兩者的差異；差異應該是 0。

對照組：在虛擬機裡執行 `pro security-status`，看「需要 Ubuntu Pro 才能取得的更新」數量。這個數字和報告裡的 A 類應該方向一致。兩者單位不同（套件數與公告數），所以不會完全相等。

## 6. 離線測試

`lxc exec` 不經過虛擬機的網路，所以拔掉網卡後仍然可以操作：

```bash
lxc exec t-2004 -- ip -br link                 # 找出網卡名稱，例如 enp5s0
lxc exec t-2004 -- ip link set enp5s0 down     # 斷網
lxc exec t-2004 -- su - ubuntu -c 'time bash collect.sh --tag T-2004-offline'
lxc exec t-2004 -- ip link set enp5s0 up       # 恢復
```

記錄總耗時，以及哪個步驟等比較久。

## 7. 確認沒有寫入其他檔案

```bash
lxc exec t-2004 -- touch /tmp/hc-marker
lxc exec t-2004 -- su - ubuntu -c 'sudo bash collect.sh --tag T-2004-write'
lxc exec t-2004 -- sh -c 'find / -xdev -newer /tmp/hc-marker -type f 2>/dev/null | grep -v -e ^/proc -e ^/sys'
```

除了產出的 tar.gz 之外，列出來的檔案都要記錄下來，例如 pro 指令自己的記錄檔。

## 8. 隱私檢查

```bash
mkdir -p check && tar -xzf runs/hc-T-2004-sudo-*.tar.gz -C check
grep -r "$(lxc exec t-2004 -- hostname)" check
grep -rE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" check | grep -v dpkg.txt
```

應該查不到主機名稱與 IP。

## 9. 已註冊主機（選做）

用 Ubuntu Pro 的免費個人訂閱註冊一台虛擬機，確認報告不會把已啟用的服務誤報為 A 類。註冊用的 token 請自己在虛擬機裡輸入，不要寫進任何紀錄檔。

```bash
lxc exec t-att -- pro attach        # 依畫面指示操作
```
