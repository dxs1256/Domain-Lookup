# Cloudflare IP 反查工具

此工具旨在通过抓取 Cloudflare 地址、反查 IP 获取域名，并验证域名的可用性。具体操作步骤如下：

## 操作步骤

### 1. 抓取 IP 地址

访问 [WeTest Cloudflare 地址查询](https://www.wetest.vip/page/cloudflare/address_v4.html) 页面，抓取至少 3 个 IP 地址，并将其保存到 `Fission_ip.txt` 文件中。

### 2. 通过反查获取大量域名

运行 `Fission.py` 脚本，程序将从 `Fission_ip.txt` 文件中提取 IP 地址，通过反查获取大量域名，并将结果保存到 `Fission_domain.txt` 文件中。

### 3. 验证域名可用性

使用 httpx 工具对 Fission_domain.txt 中的域名进行 HTTP 请求，筛选出返回 HTTP 状态码为 200 的域名，并将其保存到 Last-domain.txt 文件中。

参考项目
Fission.py - 用于获取并反查 Cloudflare IP 地址，获得大量域名。
httpx - 用于验证域名可用性的工具，支持批量域名检测。
