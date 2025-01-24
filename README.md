## 项目说明：IP 反查与域名可用性验证

**项目目标：**

本项目旨在通过 IP 反查获取大量域名，并验证这些域名的可用性，最终筛选出可用的域名列表。

**核心流程：**

1.  **IP 地址抓取：**
    *   使用 GitHub Actions 自动从网络抓取三个 IP 地址。
    *   抓取结果保存至 `Fission_ip.txt` 文件。
2.  **域名反查：**
    *   使用 `Fission.py` 脚本，对 `Fission_ip.txt` 中的 IP 地址进行反查，获取域名列表。
    *   反查结果保存至 `Fission_domain.txt` 文件。
3.  **域名可用性检测：**
    *   使用 `httpx` 工具，对 `Fission_domain.txt` 中的域名进行可用性检测，筛选出 HTTP 状态码为 200 的域名。
    *   检测结果保存至 `Last-domain.txt` 文件。

**文件说明：**

*   `Fission_ip.txt`: 自动抓取的 IP 地址列表。
*   `Fission_domain.txt`: 通过反查 IP 地址获取的域名列表。
*   `Last-domain.txt`: 最终筛选出的可用域名列表（HTTP 状态码为 200）。

**使用方法：**

本项目通过 GitHub Actions 实现自动化部署，无需手动执行脚本。

**致谢：**

感谢原项目作者 snowfal1 提供的开源项目 [CloudflareCDNFission](链接待补充)，为本项目提供了重要的技术支持和灵感。
