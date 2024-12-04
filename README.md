# 项目说明

该项目旨在获取并反查 IP 地址，以获取大量域名，并验证这些域名的可用性。IP 地址的获取部分由 GitHub Actions 自动从 [https://www.wetest.vip/page/cloudflare/address_v4.html](https://www.wetest.vip/page/cloudflare/address_v4.html) 抓取三个 IP 地址。本项目支持通过 GitHub Actions 自动化部署。

## 文件说明

### Fission_ip.txt
- **内容**：自动抓取取的 IP 地址列表。  

### Fission_domain.txt
- **内容**：通过反查 `Fission_ip.txt` 中的 IP 地址获取到的域名列表。

### Last-domain.txt
- **内容**：最终筛选出的可用域名列表（HTTP 状态码为 200）。

## 使用方法

1. **IP 地址获取**：自动抓取 IP 地址并保存至 `Fission_ip.txt` 文件。
2. **反查域名**：使用 `Fission.py` 脚本反查 `Fission_ip.txt` 中的 IP 地址，生成 `Fission_domain.txt` 文件。
3. **域名检测**：使用 [httpx](https://github.com/projectdiscovery/httpx) 工具对 `Fission_domain.txt` 中的域名进行可用性检测，筛选出 HTTP 状态码为 200 的域名。将检测结果保存至 `Last-domain.txt` 文件中。

## 感谢

感谢原项目作者 [snowfal1](https://github.com/snowfal1) 提供的开源项目 [CloudflareCDNFission](https://github.com/snowfal1/CloudflareCDNFission)，为本项目提供了重要的技术支持和灵感。

