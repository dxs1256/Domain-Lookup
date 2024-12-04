# 项目说明

该项目旨在获取并反查 Cloudflare IP 地址，以获取大量域名，并验证这些域名的可用性。IP 地址的获取部分由 GitHub Actions 自动从 [https://www.wetest.vip/page/cloudflare/address_v4.html](https://www.wetest.vip/page/cloudflare/address_v4.html) 抓取三个 IP 地址。本项目支持通过 GitHub Actions 实现自动化部署。

## 文件说明

### Fission_ip.txt
- **内容**：包含从 Cloudflare 获取的 IP 地址列表。  
  **(此文件由 GitHub Actions 自动生成)**。

### Fission_domain.txt
- **内容**：通过反查 `Fission_ip.txt` 中的 IP 地址获取到的域名列表。

### Last-domain.txt
- **内容**：最终筛选出的可用域名列表（HTTP 状态码为 200）。

## 使用方法

1. **IP 地址获取**：IP 地址由 GitHub Actions 自动从 [https://www.wetest.vip/page/cloudflare/address_v4.html](https://www.wetest.vip/page/cloudflare/address_v4.html) 抓取并保存至 `Fission_ip.txt` 文件。
2. **反查域名**：使用 `Fission.py` 脚本反查 `Fission_ip.txt` 中的 IP 地址，生成 `Fission_domain.txt` 文件。
3. **域名检测**：在筛选域名时，使用 `httpx` 工具对 `Fission_domain.txt` 中的域名进行可用性检测，筛选出 HTTP 状态码为 200 的域名。
4. **保存结果**：将检测结果保存至 `Last-domain.txt` 文件中。

## 注意事项

- 确保在运行脚本和工具之前已经安装了所有必要的依赖，包括 `httpx` 工具。
- 由于网络环境和 Cloudflare 的动态性，获取的 IP 地址和域名列表可能会随时间变化。
- 请遵守相关法律法规，不要将此工具用于非法用途。

## 版权声明

本项目为开源项目，您可以自由使用和修改，但请保留原作者信息和版权声明。
