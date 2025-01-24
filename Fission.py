import os
import re
import random
import ipaddress
import socket
import concurrent.futures
import logging
import requests
from lxml import etree
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 配置日志
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 文件配置
ips = "Fission_ip.txt"
domains = "Fission_domain.txt"
dns_result = "dns_result.txt"

# 并发数配置
max_workers_request = os.cpu_count() * 2  # 并发请求数量
max_workers_dns = os.cpu_count() * 5  # 并发DNS查询数量

# 网站配置
sites_config = {
    "site_ip138": {
        "url": "https://site.ip138.com/",  # 替换为实际的网站URL
        "xpath": '//ul[@id="list"]/li/a'
    },
    "dnsdblookup": {
        "url": "https://dnsdblookup.com/",  # 替换为实际的网站URL
        "xpath": '//ul[@id="list"]/li/a'
    },
    "ipchaxun": {
        "url": "https://ipchaxun.com/",  # 替换为实际的网站URL
        "xpath": '//div[@id="J_domain"]/p/a'
    }
}

# 生成随机User-Agent
ua = UserAgent()

# 设置会话
def setup_session():
    session = requests.Session()
    retries = Retry(total=5, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# 生成请求头
def get_headers():
    return {
        'User-Agent': ua.random,
        'Accept': '*/*',
        'Connection': 'keep-alive',
    }

# 查询域名的函数，自动重试和切换网站
def fetch_domains_for_ip(ip_address, session, attempts=0, used_sites=None):
    logging.info(f"Fetching domains for {ip_address}...")
    if used_sites is None:
        used_sites = []
    if attempts >= 3:  # 如果已经尝试了3次，终止重试
        return []

    # 选择一个未使用的网站进行查询
    available_sites = {key: value for key, value in sites_config.items() if key not in used_sites}
    if not available_sites:
        return []  # 如果所有网站都尝试过，返回空结果

    site_key = random.choice(list(available_sites.keys()))
    site_info = available_sites[site_key]
    used_sites.append(site_key)

    try:
        url = f"{site_info['url']}{ip_address}/"
        headers = get_headers()
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        html_content = response.text

        parser = etree.HTMLParser()
        tree = etree.fromstring(html_content, parser)
        a_elements = tree.xpath(site_info['xpath'])
        domains = [a.text for a in a_elements if a.text]

        if domains:
            logging.info(f"Successfully fetched domains for {ip_address} from {site_info['url']}")
            return domains
        else:
            raise Exception("No domains found")

    except Exception as e:
        logging.warning(f"Error fetching domains for {ip_address} from {site_info['url']}: {e}")
        return fetch_domains_for_ip(ip_address, session, attempts + 1, used_sites)

# 并发处理所有IP地址
def fetch_domains_concurrently(ip_addresses):
    session = setup_session()
    domains = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_request) as executor:
        future_to_ip = {executor.submit(fetch_domains_for_ip, ip, session): ip for ip in ip_addresses}
        for future in concurrent.futures.as_completed(future_to_ip):
            domains.extend(future.result())

    return list(set(domains))

# DNS查询函数
def dns_lookup(domain):
    logging.info(f"Performing DNS lookup for {domain}...")
    try:
        ip = socket.gethostbyname(domain)
        return domain, ip
    except socket.gaierror:
        return domain, None

# 通过域名列表获取绑定过的所有ip
def perform_dns_lookups(domain_filename, result_filename, unique_ipv4_filename):
    try:
        # 读取域名列表
        with open(domain_filename, 'r') as file:
            domains = file.read().splitlines()

        # 创建一个线程池并执行DNS查询
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_dns) as executor:
            results = list(executor.map(dns_lookup, domains))

        # 写入查询结果到文件
        with open(result_filename, 'w') as output_file:
            for domain, ip in results:
                if ip:
                    output_file.write(f"{domain}: {ip}\n")

        # 从结果文件中提取所有IPv4地址
        ipv4_addresses = set(ip for _, ip in results if ip)

        # 读取已存在的IP列表
        with open(unique_ipv4_filename, 'r') as file:
            existing_ips = {line.strip() for line in file}

        # 检查IP地址是否为公网IP
        filtered_ipv4_addresses = set()
        for ip in ipv4_addresses:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_global:
                    filtered_ipv4_addresses.add(ip)
            except ValueError:
                # 忽略无效IP地址
                continue

        # 合并新旧IP地址并去重
        filtered_ipv4_addresses.update(existing_ips)

        # 保存IPv4地址
        with open(unique_ipv4_filename, 'w') as output_file:
            for address in filtered_ipv4_addresses:
                output_file.write(address + '\n')

    except Exception as e:
        logging.error(f"Error performing DNS lookups: {e}")

# 主函数
def main():
    # 确保文件存在
    if not os.path.exists(ips):
        open(ips, 'w').close()
    if not os.path.exists(domains):
        open(domains, 'w').close()

    # IP反查域名
    with open(ips, 'r') as ips_txt:
        ip_list = [ip.strip() for ip in ips_txt if ip.strip()]

    domain_list = fetch_domains_concurrently(ip_list)
    logging.info(f"Domain list: {domain_list}")

    # 合并新旧域名列表
    with open(domains, 'r') as file:
        existing_domains = {line.strip() for line in file}

    domain_list = list(set(domain_list + list(existing_domains)))

    # 保存域名列表
    with open(domains, 'w') as output:
        for domain in domain_list:
            output.write(domain + "\n")
    logging.info("IP -> Domain lookup completed.")

    # 域名解析IP
    perform_dns_lookups(domains, dns_result, ips)
    logging.info("Domain -> IP lookup completed.")

# 程序入口
if __name__ == '__main__':
    main()
