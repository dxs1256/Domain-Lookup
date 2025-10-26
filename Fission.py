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

# 文件配置（分离输入与扩线结果）
input_ips_file = "Fission_ip.txt"          # 输入：你提供的初始IP
domains_file = "Fission_domain.txt"        # 收集到的域名（持久化）
dns_result_file = "dns_result.txt"         # 域名解析结果
expanded_ips_file = "Fission_ip_expanded.txt"  # 从域名解析出的新IP（扩线结果）

# 并发配置
max_workers_request = min(20, (os.cpu_count() or 4) * 2)
max_workers_dns = min(100, (os.cpu_count() or 4) * 5)

# 网站配置（已去除URL末尾空格！）
sites_config = {
    "site_ip138": {
        "url": "https://site.ip138.com/",
        "xpath": '//ul[@id="list"]/li/a'
    },
    "ipchaxun": {
        "url": "https://ipchaxun.com/",
        "xpath": '//div[@id="J_domain"]/p/a'
    }
}

# 初始化 User-Agent
ua = UserAgent()

def setup_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def get_headers():
    return {
        'User-Agent': ua.random,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    }

def is_valid_domain(domain: str) -> bool:
    """过滤明显无效或垃圾域名"""
    if not domain or len(domain) > 253 or domain.count('.') < 1:
        return False
    if not re.match(r'^[a-zA-Z0-9._-]+$', domain):
        return False
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    for part in parts:
        if not part or len(part) > 63 or part.startswith('-') or part.endswith('-'):
            return False
    # 排除 www+纯数字 或 纯数字域名
    first = parts[0]
    if re.match(r'^\d+$', first):
        return False
    if first.startswith('www') and len(first) > 3 and first[3:].isdigit():
        return False
    return True

def fetch_domains_for_ip(ip_address, session, used_sites=None):
    if used_sites is None:
        used_sites = []
    available_sites = {k: v for k, v in sites_config.items() if k not in used_sites}
    if not available_sites:
        return []

    site_key = random.choice(list(available_sites.keys()))
    site_info = available_sites[site_key]
    used_sites.append(site_key)

    try:
        url = f"{site_info['url']}{ip_address}/"
        headers = get_headers()
        response = session.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        # 快速判断是否无结果
        text_lower = response.text.lower()
        if any(keyword in text_lower for keyword in ["未收录", "没有找到", "暂无数据", "no data"]):
            raise Exception("No records")

        tree = etree.HTML(response.text)
        if tree is None:
            raise Exception("HTML parse failed")

        a_elements = tree.xpath(site_info['xpath'])
        domains = []
        for a in a_elements:
            text = a.text
            if text:
                clean_text = text.strip()
                if clean_text and is_valid_domain(clean_text):
                    domains.append(clean_text)

        if domains:
            logging.info(f"[{site_key}] Found {len(domains)} domains for {ip_address}")
            return domains
        else:
            raise Exception("No valid domains extracted")

    except Exception as e:
        logging.warning(f"Failed {site_key} for {ip_address}: {e}")
        if len(used_sites) < len(sites_config):
            return fetch_domains_for_ip(ip_address, session, used_sites)
        else:
            return []

def fetch_domains_concurrently(ip_list):
    if not ip_list:
        return []
    session = setup_session()
    all_domains = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_request) as executor:
        future_to_ip = {executor.submit(fetch_domains_for_ip, ip, session): ip for ip in ip_list}
        for future in concurrent.futures.as_completed(future_to_ip):
            domains = future.result()
            all_domains.update(domains)
    return list(all_domains)

def dns_lookup(domain):
    domain = domain.lower().strip()
    try:
        ip = socket.gethostbyname(domain)
        return domain, ip
    except Exception as e:
        logging.debug(f"DNS failed for {domain}: {e}")
        return domain, None

def perform_dns_lookups():
    if not os.path.exists(domains_file):
        logging.warning(f"{domains_file} not found. Skipping DNS.")
        return

    with open(domains_file, 'r', encoding='utf-8') as f:
        domains = [line.strip() for line in f if line.strip()]
    domains = list(set(domains))
    if not domains:
        return

    logging.info(f"Resolving {len(domains)} domains...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers_dns) as executor:
        results = list(executor.map(dns_lookup, domains))

    # 写入解析结果
    with open(dns_result_file, 'w', encoding='utf-8') as f:
        for domain, ip in results:
            if ip:
                f.write(f"{domain}: {ip}\n")

    # 提取公网 IPv4
    new_ips = set()
    for _, ip in results:
        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.version == 4 and ip_obj.is_global:
                    new_ips.add(str(ip_obj))
            except ValueError:
                continue

    # 合并扩线 IP
    existing = set()
    if os.path.exists(expanded_ips_file):
        with open(expanded_ips_file, 'r', encoding='utf-8') as f:
            existing = {line.strip() for line in f if line.strip()}

    all_ips = existing | new_ips
    with open(expanded_ips_file, 'w', encoding='utf-8') as f:
        for ip in sorted(all_ips):
            f.write(ip + '\n')

    logging.info(f"DNS done. New IPs: {len(new_ips)}, Total expanded: {len(all_ips)}")

def main():
    # 确保输入文件存在
    if not os.path.exists(input_ips_file):
        logging.info(f"Creating empty {input_ips_file}")
        open(input_ips_file, 'w').close()

    # 读取输入 IP
    with open(input_ips_file, 'r', encoding='utf-8') as f:
        ip_list = [line.strip() for line in f if line.strip()]
    ip_list = list(set(ip_list))

    all_domains = set()
    if ip_list:
        logging.info(f"Reverse lookup for {len(ip_list)} IPs")
        domains = fetch_domains_concurrently(ip_list)
        all_domains.update(domains)

    # 合并已有域名
    if os.path.exists(domains_file):
        with open(domains_file, 'r', encoding='utf-8') as f:
            existing = {line.strip() for line in f if line.strip()}
        all_domains.update(existing)

    # 保存域名
    with open(domains_file, 'w', encoding='utf-8') as f:
        for d in sorted(all_domains):
            f.write(d + '\n')

    logging.info(f"Total domains collected: {len(all_domains)}")

    # 执行 DNS 解析
    perform_dns_lookups()

if __name__ == '__main__':
    main()
