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

# ==================== 配置 ====================
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

IPS_FILE = "Fission_ip.txt"
DOMAINS_FILE = "Fission_domain.txt"
DNS_RESULT_FILE = "dns_result.txt"

MAX_WORKERS_REQUEST = min(32, (os.cpu_count() or 4) * 2)
MAX_WORKERS_DNS = min(100, (os.cpu_count() or 4) * 5)

# 反查网站配置（含备用 XPath 和关键词校验）
SITES_CONFIG = {
    "ip138": {
        "url": "https://site.ip138.com/",
        "xpaths": ['//ul[@id="list"]/li/a'],
        "no_result_keywords": ["未查询到", "暂无", "没有相关记录"]
    },
    "dnsdblookup": {
        "url": "https://dnsdblookup.com/",
        "xpaths": ['//ul[@id="list"]/li/a'],
        "no_result_keywords": ["No records found"]
    },
    "ipchaxun": {
        "url": "https://ipchaxun.com/",
        "xpaths": ['//div[@id="J_domain"]/p/a'],
        "no_result_keywords": ["未查询到", "暂无相关域名"]
    }
}

# ==================== 工具函数 ====================
def is_valid_public_ipv4(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.version == 4 and ip.is_global
    except ValueError:
        return False

def setup_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({'Connection': 'keep-alive'})
    return session

# 固定一个 UA 避免频繁变化触发风控
UA = UserAgent().random

def get_headers():
    return {'User-Agent': UA}

# ==================== IP 反查域名 ====================
def extract_domains_from_html(html, site_config):
    tree = etree.HTML(html)
    if tree is None:
        return []
    for xpath in site_config["xpaths"]:
        elements = tree.xpath(xpath)
        domains = [e.text.strip() for e in elements if e.text and e.text.strip()]
        if domains:
            return domains
    return []

def has_no_result(html, site_config):
    html_lower = html.lower()
    for keyword in site_config["no_result_keywords"]:
        if keyword.lower() in html_lower:
            return True
    return False

def fetch_domains_for_ip(ip, session, used_sites=None):
    if used_sites is None:
        used_sites = set()
    available_sites = [k for k in SITES_CONFIG if k not in used_sites]
    random.shuffle(available_sites)

    for site_key in available_sites:
        site = SITES_CONFIG[site_key]
        url = f"{site['url']}{ip}/"
        try:
            response = session.get(url, headers=get_headers(), timeout=10)
            if response.status_code != 200:
                continue

            html = response.text
            if has_no_result(html, site):
                logging.debug(f"No domains found for {ip} on {site_key}")
                continue

            domains = extract_domains_from_html(html, site)
            if domains:
                logging.info(f"✅ Got {len(domains)} domains for {ip} from {site_key}")
                return domains
        except Exception as e:
            logging.debug(f"⚠️ Failed {site_key} for {ip}: {e}")
            continue
    return []

def fetch_all_domains(ip_list):
    session = setup_session()
    all_domains = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_REQUEST) as executor:
        future_to_ip = {executor.submit(fetch_domains_for_ip, ip, session): ip for ip in ip_list}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                domains = future.result()
                all_domains.update(domains)
            except Exception as e:
                logging.error(f"Unexpected error for {ip}: {e}")
    return list(all_domains)

# ==================== DNS 解析 ====================
def dns_lookup(domain):
    try:
        # 设置 socket 超时
        socket.setdefaulttimeout(5)
        ip = socket.gethostbyname(domain)
        return domain, ip
    except Exception:
        return domain, None

def load_existing_ips(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r', encoding='utf-8') as f:
        return {line.strip() for line in f if is_valid_public_ipv4(line.strip())}

def load_existing_domains(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r', encoding='utf-8') as f:
        return {line.strip() for line in f if line.strip()}

def save_lines(filename, lines):
    with open(filename, 'w', encoding='utf-8') as f:
        for line in sorted(lines):
            f.write(line + '\n')

def perform_dns_lookups(domain_list, existing_ips):
    if not domain_list:
        logging.info("No domains to resolve.")
        return existing_ips

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_DNS) as executor:
        results = list(executor.map(dns_lookup, domain_list))

    # 写入 DNS 结果
    with open(DNS_RESULT_FILE, 'w', encoding='utf-8') as f:
        for domain, ip in results:
            if ip:
                f.write(f"{domain}: {ip}\n")

    # 提取有效公网 IP
    new_ips = set()
    for _, ip in results:
        if ip and is_valid_public_ipv4(ip):
            new_ips.add(ip)

    # 合并去重
    merged_ips = existing_ips | new_ips
    return merged_ips

# ==================== 主流程 ====================
def main():
    # 初始化文件
    for f in [IPS_FILE, DOMAINS_FILE]:
        if not os.path.exists(f):
            open(f, 'w', encoding='utf-8').close()

    # 1. 读取并校验 IP 列表
    with open(IPS_FILE, 'r', encoding='utf-8') as f:
        raw_ips = [line.strip() for line in f if line.strip()]
    valid_ips = [ip for ip in raw_ips if is_valid_public_ipv4(ip)]
    logging.info(f"Loaded {len(valid_ips)} valid public IPs.")

    # 2. IP 反查域名
    new_domains = fetch_all_domains(valid_ips)
    existing_domains = load_existing_domains(DOMAINS_FILE)
    all_domains = existing_domains | set(new_domains)
    save_lines(DOMAINS_FILE, all_domains)
    logging.info(f"Total domains after merge: {len(all_domains)}")

    # 3. 域名解析 IP
    existing_ips = load_existing_ips(IPS_FILE)
    final_ips = perform_dns_lookups(list(all_domains), existing_ips)
    save_lines(IPS_FILE, final_ips)
    logging.info(f"Final IP count: {len(final_ips)}")

if __name__ == '__main__':
    main()
