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

socket.setdefaulttimeout(5)

MAX_WORKERS_REQUEST = 5
MAX_WORKERS_DNS = 50

SITES_CONFIG = {
    "dnsdblookup": {
        "url": "https://dnsdblookup.com/",
        "xpaths": ['//ul[@id="list"]//a/text()'],
        "no_result_keywords": ["No records found"]
    },
    "ipchaxun": {
        "url": "https://ipchaxun.com/",
        "xpaths": ['//div[@id="J_domain"]//a/text()'],
        "no_result_keywords": ["未查询到", "暂无相关域名"]
    },
    "ip138": {
        "url": "https://site.ip138.com/",
        "xpaths": ['//ul[@id="list"]//a/text()'],
        "no_result_keywords": ["未查询到", "暂无", "没有相关记录"]
    }
}

UA = UserAgent().random

def get_headers():
    return {'User-Agent': UA}

def setup_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({'Connection': 'keep-alive'})
    return session

def is_valid_public_ipv4(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.version == 4 and ip.is_global
    except ValueError:
        return False

def is_ip_address(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def is_likely_junk_domain(domain):
    """垃圾域名判定（满足任一即过滤）"""
    if not domain:
        return False
    domain = domain.strip()
    if len(domain) > 20:
        return True
    if domain.count('xn--') >= 3:
        return True
    if len(domain.split('.')) >= 4:
        return True
    return False

def is_valid_domain(domain):
    if not domain or len(domain) < 2:
        return False
    if is_ip_address(domain):
        return False
    if is_likely_junk_domain(domain):
        return False
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain):
        return False
    return True

def extract_domains_from_html(html, site_config):
    tree = etree.HTML(html)
    if tree is None:
        return []
    for xpath in site_config["xpaths"]:
        try:
            domains = tree.xpath(xpath)
            return [d.strip() for d in domains if d and d.strip()]
        except Exception:
            continue
    return []

def has_no_result(html, site_config):
    html_lower = html.lower()
    for keyword in site_config["no_result_keywords"]:
        if keyword.lower() in html_lower:
            return True
    return False

def fetch_domains_for_ip(ip, session):
    available_sites = list(SITES_CONFIG.keys())
    random.shuffle(available_sites)
    for site_key in available_sites:
        site = SITES_CONFIG[site_key]
        url = f"{site['url']}{ip}/"
        try:
            response = session.get(url, headers=get_headers(), timeout=12)
            if response.status_code != 200:
                continue
            html = response.text
            if has_no_result(html, site):
                continue
            domains = extract_domains_from_html(html, site)
            valid_domains = [d for d in domains if is_valid_domain(d)]
            if valid_domains:
                logging.info(f"✅ Got {len(valid_domains)} domains for {ip} from {site_key}")
                return valid_domains
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

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return domain, ip
    except Exception:
        return domain, None

def save_lines(filename, lines):
    with open(filename, 'w', encoding='utf-8') as f:
        for line in sorted(lines):
            f.write(line + '\n')

def perform_dns_lookups(domain_list):
    if not domain_list:
        return set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_DNS) as executor:
        results = list(executor.map(dns_lookup, domain_list))

    with open(DNS_RESULT_FILE, 'w', encoding='utf-8') as f:
        for domain, ip in results:
            if ip:
                f.write(f"{domain}: {ip}\n")

    new_ips = {ip for _, ip in results if ip and is_valid_public_ipv4(ip)}
    return new_ips

def main():
    # 初始化文件（清空）
    open(IPS_FILE, 'w').close()
    open(DOMAINS_FILE, 'w').close()

    # 1. 从 wetest.vip 获取最新 Cloudflare IP（覆盖写入）
    import subprocess
    try:
        result = subprocess.run([
            'curl', '-s', 'https://www.wetest.vip/page/cloudflare/address_v4.html'
        ], capture_output=True, text=True, check=True)
        ips = re.findall(r'([0-9]{1,3}\.){3}[0-9]{1,3}', result.stdout)
        valid_ips = [ip for ip in ips if is_valid_public_ipv4(ip)]
        save_lines(IPS_FILE, valid_ips)
        logging.info(f"Fetched {len(valid_ips)} Cloudflare IPs from wetest.vip")
    except Exception as e:
        logging.error(f"Failed to fetch IPs from wetest.vip: {e}")
        return

    # 2. 反查域名（仅本次结果）
    new_domains = fetch_all_domains(valid_ips)
    logging.info(f"Fetched {len(new_domains)} unique valid domains.")
    save_lines(DOMAINS_FILE, new_domains)

    # 3. DNS 解析（仅本次 IP，不保留历史）
    final_ips = perform_dns_lookups(new_domains)
    save_lines(IPS_FILE, final_ips)  # 覆盖原 IP 文件
    logging.info(f"Final IP count (from DNS): {len(final_ips)}")

if __name__ == '__main__':
    main()
