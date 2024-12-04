import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

def get_top_ips():
    # 设置无头浏览器
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')  # 不显示浏览器界面
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

    # 启动浏览器
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

    # 打开目标网页
    driver.get('https://www.wetest.vip/page/cloudflare/address_v4.html')

    # 等待页面加载完成
    time.sleep(5)

    # 获取第四列数据（去掉 kB/s 后缀）
    columns = driver.find_elements(By.XPATH, '//table/tbody/tr/td[4]')
    values = []

    # 提取数字并去掉 kB/s 后缀
    for col in columns:
        value = col.text.replace('kB/s', '').strip()
        try:
            values.append(float(value))
        except ValueError:
            values.append(0)  # 如果无法转换为数字，记为0

    # 获取对应 IP 地址的列数据
    ip_column = driver.find_elements(By.XPATH, '//table/tbody/tr/td[2]')

    # 将数据和 IP 地址打包在一起，按数据大小排序
    data_ip_pairs = [(value, ip_column[i].text) for i, value in enumerate(values)]
    sorted_data_ip_pairs = sorted(data_ip_pairs, reverse=True, key=lambda x: x[0])

    # 取前三大的 IP 地址
    top_ips = [ip for _, ip in sorted_data_ip_pairs[:3]]

    # 打印前三大的 IP 地址
    print("Top 3 IPs:")
    for ip in top_ips:
        print(ip)

    # 将前三个 IP 地址保存到 Get-IP.txt 文件
    with open('Get-IP.txt', 'w') as file:
        for ip in top_ips:
            file.write(f"{ip}\n")

    driver.quit()

if __name__ == '__main__':
    get_top_ips()
