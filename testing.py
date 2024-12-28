import re

def match_suffix_with_regex(domain, domain_suffix):
    """
    根据 domain_suffix 和正则表达式，剔除与后缀匹配的域名。
    """
    for suffix in domain_suffix:
        if re.search(suffix, domain):
            return False  # 如果域名包含了某个后缀，返回 False，表示该域名应该被剔除
    return True  # 如果域名不包含任何后缀，返回 True，表示该域名有效

def test_domain_suffix(domains, domain_suffix):
    """
    测试域名后缀剔除
    """
    # 对每个域名进行过滤
    filtered_domains = [domain for domain in domains if match_suffix_with_regex(domain, domain_suffix)]
    return filtered_domains

# 示例数据
domains = [
    "a3.mzstatic.com",
    "cdn.apple-mapkit.com",
    "cl1.apple.com",
    "chatgpt-async-webps-prod- -1234.webpubsub.azure.com",
    "azchcdnz.com",
    "cl1-cdn.origin-apple.com.akadns.net"
]

domain_suffix = [
    "\.apple\.com$",  # 以 .apple.com 结尾的域名
    "\.azure\.com$",  # 以 .azure.com 结尾的域名
    "\.mzstatic\.com$"  # 以 .mzstatic.com 结尾的域名
]

# 测试域名后缀过滤
filtered_domains = test_domain_suffix(domains, domain_suffix)
print("Filtered domains:", filtered_domains)