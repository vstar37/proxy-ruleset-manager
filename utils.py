# utils.py

import requests
import json
import re
import ipaddress
import pandas as pd
import yaml
import logging
import os

from config import Config
config = Config()


def merge_rules(existing_data, new_data):
    """
    合并两个规则集，不进行去重。
    如果传入的数据是列表，则直接合并。
    如果传入的数据是字典，按字段进行合并。
    """
    # 如果输入数据是列表，直接合并
    if isinstance(existing_data, list) and isinstance(new_data, list):
        return existing_data + new_data

    # 否则，按字段进行合并
    merged_data = {
        "process_name": (existing_data.get("process_name", []) if isinstance(existing_data, dict) else [])
                        + (new_data.get("process_name", []) if isinstance(new_data, dict) else []),
        "domain": (existing_data.get("domain", []) if isinstance(existing_data, dict) else [])
                  + (new_data.get("domain", []) if isinstance(new_data, dict) else []),
        "domain_suffix": (existing_data.get("domain_suffix", []) if isinstance(existing_data, dict) else [])
                         + (new_data.get("domain_suffix", []) if isinstance(new_data, dict) else []),
        "ip_cidr": (existing_data.get("ip_cidr", []) if isinstance(existing_data, dict) else [])
                   + (new_data.get("ip_cidr", []) if isinstance(new_data, dict) else []),
        "domain_regex": (existing_data.get("domain_regex", []) if isinstance(existing_data, dict) else [])
                         + (new_data.get("domain_regex", []) if isinstance(new_data, dict) else [])
    }
    return merged_data

def read_yaml_from_url(url):
    response = requests.get(url)
    response.raise_for_status()
    yaml_data = yaml.safe_load(response.text)
    # logging.info(f"成功读取 YAML 数据 {url}")
    return yaml_data


def read_list_from_url(url):
    try:
        df = pd.read_csv(url, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'])
        # logging.info(f"成功读取列表数据 {url}")
    except Exception as e:
        logging.error(f"读取 {url} 时出错：{e}")
        return pd.DataFrame(), []

    filtered_rows = []
    rules = []

    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {"type": "logical", "mode": "and", "rules": []}
            pattern = ",".join(row.values.astype(str))
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                for keyword in config.MAP_DICT.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({config.MAP_DICT[keyword]: value})
            rules.append(rule)
    for index, row in df.iterrows():
        if 'AND' not in row['pattern']:
            filtered_rows.append(row)
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules


def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None


def clean_json_data(data):
    """清洗 JSON 数据，移除末尾多余的逗号。"""
    cleaned_data = re.sub(r',\s*]', ']', data)  # 处理数组末尾的逗号
    cleaned_data = re.sub(r',\s*}', '}', cleaned_data)  # 处理对象末尾的逗号
    return cleaned_data


def clean_denied_domains(domains):
    """清洗 denied-remote-domains 列表中的域名并分类。"""
    cleaned_domains = {
        "domain": [],
        "domain_suffix": []
    }

    for domain in domains:
        domain = domain.strip()  # 去除前后空格
        if domain:  # 确保域名不为空
            parts = domain.split('.')
            # 判断是否为没有子域名的域名
            if len(parts) == 2:  # 例如 "0512s.com"
                cleaned_domains["domain"].append(domain)
                cleaned_domains["domain_suffix"].append("." + domain)  # 将带点的形式添加到 domain_suffix
            elif len(parts) > 2:  # 例如 "counter.packa2.cz"
                cleaned_domains["domain"].append(domain)

    return cleaned_domains


def parse_and_convert_to_dataframe(link):
    rules = []
    try:
        if link.endswith('.yaml') or link.endswith('.txt'):
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                line_content = lines[0]
                items = line_content.split()
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address[1:]
                            if address.startswith('.'):
                                address = address[1:]
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)
                if pattern == "IP-CIDR" and "no-resolve" in address:
                    address = address.split(',', 1)[0]
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        else:
            df, rules = read_list_from_url(link)
    except Exception as e:
        logging.error(f"解析 {link} 时出错：{e}")
        return pd.DataFrame(), []

    # logging.info(f"成功解析链接 {link}")
    return df, rules


def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj


def make_hashable(item):
    """递归地将可变类型（如列表）转换为元组，以便它们可以添加到集合中"""
    if isinstance(item, dict):
        # 如果是字典，将其转换为元组
        return tuple((key, make_hashable(value)) for key, value in item.items())
    elif isinstance(item, list):
        # 如果是列表，将每个元素递归转换为元组
        return tuple(make_hashable(i) for i in item)
    else:
        # 如果是其他不可变类型，直接返回
        return item


def subtract_rules(base_data, subtract_data):
    """从 base_data 中剔除 subtract_data 的规则，并且加入步骤以保存数据"""

    # 1. 保存 subtract_data 中的条目到 saved_data
    saved_data = {
        "process_name": [],
        "domain": [],
        "domain_suffix": [],
        "ip_cidr": [],
        "domain_regex": []
    }

    # 收集 subtract_data 中的条目
    for key in saved_data.keys():
        # 将 subtract_data 中的对应规则添加到 saved_data
        for rule in subtract_data:
            if isinstance(rule, dict) and key in rule:
                saved_data[key].extend(rule[key])

    # 2. 合并 base_data 和 subtract_data
    merged_data = merge_rules(base_data, subtract_data)
    # 3. 调用 deduplicate_json 去重
    deduplicated_data = deduplicate_json(merged_data)

    # 4. 从去重后的数据中剔除 saved_data 中的条目
    for key in saved_data.keys():
        if saved_data[key]:
            for item in deduplicated_data:
                if isinstance(item, dict) and key in item:
                    item[key] = [val for val in item[key] if val not in saved_data[key]]

    # 返回最终处理后的数据
    return deduplicated_data

def load_json(filepath):
    """加载 JSON 文件"""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(data, filepath):
    """保存 JSON 文件"""
    try:
        # 假设 data 已经是一个包含规则的列表，如：{"domain": [...]}, {"ip_cidr": [...]}, ...
        result = {
            "version": 1,
            "rules": data
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=4)
    except Exception as e:
        logging.error(f"保存 JSON 文件时出错: {e}")

def deduplicate_json(data):
    """
    对输入的 JSON 数据进行三轮去重操作：
    1. 第一轮去重：检查 process_name, domain, domain_suffix, ip_cidr, domain_regex 中是否有完全一致的条目。
    2. 第二轮去重：使用 domain_regex 清洗 domain 和 domain_suffix。
    3. 第三轮去重：使用 domain_suffix 去重 domain，基于 Trie 进行去重。
    """

    # 第一轮去重：初始化合并规则
    merged_rules = {
        "process_name": set(),
        "domain": set(),
        "domain_suffix": set(),
        "ip_cidr": set(),
        "domain_regex": set()
    }

    # 遍历输入列表，逐一合并规则
    for rule in data:
        if isinstance(rule, dict):  # 确保条目是字典
            for category, values in rule.items():
                if category in merged_rules:
                    if isinstance(values, list):
                        merged_rules[category].update(values)
                    elif isinstance(values, str):
                        merged_rules[category].add(values)

    # 第二轮去重：使用 domain_regex 清洗 domain 和 domain_suffix
    final_domains = merged_rules["domain"].copy()
    domain_suffix = merged_rules["domain_suffix"]
    domain_regex = merged_rules["domain_regex"]

    # 用 domain_regex 去重 domain 和 domain_suffix
    if domain_regex:
        # 清洗 domain
        for regex in domain_regex:
            final_domains = {domain for domain in final_domains if not match_domain_regex(domain, regex)}

        # 清洗 domain_suffix
        for regex in domain_regex:
            domain_suffix = {suffix for suffix in domain_suffix if not match_domain_suffix_regex(suffix, regex)}

    merged_rules["domain"] = final_domains
    merged_rules["domain_suffix"] = domain_suffix

    # 第三轮去重：使用 Trie 对 domain_suffix 去重，并清洗 domain
    final_domains, _ = filter_domains_with_trie(merged_rules["domain"], merged_rules["domain_suffix"])
    merged_rules["domain"] = final_domains

    # 构造最终的输出列表
    final_rules = []
    for category, values in merged_rules.items():
        if values:
            final_rules.append({category: list(values)})

    return final_rules

def convert_sets_to_lists(data):
    """递归地将字典中的所有 set 转换为 list"""
    if isinstance(data, dict):
        return {key: convert_sets_to_lists(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_sets_to_lists(item) for item in data]
    elif isinstance(data, set):
        return list(data)
    else:
        return data

def match_domain_regex(domain, regex):
    """
    根据 domain 和 domain_regex 判断是否匹配
    假设这里是简单的正则匹配，你可以根据实际情况调整
    """
    return bool(re.search(regex, domain))


def match_domain_suffix_regex(suffix, regex):
    """
    用于匹配 domain_suffix 的正则表达式，确保是匹配后缀
    """
    return bool(re.match(f"^{regex}$", suffix))


# json去重算法
class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False

class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, suffix):
        """ 插入 domain_suffix，确保不包含前导 . """
        suffix = suffix.lstrip('.')
        node = self.root
        for char in reversed(suffix):  # 倒序插入，方便匹配后缀
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end = True

    def has_suffix(self, domain):
        """ 检查 domain 是否匹配某个完整的 domain_suffix """
        node = self.root
        domain = '.' + domain  # 加入前导点进行后缀匹配

        # 从尾部倒序遍历 domain
        for i in range(len(domain)):
            char = domain[-(i + 1)]
            if node.is_end and i != 0:  # 如果已经匹配到后缀，且 i != 0，代表匹配到完整后缀
                # 确保匹配的后缀是完整的二级域名
                if i == len(domain) - 1:  # 完全匹配
                    return True
                elif domain[-(i + 1)] == '.':  # 确保后缀结束在域名边界
                    return True
                else:
                    return False  # 如果有更多字符，且未结束，说明匹配是部分的
            if char not in node.children:
                return False
            node = node.children[char]

        # 完全匹配一个后缀时，结束条件
        return node.is_end

def filter_domains_with_trie(domains, domain_suffixes):
    """
    使用 Trie 过滤掉被 domain_suffix 覆盖的 domain。
    :param domains: 需要去重的 domain 集合
    :param domain_suffixes: domain_suffix 集合
    :return: 过滤后的 domains 和被过滤的数量
    """
    trie = Trie()

    # 统一插入 domain_suffix，去除前导 .
    for suffix in domain_suffixes:
        trie.insert(suffix)

    filtered_domains = set()  # 存储未被匹配的域名
    filtered_count = 0

    for domain in domains:
        if trie.has_suffix(domain):
            filtered_count += 1  # 被过滤的数量增加
        else:
            filtered_domains.add(domain)  # 将没有匹配到后缀的域名保留

    return filtered_domains, filtered_count

'''# 测试数据
domains = ["xp.apple.com", "example.com", "xp.apple"]
domain_suffixes = ["apple"]

final_domains, filtered_count = filter_domains_with_trie(domains, domain_suffixes)

print(f"过滤后的 domains: {final_domains}")
print(f"被过滤的数量: {filtered_count}")
'''
