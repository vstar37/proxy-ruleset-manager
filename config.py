import logging
import os

class Config:
    def __init__(self):
        # 日志设置
        self.log_file = 'log.txt'
        if os.path.exists(self.log_file):
            open(self.log_file, 'w').close()  # 清空旧的日志内容

        logging.basicConfig(filename=self.log_file, level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        # 规则设置
        self.rule_dir = './rule'
        self.source_dir = './source'

        self.singbox_output_directory = os.path.join(self.rule_dir, 'singbox')
        self.surge_output_directory = os.path.join(self.rule_dir, 'surge')
        self.shadowrocket_output_directory = os.path.join(self.rule_dir, 'shadowrocket')
        self.clash_output_directory = os.path.join(self.rule_dir, 'clash')

        self.trust_upstream = False
        self.ls_index = 1
        self.enable_trie_filtering = [True, False][0] # 是否按照 domain_suffix 剔除重复的 domain
        self.ls_keyword = ["little-snitch", "adobe-blocklist"] # little snitch 链接关键字
        self.adg_keyword = ["adguard"] # adguard 链接关键字
        self.map_dict = {
            'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
            'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
            'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr', 'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip',
            'DST-PORT': 'port', 'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex", "PROCESS-NAME": "process_name"
        }
        self.MAP_REVERSE = {v: k for k, v in self.map_dict.items()}
        self.SINGBOX_TO_CLASH_MAP = {
                    "domain_suffix": "DOMAIN-SUFFIX",
                    "domain": "DOMAIN",
                    "domain_keyword": "DOMAIN-KEYWORD",
                    "domain_regex": "DOMAIN-REGEX",
                    "ip_cidr": "IP-CIDR",  # 注意：Clash 仅支持 IPv4，IPv6 可能需要特殊处理
                    "source_ip_cidr": "SRC-IP-CIDR",
                    "geoip": "GEOIP",
                    "port": "DST-PORT",
                    "source_port": "SRC-PORT",
                    "process_name": "PROCESS-NAME"
        }

        self.SINGBOX_TO_SURGE_MAP = {
                    "domain_suffix": "DOMAIN-SUFFIX",
                    "domain": "DOMAIN",
                    "domain_keyword": "DOMAIN-KEYWORD",
                    "domain_regex": "DOMAIN-REGEX",
                    "ip_cidr": "IP-CIDR",
                    "source_ip_cidr": "SRC-IP-CIDR",
                    "geoip": "GEOIP",
                    "port": "DST-PORT",
                    "source_port": "SRC-PORT",
                    "process_name": "PROCESS-NAME"
        }

