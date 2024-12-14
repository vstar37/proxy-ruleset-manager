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

        # manual
        self.ls_index = 1
        self.ls_keyword = ["little-snitch", "adobe-blocklist"]
        self.map_dict = {
            'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
            'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword', 'IP-CIDR': 'ip_cidr',
            'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr', 'SRC-IP-CIDR': 'source_ip_cidr', 'GEOIP': 'geoip',
            'DST-PORT': 'port', 'SRC-PORT': 'source_port', "URL-REGEX": "domain_regex", "DOMAIN-REGEX": "domain_regex"
        }