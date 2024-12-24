import os
import json
import logging
import subprocess
import time
import yaml
import concurrent.futures
from utils import *
from config import Config
import tempfile


config = Config()


class RuleParser:
    def __init__(self):
        self.ls_index = 1

    def parse_adguard_file(self, link):
        """
        处理 AdGuard 链接并返回解析后的 JSON 数据。
        """
        try:
            logging.debug(f"正在处理 AdGuard 链接: {link}")

            # 第一步：获取 AdGuard 规则文件
            response = requests.get(link)
            response.raise_for_status()

            raw_data = response.text
            logging.debug(f"获取到的原始数据: {raw_data[:500]}")  # 打印前 500 个字符

            # 创建临时目录
            tmp_dir = tempfile.mkdtemp()
            logging.debug(f"创建临时目录: {tmp_dir}")

            # 将原始数据写入临时文件，并检查第一行是否为 '[Adblock Plus 2.0]'
            adguard_file_path = os.path.join(tmp_dir, "adguard_file.txt")
            with open(adguard_file_path, "w") as f:
                lines = raw_data.splitlines()  # 按行分割原始数据
                if lines and lines[0].startswith("["):  # 如果第一行以 "[" 开头
                    lines[0] = "!" + lines[0]  # 在第一行加上 "!"
                # 将修改后的内容写回文件
                f.write("\n".join(lines))

            # 第二步：使用 sing-box 进行转换为 srs 格式
            srs_file_path = os.path.join(tmp_dir, "output.srs")
            conversion_command = [
                "sing-box", "rule-set", "convert", "--type", "adguard",
                "--output", srs_file_path, adguard_file_path
            ]
            logging.debug(f"执行转换命令: {' '.join(conversion_command)}")

            result = subprocess.run(conversion_command, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"转换命令失败，错误信息: {result.stderr}")
                return None

            # 确认 .srs 文件已经生成
            if not os.path.exists(srs_file_path):
                logging.error(f"转换失败，没有找到生成的 SRS 文件: {srs_file_path}")
                return None

            # 第三步：使用 sing-box 反编译 srs 文件为 JSON 数据 (暂不支持)
            decompile_command = [
                "sing-box", "rule-set", "decompile", srs_file_path
            ]
            logging.debug(f"执行反编译命令: {' '.join(decompile_command)}")

            result = subprocess.run(decompile_command, capture_output=True, text=True)
            if result.returncode != 0:
                logging.error(f"反编译命令失败，错误信息: {result.stderr}")
                return None

            # 解析返回的 JSON 数据
            try:
                data = json.loads(result.stdout)
                logging.debug(f"解析后的 JSON 数据: {data}")
            except json.JSONDecodeError as e:
                logging.error(f"JSON 解析失败: {e}")
                return None

            # 清理临时文件
            os.remove(adguard_file_path)
            os.remove(srs_file_path)
            os.rmdir(tmp_dir)  # 删除临时目录

            return data

        except Exception as e:
            logging.error(f"处理 AdGuard 链接 {link} 时出错: {e}")
            return None

    def parse_littlesnitch_file(self, link, retries=3, delay=5):
        """
        处理 Little Snitch 链接并返回解析后的 JSON 数据。
        """
        try:
            logging.debug(f"正在处理 Little Snitch 链接: {link}")

            for attempt in range(retries):
                try:
                    response = requests.get(link)
                    response.raise_for_status()  # 如果请求失败，抛出异常
                    break  # 请求成功，退出循环
                except requests.exceptions.RequestException as e:
                    logging.error(f"请求失败: {e}")
                    if attempt < retries - 1:  # 如果不是最后一次尝试
                        # logging.info(f"等待 {delay} 秒后重试...")
                        time.sleep(delay)  # 等待一段时间再重试
                    else:
                        logging.error(f"已达到最大重试次数 ({retries})，停止请求。")
                        return None

            raw_data = response.text
            logging.debug(f"获取到的原始数据: {raw_data[:500]}")  # 打印前 500 个字符

            # 清理数据
            cleaned_raw_data = clean_json_data(raw_data)
            logging.debug(f"清理后的数据: {cleaned_raw_data[:500]}")

            # 解析 JSON 数据
            data = json.loads(cleaned_raw_data)
            logging.debug(f"解析后的 JSON 数据: {data}")

            # 获取被拒绝的域名
            denied_domains = data.get("denied-remote-domains", [])
            cleaned_denied_domains = clean_denied_domains(denied_domains)

            # 检查是否找到了有效的拒绝域名数据
            if not (cleaned_denied_domains["domain"] or cleaned_denied_domains["domain_suffix"]):
                logging.warning(f"从 {link} 未找到 'denied-remote-domains' 数据")
                return None

            # 准备输出数据
            output_data = {
                "rules": [
                    {
                        "domain": cleaned_denied_domains["domain"],
                        "domain_suffix": cleaned_denied_domains["domain_suffix"]
                    }
                ],
                "version": 1
            }

            logging.debug(f"成功解析链接 {link}，生成 JSON 数据")
            return output_data

        except json.JSONDecodeError:
            logging.error(f"解析 JSON 时出错，从链接 {link} 读取的内容可能不是有效的 JSON。")
            return None
        except Exception as e:
            logging.error(f"处理链接 {link} 时发生未知错误：{e}")
            return None

    def parse_yaml_file(self, yaml_file, output_directory):
        """
        解析 YAML 文件中的链接，并根据类别生成相应的 JSON 文件。
        """
        with open(yaml_file, 'r') as file:
            data = yaml.safe_load(file)
            logging.debug(f"解析的 YAML 数据: {data}")

        # 按类别存储链接
        geosite_links = data.get('geosite', [])
        geoip_links = data.get('geoip', [])
        process_links = data.get('process', [])

        # 定义生成文件的路径
        rule_set_name = os.path.basename(yaml_file).split('.')[0]
        geosite_file = os.path.join(output_directory, f"geosite-{rule_set_name}.json")
        geoip_file = os.path.join(output_directory, f"geoip-{rule_set_name}.json")
        process_file = os.path.join(output_directory, f"process-{rule_set_name}.json")

        # 检查每个类别的链接是否为空，若为空则跳过文件生成
        if geosite_links:
            self.generate_json_file(geosite_links, geosite_file, rule_set_name)

        if geoip_links:
            self.generate_json_file(geoip_links, geoip_file, rule_set_name)

        if process_links:
            self.generate_json_file(process_links, process_file, rule_set_name)


    def download_srs_file(self, url):
        """
        下载 .srs 文件到临时目录。
        """
        try:
            # 创建临时目录
            tmp_dir = tempfile.mkdtemp()
            srs_file_path = os.path.join(tmp_dir, os.path.basename(url))

            # 下载文件
            response = requests.get(url)
            response.raise_for_status()  # 确保请求成功
            with open(srs_file_path, 'wb') as file:
                file.write(response.content)

            # logging.info(f"成功下载 {url} 到 {srs_file_path}")
            return srs_file_path

        except Exception as e:
            logging.error(f"下载 {url} 时出错: {e}")
            return None

    def download_and_parse_json(self, json_file_url):
        """
        下载远程 JSON 文件到临时目录，并解析为 JSON 数据。
        """
        try:
            # logging.info(f"正在下载远程 JSON 文件: {json_file_url}")

            # 创建临时文件用于存储下载的 JSON 文件
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
                response = requests.get(json_file_url, stream=True)
                response.raise_for_status()  # 检查请求是否成功
                for chunk in response.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
                tmp_file_path = tmp_file.name  # 获取临时文件路径

            # logging.info(f"JSON 文件下载成功，临时路径: {tmp_file_path}")

            # 读取临时 JSON 文件
            with open(tmp_file_path, 'r', encoding='utf-8') as file:
                json_data = json.load(file)

            # 清理临时文件
            os.remove(tmp_file_path)
            # logging.info(f"已清理临时文件: {tmp_file_path}")

            return json_data

        except requests.exceptions.RequestException as e:
            logging.error(f"下载 JSON 文件失败: {json_file_url}, 错误: {e}")
        except json.JSONDecodeError as e:
            logging.error(f"解析 JSON 文件失败: {json_file_url}, 错误: {e}")
        except Exception as e:
            logging.error(f"处理 JSON 文件时出现未知错误: {e}")

        return None

    def generate_json_file(self, links, output_file, rule_set_name):
        """
        生成合并后的 JSON 文件
        """
        unique_links = list(set(links))  # 链接去重

        json_file_list = []
        for link in unique_links:
            json_file = self.parse_link_file_to_json(link)
            json_file_list.append(json_file)

        return self.merge_json(json_file_list, output_file, rule_set_name = rule_set_name)

    def merge_json(self, json_file_list, output_file, rule_set_name, enable_trie_filtering=config.enable_trie_filtering):
        """
        合并 JSON 文件并进行去重（第二轮 Trie 去重为可选）。

        :param json_file_list: 输入的 JSON 文件数据列表
        :param output_file: 输出合并后的 JSON 文件路径
        :param enable_trie_filtering: 是否启用基于 domain_suffix 的 Trie 去重，默认禁用
        """
        logging.debug(f"正在合并 JSON 文件: {json_file_list}")

        # 初始化合并规则，使用集合去重
        merged_rules = {
            "process_name": set(),
            "domain": set(),
            "domain_suffix": set(),
            "ip_cidr": set(),
            "domain_regex": set()  # 新增 domain_regex 字段
        }

        # 第一轮合并与去重
        for json_file in json_file_list:
            try:
                logging.debug(f"正在处理数据: {json_file}")
                for rule in json_file.get("rules", []):
                    if isinstance(rule, dict):
                        for category, values in rule.items():
                            if category in merged_rules and values:
                                # 确保 values 是列表，避免将字符串拆分成单个字符
                                if isinstance(values, list):
                                    merged_rules[category].update(values)
                                elif isinstance(values, str):  # 如果是字符串，视作单个域名
                                    merged_rules[category].add(values)
                                else:
                                    logging.warning(f"跳过无效的 {category} 值: {values}")
            except Exception as e:
                logging.error(f"解析 JSON 数据时出错: {e}")

        # 第二轮去重：基于 domain_suffix 使用 Trie 去除被覆盖的 domain（可选）
        original_domain_count = len(merged_rules.get("domain", set()))
        filtered_count = 0
        final_domains = set()

        if enable_trie_filtering:
            # logging.info("启用基于 domain_suffix 的 Trie 去重。")
            if merged_rules.get("domain_suffix"):
                if merged_rules.get("domain"):
                    final_domains, filtered_count = filter_domains_with_trie(
                        merged_rules["domain"], merged_rules["domain_suffix"]
                    )
            else:
                final_domains = merged_rules.get("domain", set())
        else:
            # logging.info("跳过基于 domain_suffix 的 Trie 去重。")
            final_domains = merged_rules.get("domain", set())

        # 更新合并后的 domain 规则
        merged_rules["domain"] = final_domains

        # 将合并后的规则从集合转换回列表
        final_rules = [
            {category: list(values)}
            for category, values in merged_rules.items()
            if values
        ]

        if enable_trie_filtering > 0:
            # 输出去重后统计信息
            logging.info(f"{rule_set_name} 规则整理完成，domain 被过滤掉的条目数量: {filtered_count}. 剩余规则总数: {len(merged_rules['domain'])+len(merged_rules['domain_suffix'])+len(merged_rules['ip_cidr'])+len(merged_rules['domain_suffix'])+len(merged_rules['domain_regex'])}")

        # 保存结果
        try:
            with open(output_file, 'w', encoding='utf-8') as file:
                json.dump({"version": 1, "rules": final_rules}, file, ensure_ascii=False, indent=4)
                # logging.info(f"合并后的规则已保存至: {output_file}")
        except Exception as e:
            logging.error(f"保存 JSON 文件时出错: {e}")

    def decompile_srs_to_json(self, srs_file_url):
        """
        处理远程 .srs 文件，下载并使用 sing-box 的 decompile 命令转换为 JSON 文件。
        """
        try:
            # 下载 .srs 文件到临时目录
            srs_file = self.download_srs_file(srs_file_url)
            if not srs_file:
                logging.error(f"下载 .srs 文件失败: {srs_file_url}")
                return None

            # 解编译 SRS 文件为 JSON
            output_json_path = srs_file.replace(".srs", ".json")
            os.system(f"sing-box rule-set decompile --output {output_json_path} {srs_file}")
            # logging.info(f"成功将 SRS 文件 {srs_file} 解编译为 JSON 文件 {output_json_path}")

            # 读取解编译后的 JSON 文件并返回
            with open(output_json_path, 'r', encoding='utf-8') as file:
                json_data = json.load(file)

            # 清理临时文件
            os.remove(srs_file)
            os.remove(output_json_path)

            return json_data

        except Exception as e:
            logging.error(f"处理 SRS 文件 {srs_file_url} 时出错: {e}")
            return None

        except Exception as e:
            logging.error(f"处理 SRS 文件 {srs_file_url} 时出错: {e}")
            return None

    def parse_link_file_to_json(self, link):
        """
        解析给定的链接并返回处理后的 JSON 数据。
        """
        try:
            # logging.info(f"正在解析链接: {link}")

            if link.endswith('.json'):
                logging.debug(f"检测到 JSON 文件 {link}，直接返回内容")
                return self.download_and_parse_json(link)

            if link.endswith('.srs'):
                logging.debug(f"检测到 SRS 文件 {link}，正在进行解编译处理")
                json_file = self.decompile_srs_to_json(link)
                return json_file

            if any(keyword in link for keyword in config.ls_keyword):
                json_file = self.parse_littlesnitch_file(link)
                return json_file

            if any(keyword in link for keyword in config.adg_keyword):
                json_file = self.parse_adguard_file(link)
                return json_file

            with concurrent.futures.ThreadPoolExecutor() as executor:
                results = list(executor.map(parse_and_convert_to_dataframe, [link]))
                dfs = [df for df, rules in results]
                rules_list = [rules for df, rules in results]
                df = pd.concat(dfs, ignore_index=True)

            logging.debug(f"生成的 DataFrame: {df.head()}")
            df = df[~df['pattern'].str.contains('IP-CIDR6')].reset_index(drop=True)
            df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
            df = df[df['pattern'].isin(config.map_dict.keys())].reset_index(drop=True)
            df = df.drop_duplicates().reset_index(drop=True)
            df['pattern'] = df['pattern'].replace(config.map_dict)

            result_rules = {"version": 1, "rules": []}
            domain_entries = []
            for pattern, addresses in df.groupby('pattern')['address'].apply(list).to_dict().items():
                if pattern == 'domain_suffix':
                    rule_entry = {pattern: [address.strip() for address in addresses]}
                    result_rules["rules"].append(rule_entry)
                elif pattern == 'domain':
                    domain_entries.extend([address.strip() for address in addresses])
                else:
                    rule_entry = {pattern: [address.strip() for address in addresses]}
                    result_rules["rules"].append(rule_entry)

            domain_entries = list(set(domain_entries))
            if domain_entries:
                result_rules["rules"].insert(0, {'domain': domain_entries})

            logging.debug(f"生成的 JSON 数据: {result_rules}")
            return result_rules

        except Exception as e:
            logging.error(f"解析链接 {link} 出现错误: {e}")
            return None

    def main(self):
        source_directory = "./source"
        output_directory = "./rule"
        yaml_files = [f for f in os.listdir(source_directory) if f.endswith('.yaml')]

        for yaml_file in yaml_files:
            print('正在处理{}'.format(yaml_file))
            yaml_file_path = os.path.join(source_directory, yaml_file)
            self.parse_yaml_file(yaml_file_path, output_directory)

        # 生成 SRS 文件
        json_files = [f for f in os.listdir(output_directory) if f.endswith('.json')]
        for json_file in json_files:
            json_file_path = os.path.join(output_directory, json_file)
            srs_path = json_file_path.replace(".json", ".srs")
            os.system(f"sing-box rule-set compile --output {srs_path} {json_file_path}")
            logging.debug(f"成功生成 SRS 文件 {srs_path}")


if __name__ == "__main__":
    # 使用类的实例
    rule_parser = RuleParser()
    rule_parser.main()