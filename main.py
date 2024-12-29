import configparser
import os
import json
import logging
import subprocess
import time
import yaml
import re
import concurrent.futures
from utils import *
from config import Config
from collections import defaultdict
import tempfile
import datetime


config = Config()


class RuleParser:
    def __init__(self):
        self.ls_index = 1
        self.generated_time = datetime.datetime.now().isoformat()


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

        # 初始化结果存储
        final_results = []

        # 处理 geosite
        if geosite_links:
            geosite_result = self.generate_json_file(geosite_links, geosite_file, rule_set_name)
            final_results.append(("geosite", geosite_result))

        # 处理 geoip
        if geoip_links:
            geoip_result = self.generate_json_file(geoip_links, geoip_file, rule_set_name)
            final_results.append(("geoip", geoip_result))

        # 处理 process
        if process_links:
            process_result = self.generate_json_file(process_links, process_file, rule_set_name)
            final_results.append(("process", process_result))

        # 输出最终处理结果
        logging.info(f"{rule_set_name} 规则整理完成:")
        for result_type, result_data in final_results:
            logging.info(
                f"类型: {result_type}\n"
                f"domain 被过滤掉的条目数量: {result_data['filtered_count']}\n"
                f"剩余规则总数: {result_data['total_rules']}\n"
                f"规则分析:\n"
                f"  domain 条目数: {result_data['domain_count']}\n"
                f"  domain_suffix 条目数: {result_data['domain_suffix_count']}\n"
                f"  ip_cidr 条目数: {result_data['ip_cidr_count']}\n"
                f"  process_name 条目数: {result_data['process_name_count']}\n"
                f"  domain_regex 条目数: {result_data['domain_regex_count']}\n"
                f"{'-' * 50}"
            )

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
        生成合并后的 JSON 文件并返回处理统计信息。
        """
        # 去重链接
        unique_links = list(set(links))

        json_file_list = []
        for link in unique_links:
            json_file = self.parse_link_file_to_json(link)
            json_file_list.append(json_file)

        # 如果只有一个 JSON 文件，直接保存，不调用 merge_json
        if len(json_file_list) == 1:
            single_file_stats = json_file_list[0]
            final_rules = single_file_stats

            # 统计信息
            filtered_count = single_file_stats.get("filtered_count", 0)
            domain_count = len(single_file_stats.get("domain", []))
            domain_suffix_count = len(single_file_stats.get("domain_suffix", []))
            ip_cidr_count = len(single_file_stats.get("ip_cidr", []))
            process_name_count = len(single_file_stats.get("process_name", []))
            domain_regex_count = len(single_file_stats.get("domain_regex", []))

            # 顶层信息
            wrapped_data = {
                "version": 1,
                "statistics": {
                    "filtered_count": filtered_count,
                    "total_rules": len(final_rules),
                    "domain_count": domain_count,
                    "domain_suffix_count": domain_suffix_count,
                    "ip_cidr_count": ip_cidr_count,
                    "process_name_count": process_name_count,
                    "domain_regex_count": domain_regex_count
                },
                "sing-box rule-set":
                {
                    "version": 1,
                    "rules": final_rules

                }
            }

            try:
                with open(output_file, 'w', encoding='utf-8') as file:
                    json.dump(wrapped_data.get("sing-box rule-set",[]), file, ensure_ascii=False, indent=4)
            except Exception as e:
                logging.error(f"保存 JSON 文件时出错: {e}")
                return {"error": str(e)}

            # 返回统计信息
            return wrapped_data["statistics"]
        # 否则调用 merge_json
        else:
            return self.merge_json(json_file_list, output_file, rule_set_name=rule_set_name)

    def merge_json(self, json_file_list, output_file, rule_set_name,
                   enable_trie_filtering=config.enable_trie_filtering):
        """
        合并 JSON 文件并返回规则统计信息。
        """
        logging.debug(f"正在合并 JSON 文件: {json_file_list}")

        # 初始化合并规则
        merged_rules = {
            "process_name": set(),
            "domain": set(),
            "domain_suffix": set(),
            "ip_cidr": set(),
            "domain_regex": set()
        }

        # 第一轮合并与去重
        for json_file in json_file_list:
            try:
                for rule in json_file.get("rules", []):
                    if isinstance(rule, dict):
                        for category, values in rule.items():
                            if category in merged_rules and values:
                                if isinstance(values, list):
                                    merged_rules[category].update(values)
                                elif isinstance(values, str):
                                    merged_rules[category].add(values)
            except Exception as e:
                logging.error(f"解析 JSON 数据时出错: {e}")

        # 基于 domain_suffix 的 Trie 去重
        original_domain_count = len(merged_rules.get("domain", set()))
        filtered_count = 0
        final_domains = set()

        if enable_trie_filtering and merged_rules.get("domain_suffix"):
            if merged_rules.get("domain"):
                final_domains, filtered_count = filter_domains_with_trie(
                    merged_rules["domain"], merged_rules["domain_suffix"]
                )
            else:
                final_domains = merged_rules.get("domain", set())
        else:
            final_domains = merged_rules.get("domain", set())

        # 更新合并后的 domain 规则
        merged_rules["domain"] = final_domains

        # 转换为最终规则列表
        final_rules = [
            {category: list(values)}
            for category, values in merged_rules.items()
            if values
        ]


        # 顶层信息
        wrapped_data = {
            "version": 1,
            "rule_set_name": rule_set_name,
            "description": f"Generated rules for {rule_set_name}",
            "generated_time": self.generated_time,
            "statistics": {
                "filtered_count": filtered_count,
                "total_rules": sum(len(values) for values in merged_rules.values()),
                "domain_count": len(merged_rules.get("domain", [])),
                "domain_suffix_count": len(merged_rules.get("domain_suffix", [])),
                "ip_cidr_count": len(merged_rules.get("ip_cidr", [])),
                "process_name_count": len(merged_rules.get("process_name", [])),
                "domain_regex_count": len(merged_rules.get("domain_regex", []))
            },
            "rules": final_rules
        }

        # 保存结果
        try:
            with open(output_file, 'w', encoding='utf-8') as file:
                json.dump(wrapped_data.get('rules',[]), file, ensure_ascii=False, indent=4)
        except Exception as e:
            logging.error(f"保存 JSON 文件时出错: {e}")

        # 返回统计信息
        return wrapped_data["statistics"]

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

    def process_category_files(self, directory):
        # 找到包含 category 的文件并按类别分组
        category_files = [f for f in os.listdir(directory) if "category" in f and f.endswith('.json')]
        grouped_files = defaultdict(list)

        # 按类别分组文件，例如 geoip-category-communitaion.json -> geoip-category-communitaion
        for file in category_files:
            base_name = file.split("@")[0].replace(".json", "")
            grouped_files[base_name].append(file)

        # 分别处理每一组文件
        for category, files in grouped_files.items():
            logging.info(f"处理类别：{category}")
            self.process_single_category(directory, category, files)

    def process_single_category(self, directory, category, files):
        # 分组文件
        general_files = [f for f in files if "@" not in f]
        non_cn_files = [f for f in files if "@!cn" in f]
        cn_files = [f for f in files if "@cn" in f]

        # 如果没有全体文件，跳过
        if not general_files:
            logging.info(f"跳过处理 {category}，因为没有全体文件")
            return

        # 加载全体文件
        general_file_path = os.path.join(directory, general_files[0])
        general_data = load_json(general_file_path).get("rules",[])

        # 如果同时有 @cn 和 @!cn 文件
        if cn_files and non_cn_files:
            # 优先处理非 cn 文件
            cn_path = os.path.join(directory, cn_files[0])
            non_cn_path = os.path.join(directory, non_cn_files[0])

            cn_data = load_json(cn_path).get("rules",[])

            # 从全体文件中剔除 cn 文件的规则，剩余部分保存到 非cn 文件
            updated_non_cn_data = subtract_rules(general_data, cn_data)

            # @!cn 文件已存在，增量更新.
            non_cn_data = load_json(non_cn_path).get("rules",[])
            updated_non_cn_data = merge_rules(non_cn_data, updated_non_cn_data)

            # !cn 增量更新，cn不变
            final_non_cn_data = updated_non_cn_data
            final_cn_data = cn_data

            final_non_cn_data = deduplicate_json(final_non_cn_data)
            final_non_cn_data = convert_sets_to_lists(final_non_cn_data)

            # 保存去重后的非cn文件
            save_json(final_non_cn_data, non_cn_path)
            save_json(final_cn_data, cn_path)

        # 只有 @cn 文件
        elif cn_files and not non_cn_files:
            cn_path = os.path.join(directory, cn_files[0])
            cn_data = load_json(cn_path).get("rules",[])

            # 从全体文件中剔除 cn 文件的规则，剩余部分保存到 非cn 文件
            non_cn_data = subtract_rules(general_data, cn_data)
            non_cn_path = os.path.join(directory, f"{category}@!cn.json")

            final_non_cn_data = non_cn_data  # 保存非cn数据
            final_cn_data = cn_data  # 保留原始的cn数据

            # 无须去重
            save_json(final_non_cn_data, non_cn_path)
            save_json(final_cn_data, cn_path)

        # 只有 @!cn 文件
        elif non_cn_files and not cn_files:
            non_cn_path = os.path.join(directory, non_cn_files[0])
            non_cn_data = load_json(non_cn_path).get("rules",[])

            # 从全体文件中剔除 非cn 文件的规则，更新 cn 文件
            cn_data = subtract_rules(general_data, non_cn_data)
            cn_path = os.path.join(directory, f"{category}@cn.json")

            final_non_cn_data = non_cn_data  # 保留原始的非cn数据
            final_cn_data = cn_data  # 更新后的cn数据

            # 无须去重
            save_json(final_non_cn_data, non_cn_path)
            save_json(final_cn_data, cn_path)

        else:
            logging.info(f"跳过处理 {category}，因为没有 @cn 或 @!cn 文件")
            return

        try:
            os.remove(general_file_path)
        except OSError as e:
            logging.error(f"删除全体文件 {general_files[0]} 失败: {e}")


    def main(self):
        source_directory = "./source"
        output_directory = "./rule"
        yaml_files = [f for f in os.listdir(source_directory) if f.endswith('.yaml')]

        for yaml_file in yaml_files:
            print('正在处理{}'.format(yaml_file))
            yaml_file_path = os.path.join(source_directory, yaml_file)
            self.parse_yaml_file(yaml_file_path, output_directory)

        # 生成 SRS 文件
        self.process_category_files(output_directory) # 拆分!cn规则 与 cn规则
        json_files = [f for f in os.listdir(output_directory) if f.endswith('.json')]
        for json_file in json_files:
            json_file_path = os.path.join(output_directory, json_file)
            srs_path = json_file_path.replace(".json", ".srs")
            os.system(f"sing-box rule-set compile --output {srs_path} {json_file_path}")
            logging.debug(f"成功生成 SRS 文件 {srs_path}")

class ConfigParser:
    def __init__(self):
        self.config = config

    def generate_singbox_route(self):
        # 固定字段
        fixed_rules = [
            {"inbound": ["tun-in", "mixed-in"], "action": "sniff", "timeout": "1s"},
            {"clash_mode": "Global", "action": "route", "outbound": "GLOBAL"},
            {"clash_mode": "Direct", "action": "route", "outbound": "Direct-Out"},
            {"type": "logical", "mode": "or", "rules": [{"protocol": "dns"}, {"port": 53}], "action": "hijack-dns"},
            {"port": 853, "network": "tcp", "action": "reject", "method": "default", "no_drop": False},
            {"port": 443, "network": "udp", "action": "reject", "method": "default", "no_drop": False}
        ]

        # 动态生成的规则
        rules = []
        rule_set = []

        for file in os.listdir('./rule'):
            if file.endswith('.srs'):
                tag = os.path.splitext(file)[0]
                # 添加规则集
                rule_set.append({
                    "tag": tag,
                    "type": "remote",
                    "format": "binary",
                    "url": f"https://raw.githubusercontent.com/vstar37/sing-box-ruleset/main/rule/{file}",
                    "download_detour": "VPN"
                })

                # 排除 fakeip 和 @cn规则
                if 'fakeip' in tag or 'geolocation-!cn' in tag or '@cn' in tag:
                    continue

                # 判断规则类型并生成相应的动作
                if 'blocker' in tag:
                    rules.append({"rule_set": [tag], "action": "reject", "method": "default", "no_drop": False})
                elif 'direct' in tag or '@cn' in tag:
                    rules.append({"rule_set": [tag], "action": "route", "outbound": "Direct-Out"})
                elif 'category' in tag:
                    outbound = self.determine_outbound(tag)
                    rules.append({"rule_set": [tag], "action": "route", "outbound": outbound})
                elif 'process' in tag:
                    match = re.search(r'process-filter-([^@]+)', tag)  # 匹配 'process-' 后的部分，直到遇到 '@'
                    if match:
                        process_tag = match.group(1)  # 提取的部分是 'communicationApp'
                        # 提取 'communication' 作为关键词
                        process_keyword = process_tag.lower().replace('app', '')  # 去掉 'App'，例如 'communicationApp' -> 'communication'
                        # 根据关键字确定outbound
                        outbound = self.determine_outbound(process_keyword)

                        # 将生成的规则添加到规则列表
                        rules.append({"rule_set": [tag], "action": "route", "outbound": outbound})
                elif 'geoip-geolocation' in tag:
                    match = re.search(r'geoip-geolocation-(\w+)', tag)  # 匹配 'geoip-geolocation-' 后的国家代码
                    if match:
                        country_code = match.group(1)  # 提取国家编号（如 jp）
                        outbound = self.determine_geolocation_outbound(country_code)  # 根据国家编号确定 outbound
                        rules.append({"rule_set": [tag], "action": "route", "outbound": outbound})

        # 合并 geosite 和 geoip 规则
        rules = self.merge_geosite_geoip_rules(rules)

        # 组合所有规则
        all_rules = fixed_rules + rules

        # 按规则分类排序
        all_rules = sorted(all_rules, key=self.rule_priority)

        route_config = {
            "route": {
                "rules": all_rules,
                "rule_set": rule_set,
                "auto_detect_interface": True,
                "final": "Others"
            }
        }

        # 写入带换行的紧凑 JSON
        with open('route.json', 'w') as f:
            json.dump(route_config, f, separators=(',', ':'), indent=2)

    def merge_geosite_geoip_rules(self, rules):
        """检查并合并 geosite 和 geoip 规则"""
        merged_rules = []
        seen_tags = set()

        for rule in rules:
            rule_set = rule.get('rule_set', [])
            if not rule_set:
                merged_rules.append(rule)
                continue

            tag = rule_set[0]
            if tag in seen_tags:
                continue

            # 尝试找出对应的 geosite 和 geoip 规则
            geosite_tag = tag.replace('geoip', 'geosite')
            geoip_tag = tag.replace('geosite', 'geoip')

            # 检查是否有相同的规则
            matching_rule = None
            for r in merged_rules:
                if geosite_tag in r.get('rule_set', []) or geoip_tag in r.get('rule_set', []):
                    matching_rule = r
                    break

            if matching_rule:
                # 如果有匹配的规则，将当前规则的 tags 合并
                matching_rule['rule_set'].extend(rule_set)
            else:
                # 没有匹配的规则，直接添加当前规则
                merged_rules.append(rule)

            seen_tags.add(tag)

        return merged_rules

    def determine_outbound(self, tag):
        # 根据tag关键字确定outbound
        if 'video' in tag:
            return "Video Service"
        if 'download' in tag:
            return "Download Service"
        if 'communication' in tag:
            return "Communication Service"
        if 'game' in tag:
            return "Game Service"
        if 'vpn' in tag:
            return "VPN"
        if 'media' in tag:
            return "Media Service"
        if 'nsfw' in tag:
            return "NSFW Content"
        if 'direct' in tag:
            return "Direct-Out"
        return "Direct-Out"

    def rule_priority(self, rule):
        # 定义规则的优先级
        if "inbound" in rule:
            return 0
        if "clash_mode" in rule:
            return 1
        if "type" in rule and rule["type"] == "logical":
            return 2
        if "port" in rule:
            return 3
        if "rule_set" in rule:
            if 'blocker' in rule["rule_set"][0] and 'process' not in rule["rule_set"][0]:
                return 4
            if 'geolocation' in rule["rule_set"][0]:
                return 5
            if '@cn' in rule["rule_set"][0]:
                return 6
            if 'category' in rule["rule_set"][0] and 'direct' not in rule["rule_set"][0]:
                return 7
            if 'direct' in rule["rule_set"][0] and 'process' not in rule["rule_set"][0]:
                return 8
            if 'process' in rule["rule_set"][0]:
                return 9
            return 10
        return 11

    def determine_geolocation_outbound(self, country_code):
        # 根据国家编号确定outbound
        geolocation_map = {
            'jp': 'JP Proxy',
            'us': 'US Proxy',
            'cn': 'CN Proxy',
            'uk': 'UK Proxy',
            # 可以添加更多国家映射
        }
        return geolocation_map.get(country_code, "Other")

if __name__ == "__main__":
    # 使用类的实例
    rule_parser = RuleParser()
    rule_parser.main()

    ConfigParser = ConfigParser()
    ConfigParser.generate_singbox_route()
