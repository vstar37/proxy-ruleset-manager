# sing-box-ruleset self-host manager  
**个人使用，请勿推广**

## 🧩功能概述  

本项目用于自托管并管理 sing-box 多格式规则集，具备以下核心功能：

✅ 多格式输入支持
	•	支持常见代理工具规则格式作为上游输入，包括：
	•	sing-box（原生 .srs, .json）
	•	Clash
	•	Surge
	•	Quantumult X (QX)
	•	Loon
	•	Little Snitch

🔄 规则统一与转换
	•	将主流规则格式统一转换为 sing-box 的规则集 Source Format。
	•	支持：
	•	✅ 规则格式标准化
	•	✅ 规则合并
	•	✅ 重复项去除
	•	✅ 格式校验

📤 多格式输出支持
	•	在转换为 sing-box 格式后，还可反向生成以下格式规则文件，方便多工具间通用：
	•	Clash 兼容格式
	•	Surge 规则文件
	•	Shadowrocket 规则集

🗂️ 输出文件结构
	•	转换后的规则文件会统一输出至 rule/ 目录中，包括：
	•	Sing-box 格式规则文件（.srs / .json）
	•	各平台反向导出规则文件（如 Clash, Surge 等）

🧰 配置模板支持
	•	预定义的配置文件模板保存在 template/ 目录中，可按需修改，快速生成适配的配置。

---

## 使用说明
使用者可自行 fork 本仓库，并在 `./source/xx.yaml` 中添加需要转换/管理的上游规则集链接，每日自动从上游更新构建。 

1. 在 `./source/xx.yaml` 中添加规则集源文件链接。  
2. 源文件链接需遵循 `geosite` , `geoip`与 `process` 进行分类。
4. 遵循 **仓库配置** 赋予 Action 读写权限，手动启动 Action，或者等待自动生成配置文件到 rule 文件夹下。

---

## **仓库配置**  
前往 **Settings** -> **Actions** -> **General** -> **Workflow permissions**，勾选：  
- **Read and write permissions**  

---

## **合并去重逻辑**  
1. **去重源文件链接**：同一 YAML 文件中重复的链接将被移除。  
2. **规则项去重**：同一链接内重复的规则项目将被过滤。  
3. **规则合并**：去重后的规则集将合并为单个 JSON 文件。  
4. **根据 `domain_suffix` 优化**：移除规则集中已被 `domain_suffix` 覆盖的 `domain` 条目。  

---

## **文件生成逻辑**  
- 根据 `./source/<文件名>.yaml` 中的设定生成 JSON 文件。  
- 输出的规则集文件命名遵循以下格式：  
   **`<分类>-<文件名>.json`**
  其中分类允许：geosite, geoip ,process

### 示例  
`./source/category-direct.yaml`  
```yaml
geosite:
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-media-cn.srs"
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-tencent@cn.srs"
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-google@cn.srs"
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-apple@cn.srs"
  - "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-microsoft@cn.srs"
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
  - "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-private.srs"
  - "https://raw.githubusercontent.com/peiyingyao/Rule-for-OCD/refs/heads/master/rule/Clash/SteamCN/SteamCN_OCD_Domain.yaml"
  - "https://raw.githubusercontent.com/peiyingyao/Rule-for-OCD/refs/heads/master/rule/Clash/Game/GameDownloadCN/GameDownloadCN_OCD_Domain.yaml"
  - "https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/games-cn.srs"

geoip:
  - "https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/cnip.srs"
  - "https://github.com/DustinWin/ruleset_geodata/releases/download/sing-box-ruleset/privateip.srs"
```

这样写会生成两个json文件: geosite-category-direct.json 和 geoip-category-direct.json 依此类推。


# 致谢（排名不分先后）

[@izumiChan16](https://github.com/izumiChan16)

[@ifaintad](https://github.com/ifaintad)

[@NobyDa](https://github.com/NobyDa)

[@blackmatrix7](https://github.com/blackmatrix7)

[@DivineEngine](https://github.com/DivineEngine)
