# sing-box-ruleset self-host manager  
**个人使用，请勿推广**

## 功能概述  
本仓库用于自托管 sing-box 规则集，适合用于定制自己的规则集，有**规则转换，规则合并，规则去重**功能。
根据 **给定的上游规则文件链接**，自动对规则进行批处理合并和去重，生成 **sing-box** 支持的 **Source Format** 文件，与便于检查的 **json** 文件到 rule 文件夹下。  
输入的上游文件链接格式支持sing-box 原生规则 `srs`、`json` 及其他工具 (Clash, Loon, QX, Surge, Little Snitch)规则文件。  
使用者可自行 fork 本仓库，并在 `./source/xx.yaml` 中添加需要转换的上游规则集链接，每日自动从上游更新构建。  

---

## 使用说明  
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
