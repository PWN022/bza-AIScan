# DirAI-BZA - AI辅助路径扫描器
DirAI-BZA是一个智能的Web路径扫描工具，结合传统字典扫描与大模型AI推理能力，帮助安全研究人员和渗透测试工程师更高效地发现Web应用中的隐藏路径、敏感文件和安全风险。
## 免责声明
请仅对您拥有合法授权或自己拥有的目标进行扫描。未经授权的扫描可能违反法律法规。使用本工具造成的任何后果由使用者自行承担。
## 主要特性
- 智能路径发现：字典扫描+AI推理双引擎，发现常规字典遗漏的路径
- 框架自动识别：支持Java Spring Boot、PHP、Node.js、Python、.NET等主流框架
- JS路径提取：从JavaScript 文件中自动提取API端点、资源路径
- 敏感信息扫描：自动识别硬编码密钥、密码、Token、数据库连接串等
- HTML可视化报告：生成HTML报告，按风险等级分类展示
- 高性能并发：支持多线程并发扫描，可配置线程数
- 断点续扫：扫描中断后可继续，无需重新开始
- Playwright抓包：使用浏览器自动捕获所有网络请求

## 安装与配置

克隆项目并安装依赖，如需使用AI功能则配置API Key：

Linux/macOS:
```bash
git clone https://github.com/PWN022/DirAI-BzA.git
cd DirAI-BzA
pip install -r requirements.txt
pip install -e .
cp .env.example .env
```

Windows:
```bash
git clone https://github.com/PWN022/DirAI-BzA.git
cd DirAI-BzA
pip install -r requirements.txt
pip install -e .
copy .env.example .env
```

编辑.env文件，填入你的API Key：

```
OPENAI_API_KEY=sk-xxxxxxxxxxxx
OPENAI_BASE_URL=https://api.deepseek.com/v1
AI_MODEL=deepseek-**chat**
```

## 快速开始

基础扫描：

```
dirai scan -u https://example.com/
```

使用AI辅助扫描：

```
dirai scan -u https://example.com/ --ai
```

指定并发线程数：

```
dirai scan -u https://example.com/ --workers 20
```

完整示例：

```
dirai scan -u https://example.com/ --workers 20 --timeout 3 --ai
```

## 命令说明

### scan - 完整扫描

自动执行：框架识别 -> 目录扫描 -> JS提取 -> 敏感信息扫描 -> HTML报告

```
dirai scan -u <url> [options]
```

|      参数      |     说明      |            默认值            |
| :----------: | :---------: | :-----------------------: |
|  -u, --url   | 目标 URL（必填）  |             -             |
|  -d, --dict  |   自定义字典文件   | data/framework_paths.json |
|    --csv     |  CSV 输出路径   |   data/scan_results.csv   |
| -o, --output | HTML 报告输出路径 |     data/report.html      |
|  --workers   |    并发线程数    |            10             |
|  --timeout   |   请求超时（秒）   |             3             |
| --max-paths  |   最大扫描路径数   |           0（不限）           |
|     --ai     |  启用 AI 辅助   |             否             |
|  --no-cache  |  禁用 404 缓存  |             否             |
|   --resume   |    断点续扫     |             否             |

### analyze - 分析已有结果

```
dirai analyze -i data/scan_results.csv
```

|      参数      |      说明      |       默认值        |
| :----------: | :----------: | :--------------: |
| -i, --input  | CSV 文件路径（必填） |        -         |
| -o, --output | HTML 报告输出路径  | data/report.html |

### report - 生成 HTML 报告

```
dirai report -i data/scan_results.csv
```

|      参数      |      说明      |       默认值        |
| :----------: | :----------: | :--------------: |
| -i, --input  | CSV 文件路径（必填） |        -         |
| -o, --output | HTML 报告输出路径  | data/report.html |

### dict - 字典管理

```
dirai dict --show
dirai dict --add /admin
dirai dict --add /actuator --fw java_spring
```

|        参数         |     说明     |     默认值     |
| :---------------: | :--------: | :---------: |
|      --show       | 显示当前所有字典条目 |      -      |
|       --add       |  添加路径到字典   |      -      |
| --fw, --framework |   指定框架名称   | java_spring |

### capture - Playwright 抓包

```
dirai capture -u https://example.com/
```

|      参数      |     说明     |              默认值              |
| :----------: | :--------: | :---------------------------: |
|  -u, --url   | 目标 URL（必填） |               -               |
| -o, --output | JSON 输出路径  | data/playwright_requests.json |
|    --wait    | 页面等待时间（秒）  |               3               |

## 输出说明

### HTML 报告

扫描完成后自动生成HTML报告，包含统计概览、高危路径列表（红色高亮）、中危路径列表（橙色标记）、敏感信息（密钥/密码/Token）、状态码分布（200/403/404 等）。

报告位置：data/report.html

### CSV 原始数据

扫描结果同时保存为CSV格式，便于二次分析，包含path（路径）、status_code（状态码）、risk_level（风险等级 High/Medium/Low）、label（是否敏感入口 1/0）等字段。

CSV 位置：data/scan_results.csv

## 自定义字典

DirAI-BZA支持用户自定义字典，格式为每行一个路径：

```
/admin
/login
/api/v1
/backup.zip
```

使用方式：

```
dirai scan -u https://example.com/ -d /path/to/my_dict.txt
```

## 项目结构

```
bza-AIScan/
├── scripts/
│   ├── scan.py              # 核心扫描引擎
│   ├── auto_scan.py         # 命令行入口
│   ├── ai_analyzer.py       # AI 推理模块
│   ├── framework_detector.py# 框架识别
│   ├── sensitive_scanner.py # 敏感信息扫描
│   ├── js_parser.py         # JS 路径提取
│   ├── html_parser.py       # HTML 路径提取
│   ├── playwright_scan.py   # 浏览器抓包
│   └── report_html.py       # HTML 报告生成
├── data/
│   ├── framework_paths.json # 框架默认字典
│   └── common_paths.txt     # 通用字典
├── .env.example             # API Key 配置模板
├── requirements.txt         # Python 依赖
├── setup.py                 # 安装配置
└── README.md                # 项目说明
```

## 依赖项

Python 3.8+、requests、beautifulsoup4、pandas、scikit-learn、xgboost、joblib、lxml、flask、openai、python-dotenv、playwright（可选，用于抓包功能）

## 常见问题

AI功能不生效时检查是否配置了API Key（cat .env），或测试API是否有效（python -c "from [scripts.ai](https://scripts.ai/)_analyzer import AIAnalyzer; ai = AIAnalyzer(); print('OK' if ai.enabled else 'FAIL')"）。

扫描速度慢时可增加并发线程数（--workers 30）或减少超时时间（--timeout 2）。

404缓存导致的问题可清除缓存重新扫描（rm -f data/url_cache.json && dirai scan -u [https://example.com/](https://example.com/) --no-cache）。

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
