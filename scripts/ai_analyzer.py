import os
import json
from dotenv import load_dotenv

load_dotenv()

class AIAnalyzer:
    def __init__(self):
        self.api_key = os.environ.get('OPENAI_API_KEY')
        self.base_url = os.environ.get('OPENAI_BASE_URL', 'https://api.openai.com/v1')
        self.model = os.environ.get('AI_MODEL', 'deepseek-chat')
        self.cache = {}
        self.enabled = bool(self.api_key)
        
        if not self.enabled:
            print("[!] 未设置 OPENAI_API_KEY，AI 功能已禁用")
            return
        
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
            print("[+] AI 分析器初始化成功 (模型: {})".format(self.model))
        except Exception as e:
            print("[!] AI 初始化失败: {}".format(e))
            self.enabled = False
    
    def generate_paths(self, found_paths, target_url, max_new=10):
        """根据已发现路径，推理新路径"""
        if not self.enabled or not found_paths:
            return []
        
        # 取最近 30 条路径作为上下文
        sample_paths = found_paths[-30:]
        
        cache_key = json.dumps(sorted(sample_paths))
        if cache_key in self.cache:
            return self.cache[cache_key][:max_new]
        
        prompt = f"""
你是一个 Web 安全专家，正在进行路径枚举。

目标网站: {target_url}

已发现的路径（状态码非404）:
{json.dumps(sample_paths, indent=2)}

任务：根据以上路径的命名规律，推断该网站可能存在的其他路径。

规则：
1. 只输出路径列表，每行一个路径，不要解释
2. 路径以 / 开头
3. 推断 5-10 个最有可能的路径
4. 不要重复已给出的路径

输出格式（只输出路径，每行一个）:
/path1
/path2
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=300
            )
            content = response.choices[0].message.content
            new_paths = [p.strip() for p in content.split('\n') if p.strip().startswith('/')]
            self.cache[cache_key] = new_paths
            return new_paths[:max_new]
        except Exception as e:
            print(f"  [!] AI 推理失败: {e}")
            return []
    
    def analyze_sensitive(self, content, file_path):
        """分析疑似敏感信息"""
        if not self.enabled:
            return None
        
        prompt = f"""
分析以下内容是否包含真实的敏感信息（密钥、密码、Token 等）:

文件: {file_path}
内容:
{content[:500]}

判断:
1. 是否真的是敏感信息？
2. 如果是，风险等级（Low/Medium/High/Critical）
3. 简要说明原因

输出格式:
- 是否敏感: 是/否
- 风险等级: xxx
- 说明: xxx
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=200
            )
            return response.choices[0].message.content
        except:
            return None
    
    def generate_report_summary(self, scan_results):
        """生成报告摘要"""
        if not self.enabled:
            return None
        
        total = len(scan_results)
        high = len([r for r in scan_results if r.get('risk_level') == 'High'])
        found_200 = len([r for r in scan_results if r.get('status_code') == 200])
        
        prompt = f"""
根据以下扫描结果，生成一段安全报告摘要（100-150字）:

- 总扫描路径: {total}
- 高危路径: {high}
- 可访问路径: {found_200}
- 状态码分布: {set(r.get('status_code') for r in scan_results[:50])}

重点说明发现的风险和建议。
"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5,
                max_tokens=500
            )
            return response.choices[0].message.content
        except:
            return None
