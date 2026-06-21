import requests
import json
from urllib.parse import urljoin
from ai_analyzer import AIAnalyzer

class FrameworkDetector:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.ai = AIAnalyzer()
        
        # 框架配置
        self.framework_configs = {
            'java_spring': {
                'name': 'Java Spring Boot',
                'extensions': ['.jsp', '.jspx', '.do', '.action', '.jspf']
            },
            'php': {
                'name': 'PHP',
                'extensions': ['.php', '.phtml', '.php5', '.php7', '.inc']
            },
            'nodejs': {
                'name': 'Node.js',
                'extensions': ['.js', '.ts', '.jsx', '.tsx']
            },
            'python': {
                'name': 'Python',
                'extensions': ['.py', '.wsgi', '.j2']
            },
            'dotnet': {
                'name': '.NET',
                'extensions': ['.aspx', '.ashx', '.asmx', '.axd']
            },
            'static': {
                'name': 'Static',
                'extensions': ['.html', '.htm', '.css', '.js', '.json', '.xml']
            }
        }

    def detect(self):
        print("正在识别目标框架...")
        
        features = self._collect_features()
        
        # 1. 尝试 AI 识别
        if self.ai and self.ai.enabled:
            result = self._ai_detect(features)
            if result and 'key' in result:
                key = result['key']
                if key in self.framework_configs:
                    print(f"  [AI] 识别到: {self.framework_configs[key]['name']}")
                    return key, self.get_scan_config(key)
        
        # 2. 规则识别
        key = self._rule_detect(features)
        print(f"  [规则] 识别到: {self.framework_configs[key]['name']}")
        return key, self.get_scan_config(key)

    def _collect_features(self):
        features = {
            'headers': {},
            'html': '',
            'status_codes': {},
            'common_paths': {}
        }
        
        try:
            resp = requests.get(self.target_url, timeout=5, allow_redirects=True,
                               headers={'User-Agent': 'Mozilla/5.0'})
            features['headers'] = dict(resp.headers)
            features['html'] = resp.text[:5000]
            features['status_codes']['/'] = resp.status_code
        except:
            pass
        
        probe_paths = ['/admin', '/login', '/api', '/actuator/health', '/index.php']
        for path in probe_paths:
            try:
                url = urljoin(self.target_url, path)
                resp = requests.get(url, timeout=3, allow_redirects=True,
                                   headers={'User-Agent': 'Mozilla/5.0'})
                features['status_codes'][path] = resp.status_code
                if resp.status_code == 200:
                    features['common_paths'][path] = resp.text[:500]
            except:
                pass
        
        return features

    def _ai_detect(self, features):
        prompt = f"""
分析以下网站的技术栈:

网站URL: {self.target_url}

响应头:
{json.dumps(features.get('headers', {}), indent=2)}

首页HTML片段:
{features.get('html', '')[:1000]}

路径状态码:
{json.dumps(features.get('status_codes', {}), indent=2)}

请选择最匹配的框架（只输出框架名称，不要输出其他内容）:
可选: java_spring, php, nodejs, python, dotnet, static

输出格式（只输出key）:
php
"""
        
        try:
            response = self.ai.client.chat.completions.create(
                model=self.ai.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=50
            )
            content = response.choices[0].message.content.strip().lower()
            # 提取框架key
            valid_keys = ['java_spring', 'php', 'nodejs', 'python', 'dotnet', 'static']
            for key in valid_keys:
                if key in content:
                    return {'key': key}
            return None
        except:
            return None

    def _rule_detect(self, features):
        content = str(features.get('headers', {})) + features.get('html', '')
        scores = {key: 0 for key in self.framework_configs.keys()}
        
        # Java
        if any(k in content for k in ['spring', 'Spring', 'X-Application-Context', 'actuator']):
            scores['java_spring'] += 3
        if 'JSESSIONID' in content:
            scores['java_spring'] += 2
        if '.jsp' in content or '.do' in content:
            scores['java_spring'] += 1
        
        # PHP
        if 'PHPSESSID' in content or 'X-Powered-By: PHP' in content:
            scores['php'] += 3
        if '.php' in content or '<?php' in content:
            scores['php'] += 2
        if 'wp-content' in content or 'wp-admin' in content:
            scores['php'] += 1
        
        # Node.js
        if 'X-Powered-By: Express' in content or 'connect.sid' in content:
            scores['nodejs'] += 3
        
        # Python
        if 'csrftoken' in content or 'sessionid' in content:
            scores['python'] += 2
        if 'django' in content.lower() or 'flask' in content.lower():
            scores['python'] += 3
        
        # .NET
        if 'ASP.NET_SessionId' in content or '__VIEWSTATE' in content:
            scores['dotnet'] += 3
        if '.aspx' in content or '.ashx' in content:
            scores['dotnet'] += 1
        
        best = max(scores, key=scores.get)
        if scores[best] <= 1:
            best = 'static'
        
        return best

    def get_scan_config(self, framework_key):
        config = self.framework_configs.get(framework_key, self.framework_configs['static'])
        return {
            'framework_name': config['name'],
            'extensions': config['extensions']
        }

def detect_framework(target_url):
    detector = FrameworkDetector(target_url)
    framework_key, config = detector.detect()
    return framework_key, config
