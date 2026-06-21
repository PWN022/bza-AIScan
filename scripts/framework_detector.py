import requests
import json
from urllib.parse import urljoin

class FrameworkDetector:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        
        # 框架探测路径配置
        self.probe_configs = {
            'java_spring': {
                'name': 'Java Spring Boot',
                'probes': [
                    {'path': '/actuator/health', 'expect': ['status', 'UP', '200']},
                    {'path': '/actuator', 'expect': ['_links', 'spring']},
                    {'path': '/swagger-ui.html', 'expect': ['swagger', 'Swagger UI']},
                    {'path': '/v3/api-docs', 'expect': ['openapi', 'swagger']},
                ],
                'headers': ['X-Application-Context', 'X-Content-Type-Options'],
                'server_headers': ['tomcat', 'spring'],
                'extensions': ['.jsp', '.jspx', '.do', '.action'],
                'common_paths': ['actuator/health', 'swagger-ui.html', 'v3/api-docs', 'admin', 'api']
            },
            'php': {
                'name': 'PHP',
                'probes': [
                    {'path': '/index.php', 'expect': ['php', '<?php']},
                    {'path': '/phpinfo.php', 'expect': ['PHP', 'phpinfo']},
                    {'path': '/wp-admin', 'expect': ['WordPress', 'wp-admin']},
                ],
                'headers': [],
                'server_headers': ['php'],
                'extensions': ['.php', '.phtml', '.php5', '.php7'],
                'common_paths': ['index.php', 'admin.php', 'wp-admin', 'phpinfo.php']
            },
            'python': {
                'name': 'Python',
                'probes': [
                    {'path': '/admin/login/?next=/admin/', 'expect': ['django', 'csrftoken']},
                    {'path': '/admin', 'expect': ['django', 'csrftoken', 'sessionid']},
                ],
                'headers': [],
                'server_headers': ['python', 'gunicorn', 'uwsgi'],
                'extensions': ['.py', '.wsgi'],
                'common_paths': ['admin/', 'login/', 'api/']
            },
            'nodejs': {
                'name': 'Node.js',
                'probes': [
                    {'path': '/api', 'expect': ['express', 'json']},
                ],
                'headers': [],
                'server_headers': ['express', 'node', 'nginx'],
                'extensions': ['.js', '.ts'],
                'common_paths': ['api/', 'admin/', 'static/']
            },
            'dotnet': {
                'name': '.NET',
                'probes': [
                    {'path': '/Default.aspx', 'expect': ['ASP.NET', '__VIEWSTATE']},
                    {'path': '/Login.aspx', 'expect': ['ASP.NET', 'login']},
                ],
                'headers': [],
                'server_headers': ['asp.net', 'microsoft-iis'],
                'extensions': ['.aspx', '.ashx', '.asmx'],
                'common_paths': ['Default.aspx', 'Login.aspx', 'Admin.aspx']
            },
            'static': {
                'name': 'Static',
                'probes': [],
                'headers': [],
                'server_headers': [],
                'extensions': ['.html', '.htm', '.css', '.js', '.json'],
                'common_paths': ['index.html', 'about.html', 'contact.html']
            }
        }

    def detect(self):
        print("正在识别目标框架...")
        scores = {fw: 0 for fw in self.probe_configs.keys()}
        
        # 1. 探测框架特征路径
        print("  正在探测框架特征路径...")
        for fw_name, config in self.probe_configs.items():
            for probe in config.get('probes', []):
                try:
                    full_url = urljoin(self.target_url, probe['path'])
                    resp = requests.get(full_url, timeout=5, allow_redirects=True,
                                       headers={'User-Agent': 'Mozilla/5.0'})
                    
                    # 200 或 403/401 说明路径存在（有权限控制）
                    if resp.status_code in [200, 201, 403, 401]:
                        scores[fw_name] += 3
                        content = resp.text.lower()
                        for expect in probe.get('expect', []):
                            if expect.lower() in content:
                                scores[fw_name] += 2
                except:
                    pass
        
        # 2. 探测响应头
        print("  正在探测响应头特征...")
        try:
            resp = requests.get(self.target_url, timeout=5, allow_redirects=True,
                               headers={'User-Agent': 'Mozilla/5.0'})
            server = resp.headers.get('Server', '').lower()
            x_powered = resp.headers.get('X-Powered-By', '').lower()
            combined_headers = server + x_powered
            
            for fw_name, config in self.probe_configs.items():
                for header in config.get('server_headers', []):
                    if header in combined_headers:
                        scores[fw_name] += 5
        except:
            pass
        
        # 3. 排序并输出
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        
        print("\n框架识别结果:")
        for fw, score in sorted_scores:
            if score > 0:
                name = self.probe_configs[fw]['name']
                print(f"  {name}: {score} 分")
        
        # 4. 决策
        if sorted_scores[0][1] < 3:
            print("\n未识别出明确的框架，使用静态扫描策略")
            return 'static', self.get_scan_config('static')
        
        detected = sorted_scores[0][0]
        print(f"\n识别到主框架: {self.probe_configs[detected]['name']}")
        return detected, self.get_scan_config(detected)

    def get_scan_config(self, framework):
        config = self.probe_configs.get(framework, self.probe_configs['static'])
        return {
            'framework_name': config['name'],
            'extensions': config.get('extensions', ['.html', '.htm']),
            'common_paths': config.get('common_paths', []),
        }

def detect_framework(target_url):
    detector = FrameworkDetector(target_url)
    framework, config = detector.detect()
    return framework, config

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
        if not url.startswith('http'):
            url = 'http://' + url
        framework, config = detect_framework(url)
        print(f"\n扫描配置: 框架={config['framework_name']}, 后缀={config['extensions']}")
    else:
        print("用法: python framework_detector.py <目标URL>")
