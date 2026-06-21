import re
import requests
from urllib.parse import urljoin, urlparse

def extract_paths_from_js(content, base_url):
    """从 JS 内容中提取所有路径"""
    extracted_paths = set()
    
    # 模式1: /xxx/xxx.xxx (绝对路径)
    pattern1 = re.compile(r'["\'](/[a-zA-Z0-9_\-./?=]+)["\']')
    matches = pattern1.findall(content)
    for m in matches:
        # 过滤掉不是路径的
        if len(m) > 2 and any(c in m for c in ['/', '.', '?', '=']):
            extracted_paths.add(m)
    
    # 模式2: 纯字符串路径 "xxx/xxx.xxx"
    pattern2 = re.compile(r'["\']([a-zA-Z0-9_\-/]+\.[a-zA-Z0-9]+)["\']')
    matches = pattern2.findall(content)
    for m in matches:
        if '/' in m or '.' in m:
            extracted_paths.add(m)
    
    # 模式3: url: 或 path: 后面的路径
    pattern3 = re.compile(r'(?:url|path|src|href)\s*[:=]\s*["\']([^"\']+)["\']')
    matches = pattern3.findall(content)
    for m in matches:
        if '/' in m or '.' in m:
            extracted_paths.add(m)
    
    # 模式4: import/require 中的路径
    pattern4 = re.compile(r'(?:import|require)\s*\(?\s*["\']([^"\']+)["\']')
    matches = pattern4.findall(content)
    for m in matches:
        if '/' in m or '.' in m:
            extracted_paths.add(m)
    
    # 模式5: 路由定义 path: '/xxx/xxx'
    pattern5 = re.compile(r'path\s*:\s*["\']([^"\']+)["\']')
    matches = pattern5.findall(content)
    for m in matches:
        if '/' in m:
            extracted_paths.add(m)
    
    # 模式6: axios/fetch 请求路径
    pattern6 = re.compile(r'(?:axios|fetch|http)\s*[.(]\s*["\']([^"\']+)["\']')
    matches = pattern6.findall(content)
    for m in matches:
        if '/' in m:
            extracted_paths.add(m)
    
    # 过滤掉明显不是路径的
    filtered = set()
    for p in extracted_paths:
        # 过滤掉纯参数、纯数字等
        if len(p) < 2:
            continue
        if p.startswith('http://') or p.startswith('https://'):
            # 提取相对路径
            parsed = urlparse(p)
            if parsed.path:
                filtered.add(parsed.path)
            continue
        if p.startswith('/') or '/' in p or '.' in p:
            filtered.add(p)
    
    # 拼接完整URL
    full_paths = set()
    for p in filtered:
        if not p.startswith('/'):
            p = '/' + p
        full_paths.add(p)
    
    return list(full_paths)

def scan_js_for_paths(base_url, found_paths, timeout=3):
    """扫描所有JS文件，提取其中的路径"""
    all_extracted = []
    checked_js = 0
    
    # 筛选JS文件
    js_paths = [p for p in found_paths if p.endswith('.js') or '.js?' in p]
    
    if not js_paths:
        return [], 0
    
    print(f"\n[+] 开始从JS文件中提取路径: 发现 {len(js_paths)} 个JS文件")
    
    for path in js_paths[:20]:  # 限制最多检查20个JS文件
        full_url = urljoin(base_url, path)
        try:
            resp = requests.get(full_url, timeout=timeout,
                               headers={'User-Agent': 'Mozilla/5.0'})
            if resp.status_code == 200:
                content = resp.text
                extracted = extract_paths_from_js(content, base_url)
                if extracted:
                    all_extracted.extend(extracted)
                    print(f"  [+] {path}: 提取到 {len(extracted)} 个路径")
                    # 显示前5个
                    for e in extracted[:5]:
                        print(f"      - {e}")
                    if len(extracted) > 5:
                        print(f"      ... 还有 {len(extracted)-5} 个")
                checked_js += 1
        except:
            pass
    
    # 去重
    all_extracted = list(set(all_extracted))
    
    if all_extracted:
        # 保存到文件
        import json
        import os
        os.makedirs('data', exist_ok=True)
        with open('data/js_extracted_paths.json', 'w') as f:
            json.dump(all_extracted, f, indent=2)
        print(f"\n[+] 从JS中提取到 {len(all_extracted)} 个路径，已保存到 data/js_extracted_paths.json")
    
    return all_extracted, checked_js
