import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def extract_paths_from_html(base_url, timeout=3):
    """从首页HTML中提取所有资源路径"""
    extracted_paths = set()
    
    try:
        resp = requests.get(base_url, timeout=timeout, 
                           headers={'User-Agent': 'Mozilla/5.0'})
        if resp.status_code != 200:
            return []
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # 1. <link href="...">
        for tag in soup.find_all('link'):
            href = tag.get('href')
            if href:
                full = urljoin(base_url, href)
                path = urlparse(full).path
                if path and path != '/':
                    extracted_paths.add(path)
        
        # 2. <script src="...">
        for tag in soup.find_all('script'):
            src = tag.get('src')
            if src:
                full = urljoin(base_url, src)
                path = urlparse(full).path
                if path and path != '/':
                    extracted_paths.add(path)
        
        # 3. <img src="...">
        for tag in soup.find_all('img'):
            src = tag.get('src')
            if src:
                full = urljoin(base_url, src)
                path = urlparse(full).path
                if path and path != '/':
                    extracted_paths.add(path)
        
        # 4. <a href="..."> (可能的内链)
        for tag in soup.find_all('a'):
            href = tag.get('href')
            if href and href.startswith('/') and not href.startswith('//'):
                if not href.endswith(('.pdf', '.zip', '.rar', '.exe')):
                    extracted_paths.add(href)
        
        # 5. 直接匹配 HTML 中的路径
        patterns = [
            r'["\'](/[a-zA-Z0-9_\-./?=]+)["\']',
            r'["\']([a-zA-Z0-9_\-/]+\.[a-zA-Z0-9]+)["\']',
        ]
        for pattern in patterns:
            for match in re.findall(pattern, resp.text):
                if '/' in match or '.' in match:
                    if match.startswith('/'):
                        extracted_paths.add(match)
                    elif match.startswith('http'):
                        extracted_paths.add(urlparse(match).path)
                    elif '/' in match:
                        extracted_paths.add('/' + match)
        
    except Exception as e:
        print(f"HTML解析失败: {e}")
        return []
    
    # 过滤
    filtered = []
    for p in extracted_paths:
        if len(p) > 1 and not p.startswith('//'):
            if not p.endswith(('.pdf', '.zip', '.rar', '.exe', '.mp4', '.mp3')):
                filtered.append(p)
    
    return list(set(filtered))

def scan_html_for_paths(base_url, timeout=3):
    """从HTML中提取路径并保存"""
    print(f"\n[+] 从首页HTML中提取资源路径...")
    paths = extract_paths_from_html(base_url, timeout)
    
    if paths:
        print(f"  [+] 提取到 {len(paths)} 个路径:")
        for p in paths[:10]:
            print(f"      - {p}")
        if len(paths) > 10:
            print(f"      ... 还有 {len(paths)-10} 个")
        
        import json
        import os
        os.makedirs('data', exist_ok=True)
        with open('data/html_extracted_paths.json', 'w') as f:
            json.dump(paths, f, indent=2)
        print(f"  [+] 已保存到 data/html_extracted_paths.json")
    else:
        print("  [!] 未提取到路径")
    
    return paths
