import json
import os
import sys
from playwright.sync_api import sync_playwright

def capture_requests(target_url, output_file='data/playwright_requests.json'):
    """
    使用 Playwright 访问目标网站，捕获所有网络请求
    """
    print(f"\n[+] Playwright 正在访问: {target_url}")
    
    all_requests = []
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        def on_request(request):
            url = request.url
            # 只捕获目标域名的请求
            if target_url in url or target_url.replace('https://', '').replace('http://', '').split('/')[0] in url:
                all_requests.append(url)
                print(f"  [请求] {url}")
        
        page.on('request', on_request)
        
        try:
            page.goto(target_url, wait_until='networkidle', timeout=30000)
            page.wait_for_timeout(3000)
        except Exception as e:
            print(f"  [!] 页面加载异常: {e}")
        
        browser.close()
    
    all_requests = list(set(all_requests))
    
    paths = []
    for url in all_requests:
        if target_url in url:
            path = url.replace(target_url, '').replace('https://', '').replace('http://', '')
            if path and path.startswith('/'):
                paths.append(path)
    
    if paths:
        os.makedirs('data', exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(paths, f, indent=2)
        print(f"\n[+] 捕获到 {len(paths)} 个路径，已保存到 {output_file}")
    else:
        print(f"\n[!] 未捕获到路径")
    
    return paths

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python playwright_scan.py <目标URL>")
        print("示例: python playwright_scan.py https://xxx.com/")
        sys.exit(1)
    
    url = sys.argv[1]
    capture_requests(url)
