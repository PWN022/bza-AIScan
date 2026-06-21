import requests
import pandas as pd
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import warnings
import os
import sys
import json
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from config import HIGH_VALUE_PATHS, STATUS_CODE_STRATEGY, HIGH_RISK_KEYWORDS, MEDIUM_RISK_KEYWORDS
from framework_detector import detect_framework
from cache import URLCache
from ai_analyzer import AIAnalyzer

warnings.filterwarnings('ignore')

# ========================================
# 信号处理
# ========================================
_interrupted = False
_lock = Lock()

def signal_handler(sig, frame):
    global _interrupted
    if not _interrupted:
        print("\n\n[!] 收到中断信号，正在保存已扫描的结果...")
        _interrupted = True
    else:
        print("\n[!] 强制退出...")
        sys.exit(1)

signal.signal(signal.SIGINT, signal_handler)

# ========================================
# 框架字典加载
# ========================================
def load_framework_paths():
    json_file = 'data/framework_paths.json'
    if os.path.exists(json_file):
        with open(json_file, 'r') as f:
            return json.load(f)
    return {
        'java_spring': ['admin', 'login', 'api', 'actuator/health'],
        'php': ['admin.php', 'login.php', 'config.php'],
        'nodejs': ['admin', 'login', 'api'],
        'python': ['admin', 'login', 'api'],
        'dotnet': ['Default.aspx', 'Login.aspx'],
        'static': ['index.html']
    }

def save_framework_paths(framework_paths):
    json_file = 'data/framework_paths.json'
    os.makedirs(os.path.dirname(json_file), exist_ok=True)
    with open(json_file, 'w') as f:
        json.dump(framework_paths, f, indent=2)

FRAMEWORK_PATHS = load_framework_paths()

def get_framework_paths(framework):
    if framework in FRAMEWORK_PATHS:
        return FRAMEWORK_PATHS[framework]
    return FRAMEWORK_PATHS.get('static', [])

def add_to_framework_paths(framework, new_paths):
    if framework not in FRAMEWORK_PATHS:
        FRAMEWORK_PATHS[framework] = []
    
    existing = set(FRAMEWORK_PATHS[framework])
    added = [p for p in new_paths if p not in existing and p.strip()]
    
    if added:
        FRAMEWORK_PATHS[framework].extend(added)
        save_framework_paths(FRAMEWORK_PATHS)
        print(f"字典更新: 框架 {framework} 新增 {len(added)} 条路径")
    
    return added

# ========================================
# 路径分类
# ========================================
def classify_path(path):
    path_lower = path.lower()
    risk_level = 'Low'
    category = 'Other'
    
    for cat, paths in HIGH_VALUE_PATHS.items():
        for p in paths:
            if p in path_lower:
                category = cat
                risk_level = 'High'
                return risk_level, category
    
    high_risk_count = sum(1 for kw in HIGH_RISK_KEYWORDS if kw in path_lower)
    medium_risk_count = sum(1 for kw in MEDIUM_RISK_KEYWORDS if kw in path_lower)
    
    if high_risk_count >= 2:
        risk_level = 'High'
        category = 'Potential Sensitive'
    elif high_risk_count >= 1 or medium_risk_count >= 2:
        risk_level = 'Medium'
        category = 'Potential Sensitive'
    else:
        risk_level = 'Low'
        category = 'Other'
    
    return risk_level, category

def load_paths_from_file(file_path):
    if not file_path or not os.path.exists(file_path):
        return None
    
    if file_path.endswith('.csv'):
        df = pd.read_csv(file_path)
        if 'path' in df.columns:
            return df['path'].tolist()
    elif file_path.endswith('.txt'):
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    return None

# ========================================
# AI 路径变体生成（规则引擎 + AI）
# ========================================
def generate_path_variants(path, depth_limit=3, max_count=20):
    variants = set()
    path_lower = path.lower()
    parts = path_lower.strip('/').split('/')
    
    if 'admin' in path_lower:
        variants.update(['admin/dashboard', 'admin/users', 'admin/settings', 'admin/login', 'admin/panel'])
    
    if 'login' in path_lower or 'signin' in path_lower:
        variants.update(['login.php', 'auth/login', 'user/login', 'index/login', 'logout', 'register'])
    
    if 'api' in path_lower:
        variants.update(['api/v1/users', 'api/v1/admin', 'api/v1/login', 'api/v2/users', 'api/health', 'api/docs'])
    
    if 'backup' in path_lower or 'bak' in path_lower:
        variants.update(['backup.zip', 'backup.sql', 'wwwroot.zip', 'site.zip', 'old.zip'])
    
    if 'config' in path_lower or 'conf' in path_lower:
        variants.update(['config.php', 'config.ini', 'config.yml', '.env', 'application.yml'])
    
    if any(k in path_lower for k in ['index', 'home', 'user', 'auth']):
        variants.update(['index/login', 'index/register', 'home/login', 'user/login', 'auth/login'])
    
    if path.endswith('/'):
        variants.update([path + 'index.php', path + 'index.html', path + 'default.php'])
    
    if any(k in path_lower for k in ['test', 'debug', 'dev']):
        variants.update(['test.php', 'debug.php', 'dev.php', 'phpinfo.php'])
    
    if '.git' in path_lower:
        variants.update(['.git/config', '.git/index', '.git/HEAD'])
    
    if 'actuator' in path_lower:
        variants.update(['actuator/health', 'actuator/info', 'actuator/metrics', 'actuator/env'])
    
    if 'swagger' in path_lower:
        variants.update(['swagger-ui.html', 'v3/api-docs', 'swagger.json'])
    
    variants.discard(path)
    variants.discard('')
    filtered = [v for v in variants if v.count('/') <= depth_limit]
    return list(set(filtered))[:max_count]

# ========================================
# 特征提取
# ========================================
def extract_features(url, path, timeout=5):
    full_url = urljoin(url, path)
    risk_level, category = classify_path(path)
    
    features = {
        'path': path,
        'risk_level': risk_level,
        'category': category,
        'length': len(path),
        'depth': path.count('/'),
        'has_dot': 1 if '.' in path else 0,
        'has_underline': 1 if '_' in path else 0,
        'has_dash': 1 if '-' in path else 0,
        'contains_admin': 1 if 'admin' in path.lower() else 0,
        'contains_login': 1 if 'login' in path.lower() else 0,
        'contains_backup': 1 if any(x in path.lower() for x in ['backup', 'bak', 'old', 'temp']) else 0,
        'contains_config': 1 if any(x in path.lower() for x in ['config', 'conf', 'env', 'xml', 'yaml']) else 0,
        'contains_zip': 1 if any(x in path.lower() for x in ['.zip', '.tar', '.gz', '.sql']) else 0,
        'status_code': 0,
        'redirect_count': 0,
        'final_url': '',
        'has_password_input': 0,
        'has_username_input': 0,
        'has_login_form': 0,
        'has_set_cookie': 0,
        'keyword_hits': 0,
        'page_length': 0,
        'label': -1,
        'status_strategy': ''
    }
    
    try:
        resp = requests.get(full_url, timeout=timeout, allow_redirects=True,
                           headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        features['status_code'] = resp.status_code
        features['redirect_count'] = len(resp.history)
        features['final_url'] = resp.url
        features['has_set_cookie'] = 1 if 'Set-Cookie' in resp.headers else 0
        features['page_length'] = len(resp.text)
        
        if resp.status_code in STATUS_CODE_STRATEGY:
            features['status_strategy'] = STATUS_CODE_STRATEGY[resp.status_code]['action']
        else:
            features['status_strategy'] = 'Check manually'
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        page_text = resp.text.lower()
        
        features['has_password_input'] = 1 if soup.find('input', {'type': 'password'}) else 0
        features['has_username_input'] = 1 if soup.find('input', {'name': ['username', 'user', 'email']}) else 0
        features['has_login_form'] = 1 if soup.find('form', {'action': lambda x: x and any(k in x.lower() for k in ['login', 'signin', 'auth'])}) else 0
        
        keywords = ['login', 'signin', 'admin', 'dashboard', 'manage', 'console', 'system']
        features['keyword_hits'] = sum(1 for kw in keywords if kw in page_text)
        
        if features['has_password_input'] or features['has_login_form']:
            features['label'] = 1
        elif features['redirect_count'] > 0 and any(k in features['final_url'].lower() for k in ['login', 'signin', 'auth']):
            features['label'] = 1
        elif features['keyword_hits'] >= 2 and features['status_code'] in [200, 403, 302]:
            features['label'] = 1
        elif features['status_code'] == 404:
            features['label'] = 0
        else:
            features['label'] = 0
            
    except Exception as e:
        features['status_code'] = -1
        features['label'] = 0
        features['status_strategy'] = 'Connection error or timeout'
        
    return features

# ========================================
# 主扫描函数
# ========================================
def scan_targets(base_url, path_list, output_file='data/scan_results.csv', 
                 enable_ai_generation=True, workers=10, timeout=3, 
                 max_paths=0, ai_limit=20, depth_limit=3, cache_404=True,
                 resume_file=None):
    global _interrupted
    _interrupted = False
    
    # 初始化缓存
    url_cache = URLCache() if cache_404 else None
    
    # AI 分析器
    ai = AIAnalyzer() if enable_ai_generation else None
    
    # 框架识别
    framework, config = detect_framework(base_url)
    print(f"检测到框架: {config['framework_name']}")
    print(f"使用后缀: {config['extensions']}")
    print("")
    
    # 从HTML提取路径
    html_found_paths = []
    try:
        from html_parser import scan_html_for_paths
        html_paths = scan_html_for_paths(base_url, timeout)
        if html_paths:
            html_found_paths = html_paths
            print(f"  HTML提取: {len(html_paths)} 条路径")
        else:
            print(f"  HTML提取: 未提取到路径")
    except Exception as e:
        print(f"  [!] HTML路径提取失败: {e}")
    
    # 加载路径
    framework_paths = get_framework_paths(framework)
    print(f"框架专属路径: {len(framework_paths)} 条")
    
    if html_found_paths:
        framework_paths = list(set(framework_paths + html_found_paths))
        print(f"  合并HTML提取路径后: {len(framework_paths)} 条")
    
    user_paths = []
    if path_list and isinstance(path_list, str):
        loaded = load_paths_from_file(path_list)
        if loaded:
            user_paths = loaded
    elif path_list and isinstance(path_list, list):
        user_paths = list(path_list)
    
    # 断点续扫
    scanned_paths_set = set()
    existing_results = []
    if resume_file and os.path.exists(resume_file):
        try:
            df_existing = pd.read_csv(resume_file)
            scanned_paths_set = set(df_existing['path'].tolist())
            existing_results = df_existing.to_dict('records')
            print(f"断点续扫: 已加载 {len(scanned_paths_set)} 条已扫描路径")
        except:
            pass
    
    # 合并路径
    merged_paths = list(set(framework_paths + user_paths))
    
    # 后缀过滤和扩展
    extensions = config.get('extensions', ['.html', '.htm', '.css', '.js'])
    filtered_paths = []
    for p in merged_paths:
        if p in scanned_paths_set:
            continue
        if '.' in p:
            ext = '.' + p.split('.')[-1]
            if ext in extensions:
                filtered_paths.append(p)
        else:
            filtered_paths.append(p)
            for ext in extensions:
                filtered_paths.append(p + ext)
    
    # 优先级排序
    priority_paths = []
    normal_paths = []
    for p in filtered_paths:
        risk, _ = classify_path(p)
        if risk == 'High':
            priority_paths.append(p)
        else:
            normal_paths.append(p)
    
    final_paths = list(set(priority_paths + normal_paths))
    print(f"最终扫描路径: {len(final_paths)} 条 (高优先级: {len(priority_paths)})")
    print(f"并发线程: {workers}, 超时: {timeout}s")
    print("")
    
    # 限制最大路径数
    if max_paths > 0 and len(final_paths) > max_paths:
        final_paths = final_paths[:max_paths]
        print(f"限制最大路径数: {max_paths}")
    
    # 开始扫描
    results = existing_results.copy()
    scanned_count = len(scanned_paths_set)
    total = len(final_paths)
    pending_paths = list(final_paths)
    ai_generated_count = 0
    ai_trigger_count = 0
    
    def scan_single(path):
        if _interrupted:
            return None
        
        full_url = urljoin(base_url, path)
        if url_cache:
            cached_status = url_cache.get(full_url)
            if cached_status is not None:
                features = {
                    'path': path,
                    'risk_level': 'Low',
                    'category': 'Other',
                    'length': len(path),
                    'depth': path.count('/'),
                    'has_dot': 1 if '.' in path else 0,
                    'has_underline': 1 if '_' in path else 0,
                    'has_dash': 1 if '-' in path else 0,
                    'contains_admin': 1 if 'admin' in path.lower() else 0,
                    'contains_login': 1 if 'login' in path.lower() else 0,
                    'contains_backup': 1 if any(x in path.lower() for x in ['backup', 'bak', 'old', 'temp']) else 0,
                    'contains_config': 1 if any(x in path.lower() for x in ['config', 'conf', 'env', 'xml', 'yaml']) else 0,
                    'contains_zip': 1 if any(x in path.lower() for x in ['.zip', '.tar', '.gz', '.sql']) else 0,
                    'status_code': cached_status,
                    'redirect_count': 0,
                    'final_url': full_url,
                    'has_password_input': 0,
                    'has_username_input': 0,
                    'has_login_form': 0,
                    'has_set_cookie': 0,
                    'keyword_hits': 0,
                    'page_length': 0,
                    'label': 0,
                    'status_strategy': 'Cached from previous scan'
                }
                return features
        
        features = extract_features(base_url, path, timeout=timeout)
        if url_cache and features['status_code'] == 404:
            url_cache.set(full_url, 404)
        return features
    
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_path = {}
            for path in pending_paths:
                future = executor.submit(scan_single, path)
                future_to_path[future] = path
            
            for future in as_completed(future_to_path):
                if _interrupted:
                    break
                path = future_to_path[future]
                result = future.result()
                if result:
                    with _lock:
                        results.append(result)
                        scanned_count += 1
                        
                        progress = int((scanned_count / total) * 100)
                        bar = '=' * (progress // 2) + '>' + '.' * (50 - progress // 2)
                        print(f"\r进度: {scanned_count}/{total} [{bar}] {progress}% - {path[:40]:<40}", end='')
                        
                        # 规则生成
                        if enable_ai_generation and ai_generated_count < ai_limit * 10:
                            if result.get('status_code') in [200, 301, 302, 403, 401]:
                                variants = generate_path_variants(path, depth_limit=depth_limit, max_count=5)
                                new_count = 0
                                for v in variants:
                                    if v not in final_paths and v not in pending_paths:
                                        if max_paths == 0 or len(final_paths) + len(pending_paths) < max_paths:
                                            pending_paths.append(v)
                                            new_count += 1
                                            ai_generated_count += 1
                                            future_new = executor.submit(scan_single, v)
                                            future_to_path[future_new] = v
                                            total = len(pending_paths) + scanned_count
                                if new_count > 0:
                                    print(f"\n  + 规则生成 {new_count} 个新路径 (总计: {ai_generated_count})", end='')
                        
                        # AI 推理（每 15 条可达路径触发一次）
                        if ai and ai.enabled and len(results) % 15 == 0 and len(results) > 0:
                            try:
                                found_paths = [r['path'] for r in results if r.get('status_code') not in [404, -1]]
                                if found_paths and len(found_paths) > 3:
                                    ai_paths = ai.generate_paths(found_paths, base_url, max_new=5)
                                    for v in ai_paths:
                                        if v not in final_paths and v not in pending_paths:
                                            if max_paths == 0 or len(final_paths) + len(pending_paths) < max_paths:
                                                pending_paths.append(v)
                                                ai_generated_count += 1
                                                future_new = executor.submit(scan_single, v)
                                                future_to_path[future_new] = v
                                                total = len(pending_paths) + scanned_count
                                                print(f"\n  + AI 推理新路径: {v}", end='')
                            except Exception as e:
                                pass
        
    except Exception as e:
        print(f"\n扫描异常: {e}")
    
    print("\n")
    
    # 保存结果
    if results:
        df = pd.DataFrame(results)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        df.to_csv(output_file, index=False)
        
        print(f"\n[+] 已保存 {len(results)} 条扫描结果到 {output_file}")
        if url_cache:
            print(f"   缓存命中: 节省了重复请求")
        
        found_paths = df[df['status_code'] != 404]['path'].tolist()
        added = add_to_framework_paths(framework, found_paths)
        if added:
            print(f"字典已更新: 新增 {len(added)} 条路径到 data/framework_paths.json")
        
        if _interrupted:
            print("\n[!] 扫描被用户中断，已保存部分结果。")
            print(f"   使用 --resume {output_file} 继续扫描")

    # ===== 敏感信息扫描 =====
    if results:
        found_paths = [r['path'] for r in results if r.get('status_code') == 200]
        from sensitive_scanner import scan_sensitive_files
        sensitive_findings, checked = scan_sensitive_files(base_url, found_paths, timeout=timeout)
        
        if sensitive_findings:
            print(f"\n[!] 发现 {len(sensitive_findings)} 条敏感信息泄露:")
            for f in sensitive_findings[:10]:
                print(f"    [{f['severity']}] {f['desc']}: {f['value']} ({f['url']})")
            
            os.makedirs('data', exist_ok=True)
            with open('data/sensitive_findings.json', 'w') as f:
                json.dump(sensitive_findings, f, indent=2)
            print(f"敏感信息详情已保存到 data/sensitive_findings.json")
        else:
            print(f"\n[+] 未发现敏感信息泄露 (已检查 {checked} 个文件)")

    # ===== JS路径提取 =====
    if results:
        found_paths = [r['path'] for r in results if r.get('status_code') == 200]
        try:
            from js_parser import scan_js_for_paths
            js_paths, checked_js = scan_js_for_paths(base_url, found_paths, timeout=timeout)
            if js_paths:
                print(f"\n[+] 从JS文件中提取到 {len(js_paths)} 个新路径")
        except Exception as e:
            print(f"\n[!] JS路径提取失败: {e}")
    
        return df
    else:
        print("[!] 没有扫描到任何结果。")
        return None

if __name__ == '__main__':
    base = 'http://testphp.vulnweb.com/'
    test_paths = ['admin', 'login']
    scan_targets(base, test_paths, enable_ai_generation=True)
