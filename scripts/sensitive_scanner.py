import re
import requests
from urllib.parse import urljoin

# 敏感信息匹配规则
SENSITIVE_PATTERNS = {
    'AES_Key': {
        'pattern': r'(AES|aes)[\s]*[=:][\s]*["\']([a-fA-F0-9]{32,64})["\']',
        'severity': 'High',
        'desc': 'AES硬编码密钥'
    },
    'Secret_Key': {
        'pattern': r'(secret|SECRET|SecretKey)[\s]*[=:][\s]*["\']([a-zA-Z0-9+/=]{32,})["\']',
        'severity': 'High',
        'desc': '硬编码密钥'
    },
    'API_Key': {
        'pattern': r'(api[_-]?key|apikey|API_KEY)[\s]*[=:][\s]*["\']([a-zA-Z0-9_-]{20,})["\']',
        'severity': 'High',
        'desc': 'API密钥泄露'
    },
    'JWT_Secret': {
        'pattern': r'(jwt[_-]?secret|JWT_SECRET)[\s]*[=:][\s]*["\']([a-zA-Z0-9_-]{32,})["\']',
        'severity': 'Critical',
        'desc': 'JWT签名密钥泄露'
    },
    'Password': {
        'pattern': r'(password|PASSWORD|passwd)[\s]*[=:][\s]*["\']([^"\']{8,})["\']',
        'severity': 'Critical',
        'desc': '密码明文泄露'
    },
    'IV_Key': {
        'pattern': r'(iv|IV|initializationVector)[\s]*[=:][\s]*["\']([a-fA-F0-9]{16,32})["\']',
        'severity': 'High',
        'desc': '加密向量IV泄露'
    },
    'Token': {
        'pattern': r'(token|TOKEN|accessToken)[\s]*[=:][\s]*["\']([a-zA-Z0-9_.-]{20,})["\']',
        'severity': 'High',
        'desc': 'Token泄露'
    },
    'DB_Connection': {
        'pattern': r'(mysql|postgres|mongodb|redis|jdbc)[\s]*[=:][\s]*["\']([^"\']{10,})["\']',
        'severity': 'Critical',
        'desc': '数据库连接串泄露'
    },
    'AWS_Key': {
        'pattern': r'(AKIA[0-9A-Z]{16})',
        'severity': 'Critical',
        'desc': 'AWS Access Key泄露'
    },
    'Private_Key': {
        'pattern': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'severity': 'Critical',
        'desc': '私钥文件泄露'
    }
}

# 需要检查内容的文件类型
TARGET_EXTENSIONS = ['.js', '.json', '.env', '.yaml', '.yml', '.xml', '.properties', '.conf', '.txt', '.log', '.sql']

def extract_sensitive_info(content, url):
    """从文件内容中提取敏感信息"""
    findings = []
    
    for name, rule in SENSITIVE_PATTERNS.items():
        matches = re.findall(rule['pattern'], content, re.IGNORECASE)
        for match in matches:
            # 处理不同的匹配格式
            if isinstance(match, tuple):
                matched_value = match[-1] if len(match) > 0 else str(match)
            else:
                matched_value = str(match)
            
            findings.append({
                'type': name,
                'severity': rule['severity'],
                'desc': rule['desc'],
                'value': matched_value[:50] + '...' if len(matched_value) > 50 else matched_value,
                'url': url
            })
    
    return findings

def scan_sensitive_files(base_url, found_paths, timeout=3):
    """扫描发现的路径中的敏感文件"""
    all_findings = []
    checked_files = 0
    
    # 筛选需要检查的文件
    target_paths = []
    for path in found_paths:
        path_lower = path.lower()
        for ext in TARGET_EXTENSIONS:
            if path_lower.endswith(ext):
                target_paths.append(path)
                break
        # 也检查没有后缀但可能是敏感文件的路径
        if '.' not in path_lower:
            for keyword in ['env', 'config', 'secret', 'key', 'credential']:
                if keyword in path_lower:
                    target_paths.append(path)
                    break
    
    if not target_paths:
        return [], 0
    
    print(f"\n[+] 开始扫描敏感信息: 发现 {len(target_paths)} 个可能包含敏感信息的文件")
    
    for path in target_paths:
        full_url = urljoin(base_url, path)
        try:
            resp = requests.get(full_url, timeout=timeout, 
                               headers={'User-Agent': 'Mozilla/5.0'})
            if resp.status_code == 200:
                content = resp.text
                findings = extract_sensitive_info(content, full_url)
                if findings:
                    all_findings.extend(findings)
                    print(f"  [!] {path}: 发现 {len(findings)} 条敏感信息")
                checked_files += 1
        except:
            pass
    
    return all_findings, checked_files
