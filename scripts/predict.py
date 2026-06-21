import sys
import pandas as pd
import joblib
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import warnings
warnings.filterwarnings('ignore')

def extract_features_single(url, path):
    full_url = urljoin(url, path)
    features = {}
    
    features['length'] = len(path)
    features['depth'] = path.count('/')
    features['has_dot'] = 1 if '.' in path else 0
    features['has_underline'] = 1 if '_' in path else 0
    features['has_dash'] = 1 if '-' in path else 0
    features['contains_admin'] = 1 if 'admin' in path.lower() else 0
    features['contains_login'] = 1 if 'login' in path.lower() else 0
    features['contains_backup'] = 1 if any(x in path.lower() for x in ['backup', 'bak', 'old', 'temp']) else 0
    features['contains_config'] = 1 if any(x in path.lower() for x in ['config', 'conf', 'env', 'xml', 'yaml']) else 0
    features['contains_zip'] = 1 if any(x in path.lower() for x in ['.zip', '.tar', '.gz', '.sql']) else 0
    
    try:
        resp = requests.get(full_url, timeout=5, allow_redirects=True,
                           headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        features['status_code'] = resp.status_code
        features['redirect_count'] = len(resp.history)
        features['has_set_cookie'] = 1 if 'Set-Cookie' in resp.headers else 0
        features['page_length'] = len(resp.text)
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        features['has_password_input'] = 1 if soup.find('input', {'type': 'password'}) else 0
        features['has_username_input'] = 1 if soup.find('input', {'name': ['username', 'user', 'email']}) else 0
        features['has_login_form'] = 1 if soup.find('form', {'action': lambda x: x and any(k in x.lower() for k in ['login', 'signin', 'auth'])}) else 0
        
        page_text = resp.text.lower()
        keywords = ['login', 'signin', 'admin', 'dashboard', 'manage', 'console', 'system']
        features['keyword_hits'] = sum(1 for kw in keywords if kw in page_text)
        
    except Exception as e:
        features['status_code'] = -1
        features['redirect_count'] = 0
        features['has_set_cookie'] = 0
        features['page_length'] = 0
        features['has_password_input'] = 0
        features['has_username_input'] = 0
        features['has_login_form'] = 0
        features['keyword_hits'] = 0
    
    return features

def predict_paths(base_url, path_list, model_file='output/dirai_model.pkl'):
    model = joblib.load(model_file)
    feature_cols = ['length', 'depth', 'has_dot', 'has_underline', 'has_dash',
                    'contains_admin', 'contains_login', 'contains_backup',
                    'contains_config', 'contains_zip', 'status_code',
                    'redirect_count', 'has_password_input', 'has_username_input',
                    'has_login_form', 'has_set_cookie', 'keyword_hits', 'page_length']
    
    results = []
    for path in path_list:
        features = extract_features_single(base_url, path)
        df = pd.DataFrame([features])
        pred = model.predict(df[feature_cols])[0]
        prob = model.predict_proba(df[feature_cols])[0]
        results.append({
            'path': path,
            'is_sensitive': pred,
            'probability': prob[1] if pred == 1 else prob[0]
        })
    
    sensitive = [r for r in results if r['is_sensitive'] == 1]
    return sensitive, results

if __name__ == '__main__':
    base = 'http://testphp.vulnweb.com/'
    test_paths = ['admin', 'login', 'admin/login.php', 'css/style.css', 'backup.zip']
    
    sensitive, all_results = predict_paths(base, test_paths)
    
    print("Prediction Results - Sensitive Paths:")
    for s in sensitive:
        print(f"  - {s['path']} (confidence: {s['probability']:.2%})")
    
    if not sensitive:
        print("  No sensitive paths found.")
