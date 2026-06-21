import os
import json
import time
from datetime import datetime, timedelta

CACHE_FILE = 'data/url_cache.json'

class URLCache:
    def __init__(self):
        self.cache = {}
        self.load()
    
    def load(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r') as f:
                    self.cache = json.load(f)
            except:
                self.cache = {}
    
    def save(self):
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump(self.cache, f, indent=2)
    
    def get(self, url):
        if url in self.cache:
            entry = self.cache[url]
            if time.time() - entry['timestamp'] < 86400:  # 24小时有效
                return entry['status_code']
        return None
    
    def set(self, url, status_code):
        self.cache[url] = {
            'status_code': status_code,
            'timestamp': time.time()
        }
        self.save()
    
    def clear(self):
        self.cache = {}
        self.save()
