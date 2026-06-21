import pandas as pd
import os
import json
from datetime import datetime

def generate_html_report(csv_file='data/scan_results.csv', output_file='data/report.html'):
    if not os.path.exists(csv_file):
        print(f"数据文件不存在: {csv_file}")
        return
    
    df = pd.read_csv(csv_file)
    
    # 加载敏感信息
    sensitive_findings = []
    if os.path.exists('data/sensitive_findings.json'):
        with open('data/sensitive_findings.json', 'r') as f:
            sensitive_findings = json.load(f)
    
    # 加载JS提取的路径
    js_paths = []
    if os.path.exists('data/js_extracted_paths.json'):
        with open('data/js_extracted_paths.json', 'r') as f:
            js_paths = json.load(f)
    
    # 统计
    total = len(df)
    high_risk = len(df[df['risk_level'] == 'High'])
    medium_risk = len(df[df['risk_level'] == 'Medium'])
    low_risk = len(df[df['risk_level'] == 'Low'])
    sensitive = len(df[df['label'] == 1])
    accessible = len(df[df['status_code'] == 200])
    forbidden = len(df[df['status_code'] == 403])
    status_counts = df['status_code'].value_counts().to_dict()
    
    # 按风险排序
    risk_order = {'High': 0, 'Medium': 1, 'Low': 2}
    df['risk_sort'] = df['risk_level'].map(risk_order)
    
    html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PathFinder 扫描报告</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; padding: 30px; color: #e6edf3; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        .header {{ background: linear-gradient(135deg, #161b22, #0d1117); border: 1px solid #30363d; padding: 30px; border-radius: 12px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 28px; color: #f0f6fc; }}
        .header .sub {{ color: #8b949e; font-size: 14px; margin-top: 5px; }}
        
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-card .num {{ font-size: 32px; font-weight: bold; }}
        .stat-card .label {{ color: #8b949e; font-size: 13px; margin-top: 5px; }}
        .stat-card .num.high {{ color: #f85149; }}
        .stat-card .num.medium {{ color: #d29922; }}
        .stat-card .num.low {{ color: #3fb950; }}
        .stat-card .num.sensitive {{ color: #f85149; }}
        .stat-card .num.critical {{ color: #f85149; }}
        
        .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; margin-bottom: 20px; overflow: hidden; }}
        .section-header {{ padding: 15px 20px; border-bottom: 1px solid #30363d; font-weight: 600; font-size: 16px; background: #0d1117; }}
        .section-header .badge {{ background: #30363d; padding: 2px 10px; border-radius: 12px; font-size: 12px; margin-left: 10px; }}
        
        .path-list {{ padding: 10px 20px; }}
        .path-item {{ display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 14px; }}
        .path-item:hover {{ background: #1c2333; }}
        .path-item .path {{ font-family: 'Courier New', monospace; color: #f0f6fc; word-break: break-all; flex: 1; }}
        .path-item .status {{ padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; margin-left: 10px; flex-shrink: 0; }}
        .status-200 {{ background: #1b3a2b; color: #3fb950; }}
        .status-403 {{ background: #3d1a1a; color: #f85149; }}
        .status-302 {{ background: #3d2a1a; color: #d29922; }}
        .status-404 {{ background: #21262d; color: #8b949e; }}
        .status-500 {{ background: #3d1a1a; color: #f85149; }}
        .status-401 {{ background: #3d1a1a; color: #f85149; }}
        .status--1 {{ background: #21262d; color: #8b949e; }}
        
        .risk-tag {{ padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; margin-left: 8px; flex-shrink: 0; }}
        .risk-High {{ background: #3d1a1a; color: #f85149; border: 1px solid #f85149; }}
        .risk-Medium {{ background: #3d2a1a; color: #d29922; border: 1px solid #d29922; }}
        .risk-Low {{ background: #1b3a2b; color: #3fb950; border: 1px solid #3fb950; }}
        
        .severity-Critical {{ background: #3d0a0a; color: #ff4444; border: 1px solid #ff4444; }}
        .severity-High {{ background: #3d1a1a; color: #f85149; border: 1px solid #f85149; }}
        .severity-Medium {{ background: #3d2a1a; color: #d29922; border: 1px solid #d29922; }}
        .severity-Low {{ background: #1b3a2b; color: #3fb950; border: 1px solid #3fb950; }}
        
        .empty {{ color: #8b949e; padding: 20px; text-align: center; }}
        .footer {{ text-align: center; color: #8b949e; font-size: 12px; margin-top: 20px; border-top: 1px solid #30363d; padding-top: 20px; }}
        
        @media (max-width: 600px) {{
            .stats {{ grid-template-columns: repeat(2, 1fr); }}
            .path-item {{ flex-wrap: wrap; gap: 5px; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>PathFinder 扫描报告</h1>
        <div class="sub">生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 共扫描 {total} 条路径</div>
    </div>
    
    <div class="stats">
        <div class="stat-card"><div class="num high">{high_risk}</div><div class="label">高危路径</div></div>
        <div class="stat-card"><div class="num medium">{medium_risk}</div><div class="label">中危路径</div></div>
        <div class="stat-card"><div class="num low">{low_risk}</div><div class="label">低危路径</div></div>
        <div class="stat-card"><div class="num sensitive">{sensitive}</div><div class="label">敏感入口</div></div>
        <div class="stat-card"><div class="num accessible">{accessible}</div><div class="label">可访问 (200)</div></div>
        <div class="stat-card"><div class="num forbidden">{forbidden}</div><div class="label">拒绝访问 (403)</div></div>
    </div>
    
    <!-- 敏感信息泄露 -->
    <div class="section">
        <div class="section-header"> 敏感信息泄露 <span class="badge">{len(sensitive_findings)}</span></div>
        <div class="path-list">
'''
    
    if len(sensitive_findings) == 0:
        html += '<div class="empty">未发现敏感信息泄露</div>'
    else:
        for f in sensitive_findings:
            severity = f.get('severity', 'Low')
            html += f'''
            <div class="path-item" style="border-left: 3px solid {'#f85149' if severity == 'Critical' else '#d29922' if severity == 'High' else '#3fb950'};">
                <span class="path" style="color: {'#f85149' if severity == 'Critical' else '#f0f6fc'};">[{f.get('type', 'Unknown')}] {f.get('desc', '')}</span>
                <span>
                    <span class="severity-{severity}">{severity}</span>
                    <span style="color: #8b949e; font-size: 12px; margin-left: 10px;">{f.get('value', '')[:30]}...</span>
                </span>
            </div>
'''
    
    html += '''
        </div>
    </div>
    
    <!-- JS提取的路径 -->
    <div class="section">
        <div class="section-header"> 从JS中提取的路径 <span class="badge">''' + str(len(js_paths)) + '''</span></div>
        <div class="path-list">
'''
    
    if len(js_paths) == 0:
        html += '<div class="empty">未从JS中提取到新路径</div>'
    else:
        for p in js_paths[:50]:
            html += f'''
            <div class="path-item">
                <span class="path">{p}</span>
                <span style="color: #8b949e; font-size: 12px;">JS提取</span>
            </div>
'''
        if len(js_paths) > 50:
            html += f'<div style="color:#8b949e; padding:10px; text-align:center;">... 还有 {len(js_paths)-50} 个路径</div>'
    
    html += '''
        </div>
    </div>
    
    <!-- 高危路径 -->
    <div class="section">
        <div class="section-header"> 高危路径 <span class="badge">''' + str(high_risk) + '''</span></div>
        <div class="path-list">
'''
    
    high_df = df[df['risk_level'] == 'High'].sort_values('risk_sort')
    if len(high_df) == 0:
        html += '<div class="empty">暂无高危路径</div>'
    else:
        for _, row in high_df.iterrows():
            status = row.get('status_code', 'N/A')
            status_class = f'status-{status}' if status in [200, 302, 403, 404, 500, 401] else 'status--1'
            html += f'''
            <div class="path-item" style="background: rgba(248,81,73,0.05); border-left: 3px solid #f85149;">
                <span class="path" style="color: #f85149; font-weight: 600;">{row['path']}</span>
                <span>
                    <span class="risk-tag risk-High">HIGH</span>
                    <span class="status {status_class}">{status}</span>
                </span>
            </div>
'''
    
    html += '''
        </div>
    </div>
    
    <!-- 中危路径 -->
    <div class="section">
        <div class="section-header"> 中危路径 <span class="badge">''' + str(medium_risk) + '''</span></div>
        <div class="path-list">
'''
    
    medium_df = df[df['risk_level'] == 'Medium'].sort_values('risk_sort')
    if len(medium_df) == 0:
        html += '<div class="empty">暂无中危路径</div>'
    else:
        for _, row in medium_df.iterrows():
            status = row.get('status_code', 'N/A')
            status_class = f'status-{status}' if status in [200, 302, 403, 404, 500, 401] else 'status--1'
            html += f'''
            <div class="path-item">
                <span class="path">{row['path']}</span>
                <span>
                    <span class="risk-tag risk-Medium">MEDIUM</span>
                    <span class="status {status_class}">{status}</span>
                </span>
            </div>
'''
    
    html += f'''
        </div>
    </div>
    
    <!-- 状态码分布 -->
    <div class="section">
        <div class="section-header"> 状态码分布</div>
        <div class="path-list" style="display: flex; flex-wrap: wrap; gap: 10px; padding: 15px 20px;">
'''
    
    for code, count in sorted(status_counts.items(), key=lambda x: x[1], reverse=True):
        if code in [200, 302, 403, 404, 500, 401]:
            html += f'<span style="background:#21262d; padding:4px 14px; border-radius:12px; font-size:13px; border:1px solid #30363d;">{code}: {count}</span>'
        else:
            html += f'<span style="background:#21262d; padding:4px 14px; border-radius:12px; font-size:13px; color:#8b949e;">{code}: {count}</span>'
    
    html += f'''
        </div>
    </div>
    
    <!-- 全部可访问路径 -->
    <div class="section">
        <div class="section-header"> 全部可访问路径 <span class="badge">{len(df[df['status_code'].isin([200, 302, 403, 401])])}</span></div>
        <div class="path-list">
'''
    
    accessible_df = df[df['status_code'].isin([200, 302, 403, 401])].sort_values('risk_sort')
    if len(accessible_df) == 0:
        html += '<div class="empty">没有可访问的路径</div>'
    else:
        for _, row in accessible_df.head(200).iterrows():
            status = row.get('status_code', 'N/A')
            status_class = f'status-{status}' if status in [200, 302, 403, 404, 500, 401] else 'status--1'
            risk = row.get('risk_level', 'Low')
            risk_class = f'risk-{risk}'
            html += f'''
            <div class="path-item">
                <span class="path">{row['path']}</span>
                <span>
                    <span class="risk-tag {risk_class}">{risk}</span>
                    <span class="status {status_class}">{status}</span>
                </span>
            </div>
'''
    
    html += f'''
        </div>
        <div style="padding: 10px 20px; color: #8b949e; font-size: 13px; border-top: 1px solid #30363d;">
            显示前 200 条可访问路径
        </div>
    </div>
    
    <div class="footer">
        PathFinder v1.0 | 扫描结果由 AI 辅助生成，请人工验证
    </div>
</div>
</body>
</html>
'''
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"HTML报告已生成: {output_file}")
    print(f"  高危路径: {high_risk} 条")
    print(f"  中危路径: {medium_risk} 条")
    print(f"  敏感信息: {len(sensitive_findings)} 条")
    print(f"  JS提取路径: {len(js_paths)} 条")
    return output_file

if __name__ == '__main__':
    generate_html_report()
