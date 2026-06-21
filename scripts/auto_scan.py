import sys
import os
import argparse
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from scan import scan_targets
from report_html import generate_html_report
from sensitive_scanner import scan_sensitive_files
from js_parser import scan_js_for_paths
from playwright_scan import capture_requests
from framework_detector import detect_framework
from scan import FRAMEWORK_PATHS, save_framework_paths
import pandas as pd
import json

def do_scan(target_url, dict_file='data/framework_paths.json', output_html='data/report.html',
            output_csv='data/scan_results.csv', workers=10, timeout=3,
            max_paths=0, ai_limit=20, depth_limit=3, cache_404=True,
            enable_ai=True, resume_file=None):
    if dict_file and not os.path.exists(dict_file):
        print(f"Warning: Dictionary file not found: {dict_file}")
        dict_file = None

    print(f"Target: {target_url}")
    print(f"Dictionary: {dict_file if dict_file else '框架内置'}")
    print(f"AI generation: {'ON' if enable_ai else 'OFF'}")
    print(f"Concurrent workers: {workers}")
    print(f"Timeout: {timeout}s")
    print(f"Output CSV: {output_csv}")
    print(f"Output HTML: {output_html}")
    print("")

    result = scan_targets(
        target_url, dict_file,
        output_file=output_csv,
        enable_ai_generation=enable_ai,
        workers=workers,
        timeout=timeout,
        max_paths=max_paths,
        ai_limit=ai_limit,
        depth_limit=depth_limit,
        cache_404=cache_404,
        resume_file=resume_file
    )

    if result is not None and len(result) > 0:
        df = pd.DataFrame(result)
        found_200 = len(df[df['status_code'] == 200])
        found_403 = len(df[df['status_code'] == 403])
        found_sensitive = len(df[df['label'] == 1])
        print(f"\n扫描统计: 共 {len(df)} 条, 200: {found_200}, 403: {found_403}, 敏感: {found_sensitive}")

        # JS提取
        print("\n[+] 从JS中提取路径...")
        try:
            found_paths = df[df['status_code'] == 200]['path'].tolist()
            print(f"    找到 {len(found_paths)} 个可访问路径用于JS提取")
            js_paths, checked_js = scan_js_for_paths(target_url, found_paths, timeout=timeout)
            if js_paths:
                print(f"    提取到 {len(js_paths)} 个新路径")
                # 保存JS提取结果
                with open('data/js_extracted_paths.json', 'w') as f:
                    json.dump(js_paths, f, indent=2)
            else:
                print(f"    未提取到新路径 (已检查 {checked_js} 个JS文件)")
        except Exception as e:
            print(f"    JS提取失败: {e}")

        # 敏感信息扫描
        print("\n[+] 扫描敏感信息...")
        try:
            found_paths = df[df['status_code'] == 200]['path'].tolist()
            findings, checked = scan_sensitive_files(target_url, found_paths, timeout=timeout)
            if findings:
                print(f"    发现 {len(findings)} 条敏感信息")
                for f in findings[:5]:
                    print(f"      [{f['severity']}] {f['desc']}: {f['value'][:30]}...")
            else:
                print(f"    未发现敏感信息 (已检查 {checked} 个文件)")
        except Exception as e:
            print(f"    敏感信息扫描失败: {e}")

        # 生成HTML报告
        print("\n[+] 生成HTML报告...")
        generate_html_report(output_csv, output_html)
        print(f"    报告已生成: {output_html}")

        return result
    else:
        print("[!] 没有扫描结果")
        return None

def do_analyze(input_csv, output_html='data/report.html', workers=10, timeout=3):
    if not os.path.exists(input_csv):
        print(f"错误: 文件不存在: {input_csv}")
        return

    print(f"分析文件: {input_csv}")
    df = pd.read_csv(input_csv)

    # JS提取
    print("\n[+] 从JS中提取路径...")
    try:
        found_paths = df[df['status_code'] == 200]['path'].tolist()
        print(f"    找到 {len(found_paths)} 个可访问路径用于JS提取")
        js_paths, checked_js = scan_js_for_paths('', found_paths, timeout=timeout)
        if js_paths:
            print(f"    提取到 {len(js_paths)} 个新路径")
        else:
            print(f"    未提取到新路径 (已检查 {checked_js} 个JS文件)")
    except Exception as e:
        print(f"    JS提取失败: {e}")

    # 敏感信息扫描
    print("\n[+] 扫描敏感信息...")
    try:
        found_paths = df[df['status_code'] == 200]['path'].tolist()
        findings, checked = scan_sensitive_files('', found_paths, timeout=timeout)
        if findings:
            print(f"    发现 {len(findings)} 条敏感信息")
        else:
            print(f"    未发现敏感信息")
    except Exception as e:
        print(f"    敏感信息扫描失败: {e}")

    # 生成HTML报告
    print("\n[+] 生成HTML报告...")
    generate_html_report(input_csv, output_html)
    print(f"    报告已生成: {output_html}")

def do_report(input_csv, output_html='data/report.html'):
    if not os.path.exists(input_csv):
        print(f"错误: 文件不存在: {input_csv}")
        return
    generate_html_report(input_csv, output_html)
    print(f"报告已生成: {output_html}")

def do_dict(args):
    if args.show:
        for fw, paths in FRAMEWORK_PATHS.items():
            print(f"\n{fw}: {len(paths)} 条路径")
            for p in paths[:10]:
                print(f"  {p}")
            if len(paths) > 10:
                print(f"  ... 还有 {len(paths)-10} 条")
        return

    if args.add:
        fw = args.framework if args.framework else 'java_spring'
        if fw not in FRAMEWORK_PATHS:
            FRAMEWORK_PATHS[fw] = []
        FRAMEWORK_PATHS[fw].append(args.add)
        save_framework_paths(FRAMEWORK_PATHS)
        print(f"已添加: {fw} → {args.add}")
        return

    print("请指定 --show 或 --add")
    print("  pathfinder dict --show")
    print("  pathfinder dict --add /admin")

def do_capture(args):
    capture_requests(args.url, args.output, args.wait)

def main():
    parser = argparse.ArgumentParser(description='PathFinder - AI-powered path scanner')
    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # ===== scan 子命令 =====
    sp = subparsers.add_parser('scan', help='完整扫描（框架识别 + 目录扫描 + JS提取 + 敏感信息 + HTML报告）')
    sp.add_argument('-u', '--url', required=True, help='目标URL')
    sp.add_argument('-d', '--dict', default='data/framework_paths.json', help='字典文件路径')
    sp.add_argument('--csv', default='data/scan_results.csv', help='CSV输出路径')
    sp.add_argument('-o', '--output', default='data/report.html', help='HTML报告输出路径')
    sp.add_argument('--workers', type=int, default=10, help='并发线程数 (默认: 10)')
    sp.add_argument('--timeout', type=int, default=3, help='请求超时秒数 (默认: 3)')
    sp.add_argument('--max-paths', type=int, default=0, help='最大扫描路径数 (默认: 0=不限)')
    sp.add_argument('--ai-limit', type=int, default=20, help='AI生成路径上限 (默认: 20)')
    sp.add_argument('--depth', type=int, default=3, help='最大路径深度 (默认: 3)')
    sp.add_argument('--no-cache', action='store_true', help='禁用404缓存')
    sp.add_argument('--no-ai', action='store_true', help='禁用AI路径生成')
    sp.add_argument('--resume', help='从之前的扫描结果继续')

    # ===== analyze 子命令 =====
    sp = subparsers.add_parser('analyze', help='分析已有CSV（JS提取 + 敏感信息 + HTML报告）')
    sp.add_argument('-i', '--input', required=True, help='CSV文件路径')
    sp.add_argument('-o', '--output', default='data/report.html', help='HTML报告输出路径')
    sp.add_argument('--workers', type=int, default=10, help='并发线程数 (默认: 10)')
    sp.add_argument('--timeout', type=int, default=3, help='请求超时秒数 (默认: 3)')

    # ===== report 子命令 =====
    sp = subparsers.add_parser('report', help='只生成HTML报告')
    sp.add_argument('-i', '--input', required=True, help='CSV文件路径')
    sp.add_argument('-o', '--output', default='data/report.html', help='HTML报告输出路径')

    # ===== dict 子命令 =====
    sp = subparsers.add_parser('dict', help='字典管理')
    sp.add_argument('--show', action='store_true', help='显示当前字典')
    sp.add_argument('--add', help='添加路径到字典')
    sp.add_argument('--fw', '--framework', help='指定框架名称 (默认: java_spring)')

    # ===== capture 子命令 =====
    sp = subparsers.add_parser('capture', help='Playwright抓包')
    sp.add_argument('-u', '--url', required=True, help='目标URL')
    sp.add_argument('-o', '--output', default='data/playwright_requests.json', help='JSON输出路径')
    sp.add_argument('--wait', type=int, default=3, help='页面等待时间 (默认: 3秒)')

    args = parser.parse_args()

    if args.command == 'scan':
        do_scan(
            args.url, args.dict,
            output_html=args.output,
            output_csv=args.csv,
            workers=args.workers,
            timeout=args.timeout,
            max_paths=args.max_paths,
            ai_limit=args.ai_limit,
            depth_limit=args.depth,
            cache_404=not args.no_cache,
            enable_ai=not args.no_ai,
            resume_file=args.resume
        )
    elif args.command == 'analyze':
        do_analyze(args.input, args.output, args.workers, args.timeout)
    elif args.command == 'report':
        do_report(args.input, args.output)
    elif args.command == 'dict':
        do_dict(args)
    elif args.command == 'capture':
        do_capture(args)
    else:
        parser.print_help()

def auto_scan_cli():
    main()

if __name__ == '__main__':
    main()
