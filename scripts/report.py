import pandas as pd
import os
from datetime import datetime

def generate_report(data_file='data/scan_results.csv', output_file='output/report.txt'):
    if not os.path.exists(data_file):
        print(f"Data file not found: {data_file}")
        return
    
    df = pd.read_csv(data_file)
    
    lines = []
    lines.append("=" * 60)
    lines.append("PathFinder - Scan Report")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Total paths scanned: {len(df)}")
    lines.append("")
    
    high_df = df[df['risk_level'] == 'High']
    medium_df = df[df['risk_level'] == 'Medium']
    sensitive_df = df[df['label'] == 1]
    
    lines.append("-" * 40)
    lines.append("Risk Level Summary")
    lines.append("-" * 40)
    lines.append(f"High risk: {len(high_df)}")
    lines.append(f"Medium risk: {len(medium_df)}")
    lines.append(f"Low risk: {len(df) - len(high_df) - len(medium_df)}")
    lines.append("")
    lines.append(f"Detected as sensitive (label=1): {len(sensitive_df)}")
    lines.append("")
    
    lines.append("-" * 40)
    lines.append("High Risk Paths")
    lines.append("-" * 40)
    if len(high_df) > 0:
        for _, row in high_df.iterrows():
            lines.append(f"  Path: {row['path']}")
            lines.append(f"    Status: {row['status_code']}")
            lines.append(f"    Category: {row.get('category', 'Unknown')}")
            lines.append(f"    Strategy: {row.get('status_strategy', 'Check manually')}")
            lines.append("")
    else:
        lines.append("  No high risk paths found.")
    lines.append("")
    
    lines.append("-" * 40)
    lines.append("Medium Risk Paths")
    lines.append("-" * 40)
    if len(medium_df) > 0:
        for _, row in medium_df.iterrows():
            lines.append(f"  Path: {row['path']}")
            lines.append(f"    Status: {row['status_code']}")
            lines.append(f"    Category: {row.get('category', 'Unknown')}")
            lines.append("")
    else:
        lines.append("  No medium risk paths found.")
    lines.append("")
    
    lines.append("-" * 40)
    lines.append("Status Code Analysis")
    lines.append("-" * 40)
    status_counts = df['status_code'].value_counts()
    for code, count in status_counts.items():
        lines.append(f"  {code}: {count}")
    lines.append("")
    
    if 'status_strategy' in df.columns:
        lines.append("-" * 40)
        lines.append("Recommended Actions")
        lines.append("-" * 40)
        strategies = df[df['status_strategy'].notna()]['status_strategy'].unique()
        for s in strategies:
            if s and len(s) > 0:
                lines.append(f"  - {s}")
    lines.append("")
    
    lines.append("=" * 60)
    lines.append("End of Report")
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w') as f:
        f.write('\n'.join(lines))
    
    print('\n'.join(lines))
    print(f"\nReport saved to {output_file}")
    
    return lines

if __name__ == '__main__':
    generate_report()
