import pandas as pd
import joblib
import sys

def analyze_with_model(data_file, model_file='output/dirai_model.pkl'):
    try:
        model = joblib.load(model_file)
    except:
        print("Error: Model file not found. Please run train.py first.")
        return
    
    df = pd.read_csv(data_file)
    print(f"Analyzing {len(df)} paths from {data_file}")
    
    if 'label' not in df.columns:
        print("Warning: No 'label' column found. Using model for prediction.")
        feature_cols = ['length', 'depth', 'has_dot', 'has_underline', 'has_dash',
                        'contains_admin', 'contains_login', 'contains_backup',
                        'contains_config', 'contains_zip', 'status_code',
                        'redirect_count', 'has_password_input', 'has_username_input',
                        'has_login_form', 'has_set_cookie', 'keyword_hits', 'page_length']
        X = df[feature_cols]
        df['predicted'] = model.predict(X)
        sensitive = df[df['predicted'] == 1]
    else:
        sensitive = df[df['label'] == 1]
    
    print(f"\nFound {len(sensitive)} sensitive paths:")
    for _, row in sensitive.iterrows():
        path = row.get('path', 'unknown')
        status = row.get('status_code', 'N/A')
        print(f"  - {path} (status: {status})")
    
    return sensitive

if __name__ == '__main__':
    if len(sys.argv) > 1:
        analyze_with_model(sys.argv[1])
    else:
        print("Usage: python analyze.py <data_file.csv>")
        print("Example: python analyze.py data/scan_results.csv")
