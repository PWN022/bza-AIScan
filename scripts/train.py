import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import warnings
warnings.filterwarnings('ignore')

def train_model(data_file='data/scan_results.csv', model_file='output/dirai_model.pkl'):
    df = pd.read_csv(data_file)
    
    df = df[df['label'] != -1]
    df = df[df['status_code'] != -1]
    
    if len(df) < 10:
        print("Error: Not enough data. Need at least 10 labeled samples.")
        return None
    
    feature_cols = ['length', 'depth', 'has_dot', 'has_underline', 'has_dash',
                    'contains_admin', 'contains_login', 'contains_backup',
                    'contains_config', 'contains_zip', 'status_code',
                    'redirect_count', 'has_password_input', 'has_username_input',
                    'has_login_form', 'has_set_cookie', 'keyword_hits', 'page_length']
    
    X = df[feature_cols]
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"Model accuracy: {acc:.2%}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Sensitive']))
    
    importance = pd.DataFrame({
        'feature': feature_cols,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    print("\nTop 10 important features:")
    print(importance.head(10).to_string(index=False))
    
    joblib.dump(model, model_file)
    print(f"\nModel saved to {model_file}")
    
    return model

if __name__ == '__main__':
    train_model()
