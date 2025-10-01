# unified_security_agent.py
import pandas as pd
import numpy as np
from fastapi import FastAPI, Request
import datetime
import joblib
import os
import json
import re
from typing import Dict, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from pathlib import Path

# ==================== CONFIGURATION ====================
FEATURE_COLS = [
    'url_length',
    'num_special_chars',
    'contains_sql_keywords',
    'contains_xss_patterns',
    'contains_path_traversal',
    'request_length',
    'request_time',
    'is_get_method',
    'is_post_method',
    'ua_length',
    'is_common_browser'
]

COMMON_BROWSERS = ['mozilla', 'chrome', 'firefox', 'safari', 'edge', 'msie', 'opera', 'webkit']
SQL_KEYWORDS = r'\b(union|select|insert|drop|update|delete|from|where|or|and|exec|execute|declare|sleep|waitfor|delay)\b|--|/\*|\*/'
XSS_PATTERNS = r'\b(script|javascript|onerror|onload|onmouseover|alert|document\.cookie|eval|fromcharcode)\b|<script|javascript:|alert\('
PATH_TRAVERSAL = r'\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.%00|\.\.%00'

MODEL_PATH = './model.pkl'
SCALER_PATH = './scaler.pkl'
DATA_PATH = '../datasets/MASTER_training_dataset.csv'
DEBUG_LOG_PATH = './debug_requests.log'

# ==================== FEATURE EXTRACTION ====================
def extract_features_from_request(request: Request, body_text: str = "") -> Dict[str, int]:
    """
    Extract security features from HTTP request
    """
    url = str(request.url)
    method = request.method
    user_agent = request.headers.get('user-agent', '')
    
    features = {
        'url_length': min(len(url), 200),
        'num_special_chars': sum(not c.isalnum() for c in url),
        'contains_sql_keywords': int(bool(re.search(SQL_KEYWORDS, url + ' ' + body_text, re.IGNORECASE))),
        'contains_xss_patterns': int(bool(re.search(XSS_PATTERNS, url + ' ' + body_text, re.IGNORECASE))),
        'contains_path_traversal': int(bool(re.search(PATH_TRAVERSAL, url, re.IGNORECASE))),
        'request_length': min(len(body_text), 1000),
        'request_time': 0.1,
        'is_get_method': int(method.upper() == 'GET'),
        'is_post_method': int(method.upper() == 'POST'),
        'ua_length': min(len(user_agent), 200),
        'is_common_browser': int(any(b in user_agent.lower() for b in COMMON_BROWSERS))
    }
    
    return features

def extract_from_log_line(log_line: str) -> Optional[Dict[str, int]]:
    """
    Extract features from log line
    """
    log_pattern = (
        r'(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) '
        r'"([^"]*)" "([^"]*)" "([^"]*)" Request_Length:(\d+) Request_Time:([0-9.]+)'
    )
    match = re.match(log_pattern, log_line)
    if not match:
        return None
    
    groups = match.groups()
    try:
        request_length = int(groups[13])
    except Exception:
        request_length = 0
    try:
        request_time = float(groups[14])
    except Exception:
        request_time = 0.0
        
    url = groups[5]
    method = groups[4]
    user_agent = groups[10]
    
    return {
        'url_length': min(len(url), 200),
        'num_special_chars': sum(not c.isalnum() for c in url),
        'contains_sql_keywords': int(bool(re.search(SQL_KEYWORDS, url, re.IGNORECASE))),
        'contains_xss_patterns': int(bool(re.search(XSS_PATTERNS, url, re.IGNORECASE))),
        'contains_path_traversal': int(bool(re.search(PATH_TRAVERSAL, url, re.IGNORECASE))),
        'request_length': request_length,
        'request_time': request_time,
        'is_get_method': int(method.upper() == 'GET'),
        'is_post_method': int(method.upper() == 'POST'),
        'ua_length': min(len(user_agent), 200),
        'is_common_browser': int(any(b in user_agent.lower() for b in COMMON_BROWSERS))
    }

# ==================== DATA PROCESSING ====================
def load_jsonl_payloads(filepath: str) -> pd.DataFrame:
    """Load malicious payloads from JSON"""
    data = []
    if not Path(filepath).exists():
        return pd.DataFrame()
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            arr = json.load(f)
            for entry in arr:
                payload = entry.get('payload', '')
                if payload:
                    features = {
                        'url_length': min(len(payload), 200),
                        'num_special_chars': sum(not c.isalnum() for c in payload),
                        'contains_sql_keywords': int(bool(re.search(SQL_KEYWORDS, payload, re.IGNORECASE))),
                        'contains_xss_patterns': int(bool(re.search(XSS_PATTERNS, payload, re.IGNORECASE))),
                        'contains_path_traversal': int(bool(re.search(PATH_TRAVERSAL, payload, re.IGNORECASE))),
                        'request_length': len(payload),
                        'request_time': 0.1,
                        'is_get_method': 0,
                        'is_post_method': 1,
                        'ua_length': 0,
                        'is_common_browser': 0,
                        'is_malicious': 1,
                        'source': 'jsonl_payloads'
                    }
                    data.append(features)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        
    return pd.DataFrame(data)

def load_lab_data(log_filepath: str) -> pd.DataFrame:
    """Load lab data from log file"""
    data = []
    if not Path(log_filepath).exists():
        return pd.DataFrame()
        
    try:
        with open(log_filepath, 'r', encoding='utf-8') as file:
            for line in file:
                features = extract_from_log_line(line.strip())
                if features:
                    is_malicious = int(
                        any(keyword in line.lower() for keyword in [
                            'union', 'select', '<script', '../', '%20', 'alert(', 'insert', 'drop', 'update', 'delete'
                        ])
                    )
                    features['is_malicious'] = is_malicious
                    features['source'] = 'lab'
                    data.append(features)
    except Exception as e:
        print(f"Error reading lab log: {e}")
        
    return pd.DataFrame(data)

def generate_synthetic_benign_data(num_samples=2000):
    """Generate synthetic benign data for balancing"""
    synthetic_data = []
    for _ in range(num_samples):
        features = {
            'url_length': np.random.randint(10, 100),
            'num_special_chars': np.random.randint(1, 10),
            'contains_sql_keywords': 0,
            'contains_xss_patterns': 0,
            'contains_path_traversal': 0,
            'request_length': np.random.randint(10, 200),
            'request_time': 0.1,
            'is_get_method': np.random.choice([0, 1]),
            'is_post_method': np.random.choice([0, 1]),
            'ua_length': np.random.randint(50, 150),
            'is_common_browser': 1,
            'is_malicious': 0,
            'source': 'synthetic'
        }
        synthetic_data.append(features)
    return pd.DataFrame(synthetic_data)

def balance_dataset(df):
    """Balance the dataset"""
    malicious_count = df['is_malicious'].sum()
    benign_count = len(df) - malicious_count
    
    if malicious_count > benign_count:
        malicious_df = df[df['is_malicious'] == 1]
        benign_df = df[df['is_malicious'] == 0]
        malicious_sampled = malicious_df.sample(benign_count, random_state=42)
        return pd.concat([malicious_sampled, benign_df])
    else:
        benign_df = df[df['is_malicious'] == 0]
        malicious_df = df[df['is_malicious'] == 1]
        benign_sampled = benign_df.sample(malicious_count, random_state=42)
        return pd.concat([benign_sampled, malicious_df])

def build_master_dataset():
    """Build the master training dataset"""
    output_file = Path('../datasets/MASTER_training_dataset.csv')
    output_file.parent.mkdir(exist_ok=True)

    master_data = pd.DataFrame()
    
    # Load from different sources
    sources = [
        ('../datasets/WEB_APPLICATION_PAYLOADS_FIXED.json', load_jsonl_payloads),
        ('../logs/access.log', load_lab_data)
    ]

    for path, loader in sources:
        if Path(path).exists():
            df = loader(path)
            master_data = pd.concat([master_data, df], ignore_index=True)
            print(f"{path}: {len(df)} entries loaded")
        else:
            print(f"File not found: {path}")

    # Add synthetic benign data
    synthetic_benign = generate_synthetic_benign_data(2000)
    master_data = pd.concat([master_data, synthetic_benign], ignore_index=True)

    # Ensure all required columns
    for col in FEATURE_COLS + ['is_malicious', 'source']:
        if col not in master_data.columns:
            master_data[col] = 0

    # Balance the dataset
    master_data = balance_dataset(master_data)
    master_data = master_data[FEATURE_COLS + ['is_malicious', 'source']]
    
    # Remove any remaining NaN values
    master_data = master_data.fillna(0)
    
    master_data.to_csv(output_file, index=False)
    print(f"\n[SUCCESS] Master dataset created with {len(master_data)} entries!")
    print(f"Malicious: {master_data['is_malicious'].sum()}")
    print(f"Benign: {len(master_data) - master_data['is_malicious'].sum()}")
    
    return master_data

# ==================== MODEL TRAINING ====================
def train_model():
    """Train the security model"""
    print("Loading dataset...")
    if not Path(DATA_PATH).exists():
        print("Dataset not found, building it...")
        df = build_master_dataset()
    else:
        df = pd.read_csv(DATA_PATH)
    
    # Handle missing values
    for col in FEATURE_COLS + ['is_malicious']:
        if col not in df.columns:
            df[col] = 0
        df[col] = df[col].fillna(0)

    X = df[FEATURE_COLS]
    y = df['is_malicious'].astype(int)

    print(f"Class distribution: {y.value_counts().to_dict()}")

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_val, y_train, y_val = train_test_split(
        X_scaled, y, test_size=0.15, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    clf.fit(X_train, y_train)

    val_accuracy = clf.score(X_val, y_val)
    print(f"Validation accuracy: {val_accuracy:.4f}")
    
    y_pred = clf.predict(X_val)
    y_pred_proba = clf.predict_proba(X_val)[:, 1]
    
    print("Classification report:")
    print(classification_report(y_val, y_pred, digits=4))
    print("Confusion matrix:")
    print(confusion_matrix(y_val, y_pred))
    
    # Save model and scaler
    Path(MODEL_PATH).parent.mkdir(exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"Model saved to {MODEL_PATH}")
    print(f"Scaler saved to {SCALER_PATH}")

    return clf, scaler

# ==================== FASTAPI APP ====================
app = FastAPI()

# Load model and scaler
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("Model and scaler loaded successfully")
except:
    print("Model not found, training new one...")
    model, scaler = train_model()

def log_debug(data: Dict):
    """Log debug information"""
    with open(DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(data) + "\n")

@app.post("/analyze")
async def analyze(request: Request):
    """Analyze HTTP request for security threats"""
    try:
        body = await request.body()
        body_text = body.decode("utf-8") if isinstance(body, bytes) else str(body)
        
        # Extract features
        features_dict = extract_features_from_request(request, body_text)
        features = [features_dict[feature] for feature in FEATURE_COLS]
        
        # Scale features
        features_scaled = scaler.transform([features])
        
        # Predict
        proba = model.predict_proba(features_scaled)[0]
        malicious_score = float(proba[1])
        threshold = 0.7

        prediction = int(malicious_score >= threshold)
        result = {
            "features": features_dict,
            "prediction": prediction,
            "malicious_probability": malicious_score,
            "message": "Malicious request detected!" if prediction else "Request appears safe."
        }

        # Log for debugging
        debug_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "url": str(request.url),
            "method": request.method,
            "headers": dict(request.headers),
            "body": body_text,
            "features": features_dict,
            "malicious_probability": malicious_score,
            "prediction": prediction,
            "threshold": threshold
        }
        log_debug(debug_data)
        
        return result
        
    except Exception as e:
        return {"error": str(e), "message": "Failed to process request"}

@app.get("/debug/logs")
def get_debug_logs(limit: int = 20):
    """Get debug logs"""
    if not os.path.exists(DEBUG_LOG_PATH):
        return {"logs": []}
    with open(DEBUG_LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()[-limit:]
        logs = [json.loads(line) for line in lines]
    return {"logs": logs}

@app.get("/train")
def train_endpoint():
    """Trigger model training"""
    global model, scaler
    model, scaler = train_model()
    return {"message": "Model trained successfully"}

@app.get("/")
async def root():
    return {"message": "Security API is running!"}

# ==================== MAIN EXECUTION ====================
if __name__ == "__main__":
    # For training only
    train_model()
    print("Training completed. Run with: uvicorn unified_security_agent:app --reload")