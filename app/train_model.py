import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve
from sklearn.feature_selection import SelectFromModel
from sklearn.calibration import CalibratedClassifierCV
import joblib
import os
import numpy as np
import logging
from datetime import datetime

# Configure logging to console only
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Define OWASP features
OWASP_FEATURES = [
    'url_length', 'num_special_chars', 'contains_sql_keywords', 'contains_xss_patterns',
    'contains_path_traversal', 'request_length', 'request_time', 'is_get_method',
    'is_post_method', 'ua_length', 'is_common_browser', 'content_entropy', 'num_digits',
    'num_uppercase', 'sensitive_path_access', 'admin_path_access', 'num_directory_levels',
    'has_encrypted_content', 'ssl_protocol_indicators', 'weak_cipher_indicators',
    'contains_command_injection', 'contains_ldap_injection', 'contains_xxe_patterns',
    'unusual_headers', 'suspicious_content_types', 'auth_related_paths',
    'credential_like_patterns', 'bruteforce_indicators', 'contains_serialized_data',
    'deserialization_indicators', 'contains_ssrf_patterns', 'internal_ip_indicators',
    'localhost_references', 'parameter_count', 'unusual_parameter_names',
    'injection_pattern_score'
]

# Define file paths with fallbacks
DATA_PATH = os.getenv("DATA_PATH", "../datasets/MASTER_training_dataset.csv")
MODEL_PATH = os.getenv("MODEL_PATH", "models/model.pkl")
THRESHOLD_PATH = os.getenv("THRESHOLD_PATH", "models/threshold.pkl")
FEATURES_PATH = os.getenv("FEATURES_PATH", "models/selected_features.pkl")
CALIBRATOR_PATH = os.getenv("CALIBRATOR_PATH", "models/calibrator.pkl")

def validate_and_prepare_df(df: pd.DataFrame) -> pd.DataFrame:
    """Validate and prepare the dataset by ensuring all features exist and are numeric."""
    logger.info(f"Original dataset shape: {df.shape}")
    for col in OWASP_FEATURES:
        if col not in df.columns:
            logger.warning(f"Feature {col} missing, initializing to 0")
            df[col] = 0
    df = df.fillna(0)
    df = df.dropna(subset=['is_malicious'])
    for col in OWASP_FEATURES:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        if col in ['contains_sql_keywords', 'contains_xss_patterns', 'contains_path_traversal', 
                   'contains_command_injection', 'contains_ldap_injection', 'contains_xxe_patterns', 
                   'is_get_method', 'is_post_method', 'is_common_browser']:
            df[col] = df[col].clip(0, 1).astype(int)
        if col in ['url_length', 'request_length', 'ua_length', 'num_special_chars', 
                   'num_digits', 'num_uppercase', 'parameter_count']:
            df[col] = df[col].clip(lower=0)
        if col == 'content_entropy':
            df[col] = df[col].clip(0, 8)
    logger.info(f"Validated dataset shape: {df.shape}")
    return df

def calculate_sample_weights(y, df):
    """Calculate sample weights based on critical pattern prevalence."""
    weights = np.ones(len(y))
    critical_patterns = {
        'contains_sql_keywords': 0.5,
        'contains_xss_patterns': 0.4,
        'contains_path_traversal': 0.4,
        'contains_command_injection': 0.8,
        'contains_ldap_injection': 1.8,
        'contains_xxe_patterns': 1.8
    }
    for feature, weight in critical_patterns.items():
        if feature in df.columns:
            prevalence = min(df[feature].mean(), 0.5)
            adjusted_weight = weight / (prevalence + 0.1)
            weights += df[feature].values * adjusted_weight
    weights = np.clip(weights, 0.5, 2.0)
    logger.info(f"Weights: Min={weights.min():.2f}, Max={weights.max():.2f}, Mean={weights.mean():.2f}")
    return weights

def main():
    """Main training function to build and save the model."""
    logger.info("Starting training...")
    if not os.path.exists(DATA_PATH):
        logger.error(f"Dataset not found: {DATA_PATH}")
        return
    
    # Load and prepare data
    df = pd.read_csv(DATA_PATH)
    if df.empty or df.shape[0] < 100:
        logger.error("Dataset too small or empty")
        return
    df = validate_and_prepare_df(df)
    if 'is_malicious' not in df.columns:
        logger.error("No 'is_malicious' column")
        return
    
    X = df[OWASP_FEATURES]
    y = df['is_malicious'].astype(int)
    logger.info(f"Class distribution: {y.value_counts().to_dict()}")
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(X_train, y_train, test_size=0.2, random_state=42, stratify=y_train)
    
    # Calculate sample weights
    sample_weights = calculate_sample_weights(y_train, X_train)
    pos_weight = (y_train == 0).sum() / (y_train == 1).sum() * 0.9
    
    # Initialize and tune model
    clf = XGBClassifier(
        objective='binary:logistic', n_estimators=200, learning_rate=0.05, max_depth=5,
        subsample=0.8, colsample_bytree=0.7, reg_alpha=0.3, reg_lambda=0.3,
        random_state=42, scale_pos_weight=pos_weight
    )
    param_grid = {
        'learning_rate': [0.05, 0.1],
        'subsample': [0.8, 0.9]
    }
    grid_search = GridSearchCV(clf, param_grid, cv=3, scoring='f1', n_jobs=1)  # Single job to save memory
    grid_search.fit(X_train, y_train, sample_weight=sample_weights)
    clf = grid_search.best_estimator_
    logger.info(f"Best params: {grid_search.best_params_}")
    
    # Feature selection
    selector = SelectFromModel(clf, threshold='median', prefit=True)
    X_train_sel = selector.transform(X_train)
    X_val_sel = selector.transform(X_val)
    X_test_sel = selector.transform(X_test)
    selected_features = [OWASP_FEATURES[i] for i in selector.get_support(indices=True)]
    critical_features = ['contains_sql_keywords', 'contains_xss_patterns', 'contains_command_injection', 
                        'contains_ldap_injection', 'contains_xxe_patterns']
    for feature in critical_features:
        if feature not in selected_features and feature in OWASP_FEATURES:
            selected_features.append(feature)
            idx = OWASP_FEATURES.index(feature)
            X_train_sel = np.column_stack([X_train_sel, X_train.iloc[:, idx]])
            X_val_sel = np.column_stack([X_val_sel, X_val.iloc[:, idx]])
            X_test_sel = np.column_stack([X_test_sel, X_test.iloc[:, idx]])
    
    # Train and calibrate
    clf.fit(X_train_sel, y_train, sample_weight=sample_weights)
    calibrator = CalibratedClassifierCV(clf, cv=3, method='sigmoid')
    calibrator.fit(X_val_sel, y_val)
    
    # Optimize threshold
    y_val_proba = calibrator.predict_proba(X_val_sel)[:, 1]
    _, _, thresholds = precision_recall_curve(y_val, y_val_proba)
    optimal_threshold = max(thresholds[np.argmax(thresholds >= 0.7)], 0.7)
    y_val_pred = (y_val_proba >= optimal_threshold).astype(int)
    
    # Validation results
    logger.info("\nValidation Results:")
    logger.info(classification_report(y_val, y_val_pred))
    logger.info(f"Confusion Matrix:\n{confusion_matrix(y_val, y_val_pred)}")
    
    # Test results
    y_test_proba = calibrator.predict_proba(X_test_sel)[:, 1]
    y_test_pred = (y_test_proba >= optimal_threshold).astype(int)
    logger.info("\nTest Results:")
    logger.info(classification_report(y_test, y_test_pred))
    
    # Save models and artifacts
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(optimal_threshold, THRESHOLD_PATH)
    joblib.dump(selected_features, FEATURES_PATH)
    joblib.dump(calibrator, CALIBRATOR_PATH)
    logger.info("Training complete")

if __name__ == '__main__':
    main()