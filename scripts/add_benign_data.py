import pandas as pd
import random
from pathlib import Path

# Path to your master dataset
DATASET_PATH = "../datasets/MASTER_training_dataset.csv"
OUTPUT_PATH = "../datasets/MASTER_training_dataset.csv"  # Overwrite or change as needed

# Define a list of short, simple, realistic benign payloads
benign_payloads = [
    "Hello, world!", "test", "foo", "bar", "index", "home", "about", "contact", "api", "status",
    "ping", "health", "main", "welcome", "submit", "info", "check", "simple", "none", "plain",
    "short", "quick", "get", "post", "data", "details", "profile", "user", "root", "page", "list",
    "view", "open", "new", "old", "admin", "dashboard", "table", "row", "col", "item", "products",
    "services", "news", "blog", "update", "delete", "add", "edit", "next", "previous", "first",
    "last", "recent", "login", "logout", "register", "signup", "signin", "help", "faq", "support"
]

def random_user_agent():
    browsers = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
        "Mozilla/5.0 (Android 10; Mobile; rv:79.0) Gecko/79.0 Firefox/79.0"
    ]
    return random.choice(browsers)

def extract_features(payload, method="POST", user_agent=None):
    SQL_KEYWORDS = r'\b(union|select|insert|drop|update|delete|from|where|or|and|exec|execute|declare|sleep|waitfor|delay)\b|--|/\*|\*/'
    XSS_PATTERNS = r'\b(script|javascript|onerror|onload|onmouseover|alert|document\.cookie|eval|fromcharcode)\b|<script|javascript:|alert\('
    PATH_TRAVERSAL = r'\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.%00|\.\.%00'
    if user_agent is None:
        user_agent = random_user_agent()
    features = {
        'url_length': len(payload),
        'num_special_chars': sum(not c.isalnum() for c in payload),
        'contains_sql_keywords': int(bool(pd.notnull(payload) and pd.Series([payload]).str.contains(SQL_KEYWORDS, case=False, regex=True).iloc[0])),
        'contains_xss_patterns': int(bool(pd.notnull(payload) and pd.Series([payload]).str.contains(XSS_PATTERNS, case=False, regex=True).iloc[0])),
        'contains_path_traversal': int(bool(pd.notnull(payload) and pd.Series([payload]).str.contains(PATH_TRAVERSAL, case=False, regex=True).iloc[0])),
        'request_length': len(payload),
        'request_time': 12,  # Arbitrary, not used in detection
        'is_get_method': int(method.upper() == 'GET'),
        'is_post_method': int(method.upper() == 'POST'),
        'ua_length': len(user_agent),
        'is_common_browser': int(any(b in user_agent.lower() for b in ['chrome', 'firefox', 'safari', 'edge', 'msie', 'opera', 'mozilla', 'webkit'])),
        'is_malicious': 0,
        'source': 'augmented_benign'
    }
    return features

def main():
    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH)

    # Generate 500 new benign samples (customize as needed)
    new_benign = []
    for _ in range(500):
        payload = random.choice(benign_payloads)
        user_agent = random_user_agent()
        method = random.choice(["GET", "POST"])
        features = extract_features(payload, method, user_agent)
        new_benign.append(features)

    benign_df = pd.DataFrame(new_benign)
    print(f"Generated {len(benign_df)} new benign samples.")

    # Append and shuffle
    df_aug = pd.concat([df, benign_df], ignore_index=True)
    df_aug = df_aug.sample(frac=1, random_state=42).reset_index(drop=True)
    df_aug.to_csv(OUTPUT_PATH, index=False)
    print(f"Augmented dataset saved to: {OUTPUT_PATH}")

    print("Preview of new benign samples:")
    print(benign_df.head())

if __name__ == "__main__":
    main()