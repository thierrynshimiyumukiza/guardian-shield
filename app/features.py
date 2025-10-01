import re
import pandas as pd
from scipy.stats import entropy
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict
import numpy as np
import json
import xml.etree.ElementTree as ET

class OWASPFeatureExtractor:
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
    COMMON_BROWSERS = ['mozilla', 'chrome', 'firefox', 'safari', 'edge', 'msie', 'opera', 'webkit']

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        text = str(text)
        counter = pd.Series(list(text)).value_counts()
        text_length = len(text)
        probabilities = counter / text_length
        return entropy(probabilities.to_numpy()) if len(counter) > 0 else 0.0

    @staticmethod
    def extract_features_from_request(request, body: str = '') -> Dict[str, float]:
        try:
            request_url = str(request.url)
            method = request.method
            user_agent = request.headers.get('user-agent', 'unknown')
            content_type = request.headers.get('content-type', '').lower()
            content = body
            if 'json' in content_type:
                try:
                    body_json = json.loads(body)
                    content = json.dumps(body_json)
                except:
                    pass
            elif 'xml' in content_type:
                try:
                    root = ET.fromstring(body)
                    content = ET.tostring(root, encoding='unicode')
                except:
                    pass
            content += request_url
            content_lower = content.lower()
            parsed_url = urlparse(request_url)
            query_params = parse_qs(parsed_url.query)
            features = {
                'url_length': len(request_url),
                'num_special_chars': sum(not c.isalnum() for c in content),
                'contains_sql_keywords': sum(1 for _ in re.finditer(OWASPFeatureExtractor.SQL_KEYWORDS, content_lower, re.IGNORECASE)),
                'contains_xss_patterns': sum(1 for _ in re.finditer(OWASPFeatureExtractor.XSS_PATTERNS, content_lower, re.IGNORECASE)),
                'contains_path_traversal': int(bool(re.search(OWASPFeatureExtractor.PATH_TRAVERSAL, content_lower, re.IGNORECASE))),
                'request_length': len(content),
                'request_time': 0.1,
                'is_get_method': int(method.upper() == 'GET'),
                'is_post_method': int(method.upper() == 'POST'),
                'ua_length': len(user_agent),
                'is_common_browser': int(any(b in user_agent.lower() for b in OWASPFeatureExtractor.COMMON_BROWSERS)),
                'content_entropy': float(OWASPFeatureExtractor._calculate_entropy(content)),
                'num_digits': sum(c.isdigit() for c in content),
                'num_uppercase': sum(c.isupper() for c in content),
                'sensitive_path_access': int(bool(re.search(OWASPFeatureExtractor.SENSITIVE_PATHS, request_url, re.IGNORECASE))),
                'admin_path_access': int(bool(re.search(OWASPFeatureExtractor.ADMIN_KEYWORDS, request_url, re.IGNORECASE))),
                'num_directory_levels': request_url.count('/'),
                'has_encrypted_content': int('https://' in request_url.lower()),
                'ssl_protocol_indicators': int('ssl' in content_lower or 'tls' in content_lower),
                'weak_cipher_indicators': int(bool(re.search(OWASPFeatureExtractor.WEAK_CIPHER_INDICATORS, content_lower, re.IGNORECASE))),
                'contains_command_injection': sum(1 for _ in re.finditer(OWASPFeatureExtractor.COMMAND_INJECTION, content_lower, re.IGNORECASE)),
                'contains_ldap_injection': sum(1 for _ in re.finditer(OWASPFeatureExtractor.LDAP_INJECTION, content_lower, re.IGNORECASE)),
                'contains_xxe_patterns': int(bool(re.search(OWASPFeatureExtractor.XXE_PATTERNS, content_lower, re.IGNORECASE))),
                'unusual_headers': sum(1 for h in request.headers if h.lower().startswith('x-')),
                'suspicious_content_types': int(content_type not in ['application/json', 'application/xml', 'text/plain', 'application/x-www-form-urlencoded']),
                'auth_related_paths': int(bool(re.search(OWASPFeatureExtractor.AUTH_PATHS, request_url, re.IGNORECASE))),
                'credential_like_patterns': int(bool(re.search(OWASPFeatureExtractor.CREDENTIAL_PATTERNS, content_lower, re.IGNORECASE))),
                'bruteforce_indicators': int('bot' in user_agent.lower() or len(query_params) > 10),
                'contains_serialized_data': int(bool(re.search(OWASPFeatureExtractor.SERIALIZATION_PATTERNS, content_lower, re.IGNORECASE))),
                'deserialization_indicators': int('serialized' in content_lower or 'deserialize' in content_lower),
                'contains_ssrf_patterns': int(bool(re.search(OWASPFeatureExtractor.SSRF_PATTERNS, content_lower, re.IGNORECASE))),
                'internal_ip_indicators': int(bool(re.search(OWASPFeatureExtractor.INTERNAL_IP, content_lower, re.IGNORECASE))),
                'localhost_references': int('localhost' in content_lower or '127.0.0.1' in content_lower),
                'parameter_count': len(query_params),
                'unusual_parameter_names': int(any(k.lower() in ['cmd', 'exec', 'shell', 'inject'] for k in query_params.keys())),
                'injection_pattern_score': 0
            }
            features['injection_pattern_score'] = min(
                features['contains_sql_keywords'] * 3 +
                features['contains_xss_patterns'] * 2 +
                features['contains_command_injection'] * 4 +
                features['contains_ldap_injection'] * 2 +
                features['contains_xxe_patterns'] * 2,
                10
            )
            return {k: float(v) for k, v in features.items()}
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return {k: 0.0 for k in [
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
            ]}

def extract_features_from_request(request, body: str = '') -> Dict[str, float]:
    return OWASPFeatureExtractor.extract_features_from_request(request, body)