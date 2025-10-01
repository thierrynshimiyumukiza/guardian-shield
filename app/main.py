from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import datetime
import joblib
import os
import pandas as pd
import json
from typing import Dict, Optional
import time
import numpy as np
import re
from urllib.parse import unquote
import requests
import aiosmtplib
from email.message import EmailMessage
from jinja2 import Template
import xml.etree.ElementTree as ET
from features import extract_features_from_request
import logging
from dotenv import load_dotenv
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.utils.validation")

# Load environment variables
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Security Agent", version="3.1")
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

templates = Jinja2Templates(directory="templates")

# Environment variables with fallback
MODEL_PATH = os.getenv("MODEL_PATH", "G:/ai-security-agent-lab/ai-agent/app/models/model.pkl")
THRESHOLD_PATH = os.getenv("THRESHOLD_PATH", "G:/ai-security-agent-lab/ai-agent/app/models/threshold.pkl")
FEATURES_PATH = os.getenv("FEATURES_PATH", "G:/ai-security-agent-lab/ai-agent/app/models/selected_features.pkl")
CALIBRATOR_PATH = os.getenv("CALIBRATOR_PATH", "G:/ai-security-agent-lab/ai-agent/app/models/calibrator.pkl")
DEBUG_LOG_PATH = os.getenv("DEBUG_LOG_PATH", "G:/ai-security-agent-lab/ai-agent/app/logs/debug_requests.log")
BLOCKED_REQUESTS_LOG = os.getenv("BLOCKED_REQUESTS_LOG", "G:/ai-security-agent-lab/ai-agent/app/logs/blocked_requests.log")
ALL_REQUESTS_LOG = os.getenv("ALL_REQUESTS_LOG", "G:/ai-security-agent-lab/ai-agent/app/logs/all_requests.log")
HF_API_TOKEN = os.getenv("HF_API_TOKEN", "")
HF_API_URL = os.getenv("HF_API_URL", "https://api-inference.huggingface.co/models/unitary/toxic-bert")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "thierrynshimiyumukiza@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "zfui tvar rlxw okil")
NOTIFY_EMAIL = os.getenv("NOTIFY_EMAIL", "thierrynshimiyumukiza@gmail.com")
API_KEY = os.getenv("I removed the random api part")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(api_key: str = Depends(api_key_header)) -> str:
    if not api_key or api_key != API_KEY:
        logger.warning(f"Invalid API key attempt: {api_key}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    logger.info(f"Valid API key accepted: {api_key}")
    return api_key

class SecurityModel:
    def __init__(self):
        self.model = None
        self.threshold = 0.70
        self.effective_threshold = 0.70
        self.feature_names = []
        self.calibrator = None
        self.loaded = False

    def load_models(self):
        try:
            self.model = joblib.load(MODEL_PATH)
            self.threshold = max(min(joblib.load(THRESHOLD_PATH), 0.85), 0.70)
            self.feature_names = joblib.load(FEATURES_PATH)
            self.calibrator = joblib.load(CALIBRATOR_PATH)
            self.loaded = True
            logger.info(f"Loaded models: {len(self.feature_names)} features, threshold {self.threshold}")
        except Exception as e:
            logger.error(f"Model load error: {e}")
            self.loaded = False

    def predict(self, features_dict: Dict) -> tuple[float, int]:
        if not self.loaded:
            return 0.0, 0
        try:
            features = [features_dict.get(f, 0) for f in self.feature_names]
            df = pd.DataFrame([features], columns=self.feature_names)
            prob = self.calibrator.predict_proba(df)[0, 1] if self.calibrator else self.model.predict_proba(df)[0, 1]
            pred = 1 if prob >= self.effective_threshold else 0
            return prob, pred
        except Exception as e:
            logger.error(f"Predict error: {e}")
            return 0.0, 0

class OWASPRulesEngine:
    @staticmethod
    def is_whitelisted_request(text: str, path: str) -> bool:
        if not text.strip():
            return True
        try:
            decoded = unquote(text)
        except:
            decoded = text
        decoded_lower = decoded.lower()
        benign_patterns = [
            r'^search=[a-zA-Z0-9\s\+\-]+$',
            r'^query=[a-zA-Z0-9\s\+\-]+$',
            r'^email=[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$',
            r'^username=[a-zA-Z0-9_-]+$',
            r'^password=[a-zA-Z0-9!@#$%^&*()_+-=]+$',
            r'^name=[a-zA-Z\s]+$',
            r'^title=[a-zA-Z0-9\s]+$',
            r'^message=[a-zA-Z0-9\s\.!,?]+$',
            r'^content=[a-zA-Z0-9\s\.!,?]+$',
            r'^q=[a-zA-Z0-9\s\+]+$',
            r'^term=[a-zA-Z0-9\s]+$',
            r'^id=\d+$', r'^page=\d+$', r'^limit=\d+$', r'^offset=\d+$',
        ]
        params = decoded_lower.split('&')
        for param in params:
            param = param.strip()
            if not param or any(re.match(p, param) for p in benign_patterns):
                continue
            if '=' in param:
                key, value = param.split('=', 1)
                common_keys = ['search', 'query', 'email', 'username', 'name', 'title', 'message', 'content', 'q', 'term', 'id', 'page', 'limit', 'offset', 'sort', 'order', 'filter', 'type']
                if key in common_keys and len(value) < 200 and re.match(r'^[a-zA-Z0-9\s\.@\-_\+!?=]*$', value):
                    continue
            return False
        return True

    @staticmethod
    def check_critical_patterns(features: Dict, text: str) -> tuple[bool, str]:
        if not text:
            return False, ""
        try:
            decoded = unquote(text)
        except:
            decoded = text
        decoded_lower = decoded.lower()
        sql_patterns = [
            r"'\s+or\s+1=1\s*--", r"union\s+select.*from", r"insert\s+into.*values",
            r"drop\s+table", r"exec\(|exec\x20", r"waitfor\s+delay", r"sleep\s*\(",
            r"benchmark\s*\(", r";\s*select", r"'\s+union\s+"
        ]
        for p in sql_patterns:
            if re.search(p, decoded_lower, re.IGNORECASE):
                return True, f"critical_sql_pattern_{p[:15]}"
        xss_patterns = [
            r"<script[^>]*>.*</script>", r"javascript:\s*alert", r"onload\s*=\s*[^>]*",
            r"onerror\s*=\s*[^>]*", r"onclick\s*=\s*[^>]*", r"eval\s*\(", r"document\.cookie"
        ]
        for p in xss_patterns:
            if re.search(p, decoded_lower, re.IGNORECASE):
                return True, f"critical_xss_pattern_{p[:15]}"
        cmd_patterns = [
            r"[;&|`]\s*(ls|cat|rm|wget|curl|nc|bash|sh)\s", r"\$\{.*\}", r"\(\s*.*\s*\)",
            r"\|.*\s*cat", r";\s*rm\s+-"
        ]
        for p in cmd_patterns:
            if re.search(p, decoded_lower, re.IGNORECASE):
                return True, f"critical_cmd_pattern_{p[:15]}"
        if re.search(r"\.\./\.\./\.\./", decoded_lower):
            return True, "critical_path_traversal"
        ldap_patterns = [r"\(\w+=.*\)", r"\*\w+\*", r"null.*null"]
        for p in ldap_patterns:
            if re.search(p, decoded_lower):
                return True, f"critical_ldap_pattern_{p[:10]}"
        if (features.get('contains_command_injection', 0) > 0 and features.get('injection_pattern_score', 0) >= 9):
            return True, "high_confidence_command_injection"
        if (features.get('contains_xss_patterns', 0) > 0 and features.get('content_entropy', 0) > 7.0 and features.get('injection_pattern_score', 0) >= 8):
            return True, "high_confidence_xss"
        if (features.get('contains_sql_keywords', 0) >= 3 and features.get('injection_pattern_score', 0) >= 9):
            return True, "high_confidence_sql_injection"
        return False, ""

class SecurityLogger:
    @staticmethod
    def log_request(data: Dict, path: str):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(data, default=str) + "\n")
        except Exception as e:
            logger.error(f"Log error {path}: {e}")

    @staticmethod
    async def log_security_event(event_type: str, request: Request, details: Dict):
        data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event_type": event_type,
            "url": str(request.url),
            "method": request.method,
            "client_ip": request.client.host if request.client else "unknown",
            **details
        }
        log_path = BLOCKED_REQUESTS_LOG if event_type in ["blocked", "suspicious"] else ALL_REQUESTS_LOG
        SecurityLogger.log_request(data, log_path)
        SecurityLogger.log_request(data, DEBUG_LOG_PATH)
        if event_type == "blocked":
            reason = details.get("reason", "unknown")
            mitigation = get_mitigation_steps(reason)
            await send_email_notification(data, reason, mitigation)

def get_mitigation_steps(reason: str) -> str:
    mitigations = {
        "critical_sql_pattern_': or 1=1 --": "Use parameterized queries. OWASP SQLi Prevention Cheat Sheet.",
        "critical_xss_pattern_<script": "Implement output encoding and CSP. OWASP XSS Prevention Cheat Sheet.",
        "critical_cmd_pattern_[;&|`]": "Avoid shell commands; use whitelists. OWASP Command Injection.",
        "critical_path_traversal": "Validate file paths against allowlists.",
        "critical_ldap_pattern_(": "Escape LDAP special characters in queries.",
        "high_confidence_command_injection": "Sanitize inputs for shell commands.",
        "high_confidence_xss": "Use Content Security Policy and encode outputs.",
        "high_confidence_sql_injection": "Adopt prepared statements for database queries.",
        "llm_toxic": "Review request for malicious intent; sanitize inputs.",
        "ml_detection": "Review ML features; consider retraining model.",
        "unknown": "Investigate logs and update security rules."
    }
    return mitigations.get(reason, mitigations["unknown"])

async def send_email_notification(data: Dict, reason: str, mitigation: str):
    if not SMTP_USER or not SMTP_PASS:
        logger.warning("Email config missing")
        return
    subject = f"AI Security Alert: {reason.upper()} Detected"
    template = Template("""
    <html>
    <body>
        <h2>AI Security Agent Alert</h2>
        <p><strong>Timestamp:</strong> {{ timestamp }}</p>
        <p><strong>URL:</strong> {{ url }}</p>
        <p><strong>Method:</strong> {{ method }}</p>
        <p><strong>Client IP:</strong> {{ client_ip }}</p>
        <p><strong>Reason:</strong> {{ reason }}</p>
        <p><strong>Mitigation:</strong> {{ mitigation }}</p>
        <p><strong>Details:</strong> <pre>{{ details }}</pre></p>
    </body>
    </html>
    """)
    body_html = template.render(
        timestamp=data["timestamp"], url=data["url"], method=data["method"],
        client_ip=data["client_ip"], reason=reason, mitigation=mitigation,
        details=json.dumps(data.get("features", {}), indent=2)
    )
    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = NOTIFY_EMAIL
    msg["Subject"] = subject
    msg.set_content(body_html, subtype="html")
    try:
        await aiosmtplib.send(msg, hostname=SMTP_HOST, port=SMTP_PORT, username=SMTP_USER, password=SMTP_PASS, use_tls=True)
        logger.info("Email notification sent")
    except Exception as e:
        logger.error(f"Email send error: {e}")

async def hf_threat_analysis(body_text: str) -> Dict[str, str]:
    if not body_text or len(body_text) < 10 or not re.search(r'[<>;=\'"&]', body_text):
        return {"threat_level": "low", "reason": "Low risk or empty text", "mitigation": "None needed"}
    if not HF_API_TOKEN:
        logger.warning("HF_API_TOKEN missing, skipping LLM analysis")
        return {"threat_level": "medium", "reason": "LLM disabled", "mitigation": "Fallback to rules/ML"}
    try:
        headers = {"Authorization": f"Bearer {HF_API_TOKEN}"}
        payload = {"inputs": body_text[:500]}
        resp = requests.post(HF_API_URL, json=payload, headers=headers, timeout=10)
        result = resp.json()
        score = max([item['score'] for item in result if item['label'].startswith('toxic')]) if result else 0.0
        threat_level = "high" if score > 0.8 else "medium" if score > 0.5 else "low"
        reason = f"Toxic score: {score:.2f}" if result else "Analysis failed"
        mitigation = "Review request for malicious intent; sanitize inputs." if threat_level == "high" else "Monitor request patterns."
        return {"threat_level": threat_level, "reason": reason, "mitigation": mitigation}
    except Exception as e:
        logger.error(f"Hugging Face error: {e}")
        return {"threat_level": "medium", "reason": f"Analysis failed: {str(e)}", "mitigation": "Fallback to rules/ML"}

security_model = SecurityModel()
rules_engine = OWASPRulesEngine()

@app.on_event("startup")
async def startup_event():
    try:
        security_model.load_models()
        logger.info("AI Security Agent Started | Model Loaded: True | Threshold: 0.7")
    except Exception as e:
        logger.error(f"Startup error: {e}")

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    start_time = time.time()
    try:
        if request.url.path in ["/", "/health"]:
            response = await call_next(request)
            response.headers["X-Process-Time"] = f"{time.time() - start_time:.3f}s"
            return response

        body = await request.body()
        body_text = body.decode("utf-8", errors="ignore") if body else ""
        content_type = request.headers.get("content-type", "").lower()
        if "json" in content_type:
            try:
                body_json = json.loads(body_text)
                body_text = json.dumps(body_json)
            except:
                pass
        elif "xml" in content_type:
            try:
                root = ET.fromstring(body_text)
                body_text = ET.tostring(root, encoding="unicode")
            except:
                pass

        if rules_engine.is_whitelisted_request(body_text, str(request.url.path)):
            response = await call_next(request)
            response.headers["X-Security-Check"] = "whitelisted"
            response.headers["X-Process-Time"] = f"{time.time() - start_time:.3f}s"
            await SecurityLogger.log_security_event("allowed", request, {"whitelisted": True, "body_preview": body_text[:100]})
            return response

        features = extract_features_from_request(request, body_text)
        critical_block, reason = rules_engine.check_critical_patterns(features, body_text)

        llm_analysis = await hf_threat_analysis(body_text)
        if llm_analysis["threat_level"] == "high":
            critical_block = True
            reason = reason or "llm_toxic"

        if critical_block:
            await SecurityLogger.log_security_event("blocked", request, {
                "reason": reason, "features": {k: v for k, v in list(features.items())[:5]},
                "llm_analysis": llm_analysis, "body_preview": body_text[:100]
            })
            mitigation = get_mitigation_steps(reason)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by AI agent",
                    "reason": reason,
                    "mitigation": mitigation
                },
                headers={"X-Blocked-By": "rules-or-llm"}
            )

        if features.get('injection_pattern_score', 0) == 0 and features.get('content_entropy', 0) < 3.0:
            response = await call_next(request)
            response.headers["X-Security-Check"] = "low_risk"
            response.headers["X-Process-Time"] = f"{time.time() - start_time:.3f}s"
            await SecurityLogger.log_security_event("allowed", request, {
                "low_risk": True, "body_preview": body_text[:100]
            })
            return response

        ml_probability, ml_prediction = security_model.predict(features)
        if ml_prediction == 1 and ml_probability > security_model.effective_threshold:
            await SecurityLogger.log_security_event("blocked", request, {
                "probability": ml_probability,
                "threshold": security_model.effective_threshold,
                "features": {k: v for k, v in list(features.items())[:5]},
                "body_preview": body_text[:100],
                "blocked_by": "ml_model"
            })
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by ML model",
                    "malicious_probability": ml_probability,
                    "mitigation": get_mitigation_steps("ml_detection")
                },
                headers={"X-Blocked-By": "ml-model"}
            )

        response = await call_next(request)
        response.headers["X-Security-Check"] = "passed"
        response.headers["X-Process-Time"] = f"{time.time() - start_time:.3f}s"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        await SecurityLogger.log_security_event("allowed", request, {
            "ml_probability": ml_probability,
            "features_summary": {k: v for k, v in list(features.items())[:5]}
        })
        return response

    except HTTPException as e:
        await SecurityLogger.log_security_event("error", request, {"error": str(e.detail)})
        raise
    except Exception as e:
        await SecurityLogger.log_security_event("error", request, {"error": str(e)})
        return JSONResponse(
            status_code=500,
            content={"error": f"Internal server error: {str(e)}"}
        )

@app.post("/analyze")
@limiter.limit("10/minute")
async def analyze(request: Request):
    try:
        body = await request.body()
        body_text = body.decode("utf-8", errors="ignore") if body else ""
        content_type = request.headers.get("content-type", "").lower()
        if "json" in content_type:
            try:
                body_json = json.loads(body_text)
                body_text = json.dumps(body_json)
            except:
                pass
        elif "xml" in content_type:
            try:
                root = ET.fromstring(body_text)
                body_text = ET.tostring(root, encoding="unicode")
            except:
                pass

        if rules_engine.is_whitelisted_request(body_text, str(request.url.path)):
            result = {
                "request_analysis": {
                    "body_preview": body_text[:100],
                    "is_whitelisted": True,
                    "critical_pattern_detected": False,
                    "critical_reason": None
                },
                "ml_analysis": {
                    "probability": 0.0,
                    "prediction": 0,
                    "threshold": security_model.threshold,
                    "model_loaded": security_model.loaded
                },
                "llm_analysis": {"threat_level": "low", "reason": "Whitelisted", "mitigation": "None"},
                "decision": {
                    "would_be_blocked": False,
                    "blocking_reason": "whitelisted",
                    "final_verdict": "ALLOWED"
                },
                "features_preview": {}
            }
            await SecurityLogger.log_security_event("allowed", request, result)
            return result

        features = extract_features_from_request(request, body_text)
        critical_block, reason = rules_engine.check_critical_patterns(features, body_text)
        llm_analysis = await hf_threat_analysis(body_text)
        ml_probability, ml_prediction = security_model.predict(features)

        would_be_blocked = critical_block or (ml_prediction == 1 and ml_probability > security_model.effective_threshold) or llm_analysis["threat_level"] == "high"
        blocking_reason = reason or ("llm_toxic" if llm_analysis["threat_level"] == "high" else "ml_detection" if ml_prediction == 1 else "none")

        result = {
            "request_analysis": {
                "body_preview": body_text[:100],
                "is_whitelisted": False,
                "critical_pattern_detected": critical_block,
                "critical_reason": reason
            },
            "ml_analysis": {
                "probability": ml_probability,
                "prediction": ml_prediction,
                "threshold": security_model.threshold,
                "model_loaded": security_model.loaded
            },
            "llm_analysis": llm_analysis,
            "decision": {
                "would_be_blocked": would_be_blocked,
                "blocking_reason": blocking_reason,
                "final_verdict": "BLOCKED" if would_be_blocked else "ALLOWED"
            },
            "features_preview": dict(list(features.items())[:10])
        }

        await SecurityLogger.log_security_event("analysis", request, result)
        if would_be_blocked:
            mitigation = get_mitigation_steps(blocking_reason)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by AI agent",
                    "reason": blocking_reason,
                    "mitigation": mitigation
                },
                headers={"X-Blocked-By": "rules-or-llm" if critical_block or llm_analysis["threat_level"] == "high" else "ml-model"}
            )
        return result

    except Exception as e:
        await SecurityLogger.log_security_event("error", request, {"error": str(e)})
        return JSONResponse(status_code=500, content={"error": f"Analysis error: {str(e)}"})

@app.get("/dashboard", response_class=HTMLResponse)
@limiter.limit("5/minute")
async def dashboard(request: Request, api_key: str = Depends(get_api_key)):
    stats = await get_security_stats()
    recent_blocks = []
    try:
        with open(BLOCKED_REQUESTS_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()[-10:]
            recent_blocks = [json.loads(line) for line in lines if line.strip()]
    except:
        pass
    return templates.TemplateResponse("dashboard.html", {"request": request, "stats": stats, "recent_blocks": recent_blocks})

@app.get("/security/stats")
async def get_security_stats(api_key: str = Depends(get_api_key)):
    stats = {
        "system": {
            "model_loaded": security_model.loaded,
            "threshold": security_model.threshold,
            "feature_count": len(security_model.feature_names),
            "server_time": datetime.datetime.now().isoformat()
        },
        "requests": {
            "total_blocked": 0,
            "blocked_by_rules": 0,
            "blocked_by_ml": 0,
            "blocked_by_llm": 0,
            "total_allowed": 0
        }
    }
    try:
        if os.path.exists(BLOCKED_REQUESTS_LOG):
            with open(BLOCKED_REQUESTS_LOG, "r", encoding="utf-8") as f:
                lines = f.readlines()
                blocked = [json.loads(line) for line in lines if line.strip()]
                stats["requests"]["total_blocked"] = len(blocked)
                stats["requests"]["blocked_by_rules"] = len([r for r in blocked if r.get('blocked_by') == 'rules-or-llm' and r.get('reason', '').startswith('critical')])
                stats["requests"]["blocked_by_ml"] = len([r for r in blocked if r.get('blocked_by') == 'ml-model'])
                stats["requests"]["blocked_by_llm"] = len([r for r in blocked if r.get('reason') == 'llm_toxic'])
        if os.path.exists(ALL_REQUESTS_LOG):
            with open(ALL_REQUESTS_LOG, "r", encoding="utf-8") as f:
                lines = f.readlines()
                stats["requests"]["total_allowed"] = len([json.loads(line) for line in lines if line.strip() and json.loads(line).get('event_type') == 'allowed'])
    except Exception as e:
        stats["error"] = f"Stats load error: {str(e)}"
    return stats

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.datetime.now().isoformat(),
        "model_loaded": security_model.loaded,
        "threshold": security_model.threshold,
        "components": {
            "model": security_model.model is not None,
            "features": len(security_model.feature_names) > 0,
            "calibrator": security_model.calibrator is not None
        }
    }

@app.get("/")
async def root():
    return {
        "message": "AI Security Agent v3.1",
        "endpoints": {
            "POST /analyze": "Analyze request for threats",
            "GET /dashboard": "View security dashboard",
            "GET /security/stats": "Security statistics",
            "GET /health": "Health check"
        },
        "security_settings": {
            "ml_threshold": security_model.effective_threshold,
            "rule_based_blocking": "enabled",
            "llm_analysis": "enabled (Hugging Face toxic-bert)",
            "whitelisting": "enabled"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)