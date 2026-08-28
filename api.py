import math
import re
from fastapi import FastAPI, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="AI Malicious URL Radar API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MESSAGES = {
    "ar": {
        "safe": "آمن وموثوق",
        "suspicious": "مشبوه - تحذير",
        "malicious": "عالي الخطورة - خبيث",
        "ip_warning": "استخدام عنوان IP صريح لتجاوز سجلات الـ DNS",
        "entropy_warning": "عشوائية عالية بالنطاق (احتمال توليد آلي DGA)",
        "no_ssl": "الاتصال غير مشفر (HTTP) ومعرض لاعتراض البيانات"
    },
    "en": {
        "safe": "CLEAN / SAFE",
        "suspicious": "SUSPICIOUS",
        "malicious": "MALICIOUS / CRITICAL",
        "ip_warning": "Direct IP address used instead of a legitimate domain",
        "entropy_warning": "High character entropy indicates automated DGA domain",
        "no_ssl": "Connection is unencrypted (HTTP instead of HTTPS)"
    }
}

class URLRequest(BaseModel):
    url: str

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log2(p) for p in prob])

@app.post("/api/scan")
def scan_url(request: URLRequest, accept_language: str = Header(default="ar")):
    lang = "en" if "en" in accept_language.lower() else "ar"
    msgs = MESSAGES[lang]
    
    url = request.url.strip()
    has_ip = bool(re.search(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', url))
    is_https = url.startswith("https://")
    entropy = round(calculate_entropy(url), 2)
    length = len(url)
    
    risk_score = 0
    reasons = []
    
    if has_ip:
        risk_score += 45
        reasons.append(msgs["ip_warning"])
    if not is_https:
        risk_score += 25
        reasons.append(msgs["no_ssl"])
    if entropy > 4.1:
        risk_score += 20
        reasons.append(msgs["entropy_warning"])
        
    risk_score = min(risk_score, 100)
    
    if risk_score < 30:
        status = msgs["safe"]
    elif risk_score < 65:
        status = msgs["suspicious"]
    else:
        status = msgs["malicious"]
        
    return {
        "url": url,
        "status": status,
        "risk_score": risk_score,
        "metrics": {
            "entropy": entropy,
            "length": length,
            "has_ip": has_ip,
            "is_https": is_https
        },
        "reasons": reasons
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
