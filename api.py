"""
AI Malicious URL Radar API
===========================
API متقدمة لكشف وتحليل URLs الخبيثة باستخدام تقنيات التحليل الآمن
Detects malicious URLs using entropy analysis, SSL checks, and IP detection

Author: Ahmed
Version: 1.0.0
"""

import math
import re
import logging
from typing import Optional, List, Dict
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator


# ==================== CONFIG & CONSTANTS ====================

# رسائل الخطأ والنتائج بلغات متعددة
MESSAGES = {
    "ar": {
        "safe": "آمن وموثوق",
        "suspicious": "مشبوه - تحذير",
        "malicious": "عالي الخطورة - خبيث",
        "ip_warning": "استخدام عنوان IP صريح لتجاوز سجلات الـ DNS",
        "entropy_warning": "عشوائية عالية بالنطاق (احتمال توليد آلي DGA)",
        "no_ssl": "الاتصال غير مشفر (HTTP) ومعرض لاعتراض البيانات",
        "invalid_url": "صيغة URL غير صحيحة"
    },
    "en": {
        "safe": "CLEAN / SAFE",
        "suspicious": "SUSPICIOUS",
        "malicious": "MALICIOUS / CRITICAL",
        "ip_warning": "Direct IP address used instead of a legitimate domain",
        "entropy_warning": "High character entropy indicates automated DGA domain",
        "no_ssl": "Connection is unencrypted (HTTP instead of HTTPS)",
        "invalid_url": "Invalid URL format"
    }
}

# ثوابت قياس المخاطر
RISK_THRESHOLDS = {
    "safe": (0, 30),
    "suspicious": (30, 65),
    "malicious": (65, 100)
}

RISK_WEIGHTS = {
    "ip_detected": 45,
    "no_https": 25,
    "high_entropy": 20
}

ENTROPY_THRESHOLD = 4.1

# إعداد السجل (Logging)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================== MODELS ====================

class URLRequest(BaseModel):
    """
    نموذج طلب الفحص
    Model for URL scan request
    """
    url: str = Field(
        ...,
        min_length=5,
        max_length=2048,
        description="URL to scan / الـ URL المراد فحصه"
    )

    @validator('url')
    def validate_url(cls, v):
        """
        التحقق من صحة صيغة URL
        Validate URL format
        """
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class URLMetrics(BaseModel):
    """مقاييس الـ URL / URL analysis metrics"""
    entropy: float = Field(..., description="عشوائية النطاق / Domain entropy")
    length: int = Field(..., description="طول الـ URL / URL length")
    has_ip: bool = Field(..., description="هل يستخدم عنوان IP / Contains IP address")
    is_https: bool = Field(..., description="هل يستخدم HTTPS / Uses HTTPS")


class ScanResponse(BaseModel):
    """
    نموذج الاستجابة
    Model for scan response
    """
    url: str
    status: str
    risk_score: int = Field(..., ge=0, le=100, description="درجة المخاطر (0-100)")
    metrics: URLMetrics
    reasons: List[str]


# ==================== UTILITY FUNCTIONS ====================

def calculate_entropy(text: str) -> float:
    """
    حساب مستوى العشوائية في النص
    Calculate Shannon entropy of a string
    
    Args:
        text (str): النص المراد حساب عشوائيته
    
    Returns:
        float: قيمة العشوائية (0 = منخفضة، 8 = عالية جداً)
    
    Example:
        >>> calculate_entropy("example")
        2.81
    """
    if not text:
        return 0.0
    
    # حساب احتمالية كل حرف
    frequencies = [text.count(char) / len(text) for char in set(text)]
    
    # صيغة Shannon entropy: -Σ(p * log2(p))
    entropy = -sum(p * math.log2(p) for p in frequencies)
    
    return round(entropy, 2)


def extract_domain(url: str) -> str:
    """
    استخراج النطاق من الـ URL
    Extract domain from URL
    
    Args:
        url (str): الـ URL الكامل
    
    Returns:
        str: النطاق فقط
    """
    # إزالة البروتوكول
    domain = re.sub(r'^https?://', '', url)
    # إزالة المسار والمعاملات
    domain = domain.split('/')[0].split('?')[0]
    return domain


def detect_direct_ip(url: str) -> bool:
    """
    كشف استخدام عنوان IP بدلاً من النطاق
    Detect if URL uses direct IP address
    
    Args:
        url (str): الـ URL للفحص
    
    Returns:
        bool: True إذا كان يستخدم IP مباشرة
    """
    domain = extract_domain(url)
    # نمط regex لعنوان IPv4
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    return bool(re.match(ip_pattern, domain))


def analyze_url(url: str, lang: str = "ar") -> Dict:
    """
    تحليل شامل للـ URL
    Comprehensive URL analysis
    
    Args:
        url (str): الـ URL للفحص
        lang (str): لغة الاستجابة (ar/en)
    
    Returns:
        Dict: نتائج التحليل مع درجة المخاطر
    """
    msgs = MESSAGES[lang]
    url = url.strip()
    
    # الفحوصات الأساسية
    has_ip = detect_direct_ip(url)
    is_https = url.startswith("https://")
    domain = extract_domain(url)
    entropy = calculate_entropy(domain)
    length = len(url)
    
    # حساب درجة المخاطر
    risk_score = 0
    reasons: List[str] = []
    
    # 1. كشف استخدام IP المباشر (خطير جداً)
    if has_ip:
        risk_score += RISK_WEIGHTS["ip_detected"]
        reasons.append(msgs["ip_warning"])
    
    # 2. عدم استخدام HTTPS
    if not is_https:
        risk_score += RISK_WEIGHTS["no_https"]
        reasons.append(msgs["no_ssl"])
    
    # 3. عشوائية عالية (علامة على DGA - Domain Generation Algorithm)
    if entropy > ENTROPY_THRESHOLD:
        risk_score += RISK_WEIGHTS["high_entropy"]
        reasons.append(msgs["entropy_warning"])
    
    # حد أقصى 100
    risk_score = min(risk_score, 100)
    
    # تحديد الحالة بناءً على درجة المخاطر
    if risk_score < RISK_THRESHOLDS["suspicious"][0]:
        status = msgs["safe"]
    elif risk_score < RISK_THRESHOLDS["malicious"][0]:
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


# ==================== API INITIALIZATION ====================

app = FastAPI(
    title="AI Malicious URL Radar API",
    version="1.0.0",
    description="API لكشف والتحقق من URLs الخبيثة / Detect and analyze malicious URLs",
    contact={
        "name": "Ahmed",
        "email": "your.email@example.com"
    }
)

# إضافة CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== API ENDPOINTS ====================

@app.post(
    "/api/scan",
    response_model=ScanResponse,
    summary="Scan URL / فحص الـ URL",
    description="فحص URL واكتشاف ما إذا كان خبيثاً أم آمناً"
)
def scan_url(
    request: URLRequest,
    accept_language: str = Header(default="ar", description="لغة الاستجابة")
) -> ScanResponse:
    """
    فحص URL للكشف عن التهديدات
    Scan a URL for malicious indicators
    
    Args:
        request (URLRequest): كائن الطلب يحتوي على الـ URL
        accept_language (str): اللغة المفضلة (ar أو en)
    
    Returns:
        ScanResponse: نتائج الفحص الشاملة
    
    Raises:
        HTTPException: إذا كان الـ URL غير صحيح
    """
    try:
        # تحديد اللغة
        lang = "en" if "en" in accept_language.lower() else "ar"
        
        # تحليل الـ URL
        result = analyze_url(request.url, lang)
        
        # تسجيل الفحص
        logger.info(
            f"URL Scanned | URL: {result['url'][:50]}... | Risk: {result['risk_score']}"
        )
        
        return ScanResponse(**result)
    
    except ValueError as e:
        logger.error(f"Validation Error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get(
    "/api/health",
    summary="Health Check",
    description="التحقق من حالة الـ API"
)
def health_check():
    """
    التحقق من أن الـ API تعمل بشكل صحيح
    Check if API is running
    """
    return {
        "status": "healthy",
        "version": "1.0.0",
        "service": "AI Malicious URL Radar"
    }


@app.get(
    "/",
    summary="Welcome / ترحيب"
)
def welcome():
    """صفحة الترحيب / Welcome page"""
    return {
        "message": "مرحباً بك في API كشف URLs الخبيثة",
        "welcome": "Welcome to AI Malicious URL Radar API",
        "endpoints": {
            "scan": "POST /api/scan",
            "health": "GET /api/health",
            "docs": "/docs"
        }
    }


# ==================== MAIN ====================

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting AI Malicious URL Radar API...")
    print("📍 Server: http://0.0.0.0:8000")
    print("📖 Docs: http://localhost:8000/docs")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
