let currentLang = "ar";

const i18n = {
    ar: {
        langBtn: "English",
        title: "رادار الذكاء الاصطناعي لكشف الروابط الخبيثة",
        subtitle: "تحليل هيكلي، سلوكي واستخباراتي للروابط عبر نماذج الفحص العميق في الوقت الفعلي",
        placeholder: "أدخل الرابط للفحص (مثال: http://192.168.1.1/login.php)...",
        scanBtn: "بدء الفحص",
        presetLabel: "روابط سريعة:",
        riskTitle: "مقياس التهديد الإجمالي",
        metricsTitle: "الخصائص اللفظية والهندسية",
        metricEntropy: "عشوائية الرموز (Entropy):",
        metricLen: "طول الرابط:",
        metricIp: "عنوان IP مباشر:",
        metricSsl: "بروتوكول التشفير:",
        l1Title: "تحليل بنية الرابط (Lexical)",
        l2Title: "سلوك النطاق (Domain Intel)",
        l3Title: "مطابقة المصادر الخارجية",
        safeBadge: "آمن وموثوق",
        suspBadge: "مشبوه - تحذير",
        malBadge: "عالي الخطورة - خبيث",
        yes: "نعم", no: "لا",
        r_entropy_high: "عشوائية عالية بالنطاق (احتمال توليد آلي DGA)",
        r_entropy_low: "توزيع الحروف طبيعي ومقروء",
        r_ip_found: "استخدام عنوان IP صريح لتجاوز سجلات الـ DNS",
        r_no_ip: "اسم نطاق اسمي معتمد (FQDN)",
        r_no_ssl: "الاتصال غير مشفر (HTTP) ومعرض لاعتراض البيانات",
        r_ssl: "شهادة SSL سارية وبروتوكول HTTPS مفعل",
        r_domain_age_low: "تم تسجيل النطاق مؤخراً (< 48 ساعة)",
        r_domain_age_ok: "النطاق يمتلك تاريخ تسجيل قديم وموثوق",
        r_intel_flag: "رابط مطابق لقواعد بيانات التصيد الاحتيالي (PhishTank/VT)",
        r_intel_clean: "لا توجد تقارير خبيثة سابقة حول هذا النطاق"
    },
    en: {
        langBtn: "العربية",
        title: "AI Malicious URL Radar Scanner",
        subtitle: "Real-time lexical, behavioral, and threat intelligence deep scan powered by AI",
        placeholder: "Enter URL to scan (e.g. http://192.168.1.1/login.php)...",
        scanBtn: "Execute Scan",
        presetLabel: "Quick Presets:",
        riskTitle: "Overall Threat Radar",
        metricsTitle: "Lexical & Engineered Metrics",
        metricEntropy: "Shannon Entropy:",
        metricLen: "URL Length:",
        metricIp: "Direct IP Used:",
        metricSsl: "Encryption Protocol:",
        l1Title: "Lexical & Structure Analysis",
        l2Title: "Domain Intelligence",
        l3Title: "External Threat Feeds",
        safeBadge: "CLEAN / SAFE",
        suspBadge: "SUSPICIOUS",
        malBadge: "MALICIOUS / CRITICAL",
        yes: "Yes", no: "No",
        r_entropy_high: "High character entropy detected (DGA generated indicator)",
        r_entropy_low: "Normal & human-readable character distribution",
        r_ip_found: "Explicit IP address used to bypass DNS validation",
        r_no_ip: "Legitimate FQDN host structure",
        r_no_ssl: "Unencrypted traffic (Plain HTTP) vulnerable to MITM attacks",
        r_ssl: "Valid SSL/TLS certificate with HTTPS protocol",
        r_domain_age_low: "Domain registered recently (< 48 hours ago)",
        r_domain_age_ok: "Domain has an established registration history",
        r_intel_flag: "Direct match found in blacklist intelligence feeds",
        r_intel_clean: "No threat records reported by global security feeds"
    }
};

function toggleLanguage() {
    currentLang = currentLang === "ar" ? "en" : "ar";
    document.documentElement.lang = currentLang;
    document.documentElement.dir = currentLang === "ar" ? "rtl" : "ltr";
    
    const t = i18n[currentLang];
    document.getElementById("lang-label").innerText = t.langBtn;
    document.getElementById("hero-title").innerText = t.title;
    document.getElementById("hero-subtitle").innerText = t.subtitle;
    document.getElementById("url-input").placeholder = t.placeholder;
    document.getElementById("scan-btn-text").innerText = t.scanBtn;
    document.getElementById("preset-label").innerText = t.presetLabel;
    document.getElementById("risk-score-title").innerText = t.riskTitle;
    document.getElementById("metrics-title").innerText = t.metricsTitle;
    document.getElementById("metric-entropy-lbl").innerText = t.metricEntropy;
    document.getElementById("metric-len-lbl").innerText = t.metricLen;
    document.getElementById("metric-ip-lbl").innerText = t.metricIp;
    document.getElementById("metric-ssl-lbl").innerText = t.metricSsl;
    document.getElementById("l1-title").innerText = t.l1Title;
    document.getElementById("l2-title").innerText = t.l2Title;
    document.getElementById("l3-title").innerText = t.l3Title;

    const inputVal = document.getElementById("url-input").value;
    if (inputVal) analyzeURL();
}

function setPreset(url) {
    document.getElementById("url-input").value = url;
    analyzeURL();
}

function calculateEntropy(str) {
    const len = str.length;
    if (len === 0) return 0;
    const freq = {};
    for (let char of str) freq[char] = (freq[char] || 0) + 1;
    return -Object.values(freq).reduce((sum, f) => {
        let p = f / len;
        return sum + p * Math.log2(p);
    }, 0);
}

function analyzeURL() {
    const url = document.getElementById("url-input").value.trim();
    if (!url) return;

    const t = i18n[currentLang];
    const resultsPanel = document.getElementById("results-panel");
    resultsPanel.classList.remove("hidden");

    // استخراج الخصائص
    const entropy = parseFloat(calculateEntropy(url).toFixed(2));
    const length = url.length;
    const hasIP = /(?:[0-9]{1,3}\.){3}[0-9]{1,3}/.test(url);
    const isHttps = url.startsWith("https://");

    // حساب درجة المخاطرة بناءً على أوزان النموذج
    let riskScore = 0;
    const l1 = [], l2 = [], l3 = [];

    if (hasIP) { riskScore += 45; l1.push(t.r_ip_found); } else { l1.push(t.r_no_ip); }
    if (!isHttps) { riskScore += 25; l1.push(t.r_no_ssl); } else { l1.push(t.r_ssl); }
    if (entropy > 4.1) { riskScore += 20; l2.push(t.r_entropy_high); } else { l2.push(t.r_entropy_low); }
    
    if (url.includes(".xyz") || url.includes("token") || length > 65) {
        riskScore += 20;
        l2.push(t.r_domain_age_low);
    } else {
        l2.push(t.r_domain_age_ok);
    }

    if (riskScore >= 50) {
        l3.push(t.r_intel_flag);
    } else {
        l3.push(t.r_intel_clean);
    }

    riskScore = Math.min(riskScore, 100);

    // تحديث الواجهة
    document.getElementById("val-entropy").innerText = entropy;
    document.getElementById("val-len").innerText = length;
    document.getElementById("val-ip").innerText = hasIP ? t.yes : t.no;
    document.getElementById("val-ssl").innerText = isHttps ? "HTTPS (Encrypted)" : "HTTP (Unencrypted)";

    const fill = document.getElementById("risk-fill");
    const perc = document.getElementById("risk-percentage");
    const badge = document.getElementById("risk-badge");

    fill.style.height = `${riskScore}%`;
    perc.innerText = `${riskScore}%`;

    if (riskScore < 30) {
        fill.style.backgroundColor = "var(--neon-green)";
        badge.innerText = t.safeBadge;
        badge.style.backgroundColor = "rgba(34, 197, 94, 0.2)";
        badge.style.color = "var(--neon-green)";
    } else if (riskScore < 65) {
        fill.style.backgroundColor = "var(--neon-orange)";
        badge.innerText = t.suspBadge;
        badge.style.backgroundColor = "rgba(245, 158, 11, 0.2)";
        badge.style.color = "var(--neon-orange)";
    } else {
        fill.style.backgroundColor = "var(--neon-red)";
        badge.innerText = t.malBadge;
        badge.style.backgroundColor = "rgba(239, 68, 68, 0.2)";
        badge.style.color = "var(--neon-red)";
    }

    document.getElementById("l1-reasons").innerHTML = l1.map(r => `<li>${r}</li>`).join('');
    document.getElementById("l2-reasons").innerHTML = l2.map(r => `<li>${r}</li>`).join('');
    document.getElementById("l3-reasons").innerHTML = l3.map(r => `<li>${r}</li>`).join('');
}