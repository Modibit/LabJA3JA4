/**
 * Authentic Pre-bundled Client Profiles for Security Analysis & Comparison
 * All profiles represent realistic, verifiable TLS ClientHello configurations.
 */

export interface ClientProfile {
  id: string;
  name: string;
  category: "browser" | "cli" | "script" | "bot";
  badge: string;
  badgeColor: string;
  description: string;
  userAgentExample: string;
  version: number;
  supportedVersions: number[];
  ciphers: number[];
  extensions: number[];
  sni: string;
  alpn: string[];
  curves: number[];
  pointFormats: number[];
  sigAlgs: number[];
  securityAnalysis: {
    fingerprintCharacteristics: string[];
    riskScore: "کم (طبیعی)" | "متوسط (ابزار خودکار)" | "بالا (مشکوک/غیرمعمول)";
    analystNotes: string;
    falsePositiveWarning: string;
  };
}

export const CLIENT_PROFILES: ClientProfile[] = [
  {
    id: "chrome_desktop",
    name: "مرورگر گوگل کروم (Google Chrome 124+)",
    category: "browser",
    badge: "مرورگر دسکتاپ مدرن",
    badgeColor: "#06b6d4",
    description: "الگوی استاندارد مرورگر کروم؛ همراه با تزریق افزونه‌ها و سایفرهای تصادفی GREASE و استفاده از شافلینگ در ترتیب افزونه‌ها.",
    userAgentExample: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    version: 0x0303,
    supportedVersions: [0x5a5a, 0x0304, 0x0303], // GREASE + TLS 1.3 + TLS 1.2
    ciphers: [
      0x2a2a, // GREASE cipher
      0x1301, 0x1302, 0x1303, // TLS 1.3 ciphers
      0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE-RSA/ECDSA
      0xcca9, 0xcca8,
      0xc013, 0xc014,
      0x009c, 0x009d,
      0x002f, 0x0035
    ],
    extensions: [
      0x3a3a, // GREASE extension
      0x0000, // SNI
      0x0017, // Extended master secret
      0xff01, // renegotiation_info
      0x000a, // supported_groups
      0x000b, // ec_point_formats
      0x0023, // session_ticket
      0x0010, // ALPN
      0x0005, // status_request (OCSP)
      0x000d, // signature_algorithms
      0x0012, // SCT
      0x0033, // key_share
      0x002d, // psk_key_exchange_modes
      0x002b, // supported_versions
      0x001b  // compress_certificate
    ],
    sni: "auth.google.com",
    alpn: ["h2", "http/1.1"],
    curves: [0x4a4a, 0x001d, 0x0017, 0x0018],
    pointFormats: [0],
    sigAlgs: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
    securityAnalysis: {
      fingerprintCharacteristics: [
        "وجود مقادیر تصادفی GREASE در سایفرها، افزونه‌ها و منحنی‌ها (ویژگی شاخص BoringSSL)",
        "پشتیبانی کامل از HTTP/2 در ALPN به عنوان اولین انتخاب (h2)",
        "مجموعه غنی از ۱۵ افزونه مدرن شامل compress_certificate و SCT",
        "تغییر متناوب ترتیب افزونه‌ها در نسخه‌های جدید کروم (شکننده برای JA3، پایدار در JA4)"
      ],
      riskScore: "کم (طبیعی)",
      analystNotes: "این اثر انگشت کاملاً منطبق با ترافیک معمول و مشروع کاربران نهایی اینترنت است. البته ابزارهای جعل هویت پیشرفته (مانند curl_impersonate) ممکن است بکوشند این اثر انگشت را شبیه‌سازی کنند.",
      falsePositiveWarning: "یکسان بودن این اثر انگشت فقط نشان‌دهنده استفاده از پشته شبکه Chromium است و هویت قطعی یا امن‌بودن کاربر را تضمین نمی‌کند."
    }
  },
  {
    id: "firefox_desktop",
    name: "مرورگر فایرفاکس (Mozilla Firefox 125+)",
    category: "browser",
    badge: "پشته NSS موزیلا",
    badgeColor: "#f97316",
    description: "پشته شبکه موزیلا مبتنی بر کتابخانه NSS؛ بدون استفاده از GREASE، با ترتیب افزونه‌های متفاوت و سایفرهای متمایز.",
    userAgentExample: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    version: 0x0303,
    supportedVersions: [0x0304, 0x0303],
    ciphers: [
      0x1301, 0x1303, 0x1302, // Firefox orders ChaCha20 ahead of AES-256
      0xc02b, 0xc02f, 0xcca9, 0xcca8,
      0xc02c, 0xc030,
      0xc00a, 0xc009, 0xc013, 0xc014,
      0x002f, 0x0035
    ],
    extensions: [
      0x0000, // SNI
      0x0017, // EMS
      0x000a, // supported_groups
      0x000b, // ec_point_formats
      0x0023, // session_ticket
      0x0010, // ALPN
      0x0005, // status_request
      0x000d, // signature_algorithms
      0x002b, // supported_versions
      0x0033, // key_share
      0x002d  // psk_modes
    ],
    sni: "mozilla.org",
    alpn: ["h2", "http/1.1"],
    curves: [0x001d, 0x0017, 0x0018, 0x0019],
    pointFormats: [0],
    sigAlgs: [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
    securityAnalysis: {
      fingerprintCharacteristics: [
        "عدم استفاده از GREASE برخلاف کروم و سافاری",
        "ترجیح ChaCha20 بر روی AES-256 در پشته NSS (0x1303 قبل از 0x1302)",
        "پشتیبانی از منحنی‌های بیضوی نامعمول‌تر مانند secp521r1 (0x0019)"
      ],
      riskScore: "کم (طبیعی)",
      analystNotes: "ترافیک طبیعی و مشروع مربوط به مرورگر منبع‌باز فایرفاکس.",
      falsePositiveWarning: "تنظیمات تغییر حریم خصوصی فایرفاکس (about:config) می‌تواند اثر انگشت آن را میان کاربران تغییر دهد."
    }
  },
  {
    id: "python_urllib",
    name: "اسکریپت پایتون (Python Requests / Urllib3)",
    category: "script",
    badge: "اسکریپت خودکار",
    badgeColor: "#eab308",
    description: "ترافیک کتابخانه‌های استاندارد توسعه نرم‌افزار پایتون بر بستر OpenSSL؛ بدون ALPN چندگانه و با کمترین افزونه‌های مرورگری.",
    userAgentExample: "python-requests/2.31.0",
    version: 0x0303,
    supportedVersions: [0x0304, 0x0303],
    ciphers: [
      0x1301, 0x1302, 0x1303,
      0xc02b, 0xc02f, 0xc02c, 0xc030,
      0xcca9, 0xcca8,
      0xc009, 0xc013, 0xc00a, 0xc014,
      0x002f, 0x0035
    ],
    extensions: [
      0x0000, // SNI
      0x000a, // Supported groups
      0x000b, // EC point formats
      0x000d, // Signature algorithms
      0x0016, // Encrypt then mac
      0x0017, // EMS
      0x002b, // Supported versions
      0x002d, // PSK modes
      0x0033  // Key share
    ],
    sni: "internal-api.service.local",
    alpn: [], // Python requests has NO ALPN by default!
    curves: [0x001d, 0x0017, 0x0018],
    pointFormats: [0],
    sigAlgs: [0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601],
    securityAnalysis: {
      fingerprintCharacteristics: [
        "فقدان افزونه ALPN یا فقط پشتیبانی از http/1.1 (عدم پشتیبانی پیش‌فرض از h2)",
        "فقدان افزونه‌های SCT، Session Ticket یا فشرده‌سازی گواهی",
        "کد ALPN در JA4 برابر '00' می‌شود (بسیار متمایز از مرورگرها)"
      ],
      riskScore: "متوسط (ابزار خودکار)",
      analystNotes: "در صورتی که در هدر User-Agent این کلاینت ادعای Chrome شده باشد اما اثر انگشت JA3/JA4 مربوط به Python باشد، با یک حمله جعل کلاینت (User-Agent Spoofing) قطعی روبرو هستیم!",
      falsePositiveWarning: "بسیاری از نرم‌افزارهای یکپارچه‌سازی و ابزارهای مانیتورینگ قانونی نیز با پایتون نوشته شده‌اند و به خودی خود بدافزار نیستند."
    }
  },
  {
    id: "curl_cli",
    name: "ابزار خط فرمان cURL (Curl CLI 8.x)",
    category: "cli",
    badge: "ابزار ترمینال",
    badgeColor: "#10b981",
    description: "ابزار محبوب توسعه‌دهندگان و ادمین‌های شبکه با پشتیبانی صریح از HTTP/2 و پشته مستقیم OpenSSL.",
    userAgentExample: "curl/8.4.0",
    version: 0x0303,
    supportedVersions: [0x0304, 0x0303],
    ciphers: [
      0x1302, 0x1303, 0x1301,
      0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa,
      0xc02b, 0xc02f, 0x009e, 0xc00a, 0xc009, 0xc013, 0xc014,
      0x0033, 0x0039, 0x002f, 0x0035
    ],
    extensions: [
      0x0000, 0x002b, 0x000a, 0x000b, 0x000d, 0x0016, 0x0017, 0x0033, 0x002d, 0x0029, 0x0010
    ],
    sni: "raw.githubusercontent.com",
    alpn: ["h2", "http/1.1"],
    curves: [0x001d, 0x0017, 0x001e, 0x0019, 0x0018],
    pointFormats: [0],
    sigAlgs: [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
    securityAnalysis: {
      fingerprintCharacteristics: [
        "تعداد بالای ۲۰ سایفر پیشنهادی استاندارد OpenSSL",
        "افزونه‌های ۱۱ تایی با کد ALPN برابر 'h2' یا 'h1'",
        "ترتیب امضاهای گسترده شامل مقادیر خاص Ed25519"
      ],
      riskScore: "متوسط (ابزار خودکار)",
      analystNotes: "توسط ادمین‌های سیستم و اسکریپت‌های Cron استفاده می‌شود؛ همچنین ابزار محبوب نفوذگران برای واکشی اسکریپت‌های مرحله دوم (Payload Dropper).",
      falsePositiveWarning: "استفاده از curl در محیط‌های توسعه بسیار رایج است."
    }
  },
  {
    id: "scanner_bot",
    name: "ربات اسکنر تهاجمی (Automated Port/TLS Scanner)",
    category: "bot",
    badge: "اسکنر مشکوک",
    badgeColor: "#ef4444",
    description: "اتصال ناهنجار با هدف بررسی سریع پورت یا اکسپلویت؛ فاقد نام دامنه (SNI)، نسخه منسوخ و تنها ۴ سایفر ضعیف.",
    userAgentExample: "Masscan/1.3.2 (or empty)",
    version: 0x0301, // TLS 1.0 legacy probe
    supportedVersions: [],
    ciphers: [
      0x002f, 0x0035, 0x0005, 0x000a // Includes RC4 and 3DES!
    ],
    extensions: [
      0x000a, 0x000b
    ],
    sni: "", // No SNI, targeting raw IP address
    alpn: [],
    curves: [0x0017],
    pointFormats: [0],
    sigAlgs: [],
    securityAnalysis: {
      fingerprintCharacteristics: [
        "فقدان کامل SNI (کد 'i' در JA4_a)، نشان‌دهنده اسکن مستقیم محدوده آدرس‌های IP اینترنت",
        "درخواست نسخه منسوخ TLS 1.0 بدون supported_versions (کد '10' در JA4_a)",
        "ارائه سایفرهای قدیمی و آسیب‌پذیر مانند 3DES و RC4",
        "تنها ۲ افزونه اولیه؛ عدم وجود ALPN و امضاهای امنیتی"
      ],
      riskScore: "بالا (مشکوک/غیرمعمول)",
      analystNotes: "این اثر انگشت به دلیل فقدان SNI و استفاده از سایفرهای منسوخ، در داشبورد SOC به عنوان پایش تهاجمی شبکه (Reconnaissance) یا ربات اسکنر با اولویت بالا علامت‌گذاری می‌شود.",
      falsePositiveWarning: "برخی دستگاه‌های بسیار قدیمی سخت‌افزاری صنعتی (Legacy Embedded) ممکن است اثر انگشت مشابهی داشته باشند."
    }
  }
];
