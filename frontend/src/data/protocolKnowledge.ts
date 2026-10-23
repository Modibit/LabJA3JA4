/**
 * TLS Protocol Knowledge Base
 * Mapping of hex/decimal identifiers to standard IETF RFC names and Persian explanations.
 */

export interface ProtocolEntity {
  id: number;
  hex: string;
  name: string;
  standard: string;
  isGrease: boolean;
  securityRating: "modern" | "secure" | "legacy" | "insecure";
  description: string;
}

export const KNOWN_CIPHER_SUITES: Record<number, { name: string; security: "modern" | "secure" | "legacy" | "insecure"; desc: string }> = {
  // TLS 1.3
  0x1301: { name: "TLS_AES_128_GCM_SHA256", security: "modern", desc: "سایفر استاندارد و سریع TLS 1.3 با احراز هویت متقارن AEAD" },
  0x1302: { name: "TLS_AES_256_GCM_SHA384", security: "modern", desc: "سایفر سنگین‌تر با کلید ۲۵۶ بیتی و هش ۳۸۴ در TLS 1.3" },
  0x1303: { name: "TLS_CHACHA20_POLY1305_SHA256", security: "modern", desc: "الگوریتم پرسرعت مدرن مناسب موبایل و پردازنده‌های بدون شتاب‌دهنده سخت‌افزاری AES" },
  0x1304: { name: "TLS_AES_128_CCM_SHA256", security: "modern", desc: "رمزنگاری سازگار با دستگاه‌های اینترنت اشیاء (IoT)" },
  0x1305: { name: "TLS_AES_128_CCM_8_SHA256", security: "modern", desc: "نسخه کوتاه‌شده تگ برای سامانه‌های نهفته کم‌مصرف" },

  // TLS 1.2 ECDHE
  0xc02b: { name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", security: "secure", desc: "سایفر بسیار محبوب TLS 1.2 با گواهی ECDSA و فوروارد سیکرسی" },
  0xc02f: { name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", security: "secure", desc: "سایفر استاندارد TLS 1.2 با کلید عمومی RSA و تبادل کلید بیضوی" },
  0xc02c: { name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", security: "secure", desc: "نسخه ۲۵۶ بیتی با امنیت بالا در TLS 1.2" },
  0xc030: { name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", security: "secure", desc: "سایفر ۲۵۶ بیتی با گواهی RSA و هش قوی SHA-384" },
  0xcca9: { name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", security: "secure", desc: "ChaCha20 در ترکیب با گواهی امضای بیضوی" },
  0xcca8: { name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", security: "secure", desc: "ChaCha20 در ترکیب با گواهی وب‌سایت مبتنی بر RSA" },

  // Legacy / CBC
  0xc013: { name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", security: "legacy", desc: "سایفر قدیمی مبتنی بر CBC و SHA-1 (آسیب‌پذیر در برابر حملات Padding)" },
  0xc014: { name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", security: "legacy", desc: "سایفر قدیمی ۲۵۶ بیتی با حالت CBC" },
  0x009c: { name: "TLS_RSA_WITH_AES_128_GCM_SHA256", security: "legacy", desc: "سایفر بدون فوروارد سیکرسی (Forward Secrecy)، فقط RSA ثابت" },
  0x009d: { name: "TLS_RSA_WITH_AES_256_GCM_SHA384", security: "legacy", desc: "RSA ثابت بدون ECDHE" },
  0x002f: { name: "TLS_RSA_WITH_AES_128_CBC_SHA", security: "legacy", desc: "سایفر بسیار قدیمی TLS 1.0/1.1 با کلید تبادل سنتی" },
  0x0035: { name: "TLS_RSA_WITH_AES_256_CBC_SHA", security: "legacy", desc: "سایفر سنتی با AES-256 و کلید استاتیک" },
  0x000a: { name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", security: "insecure", desc: "الگوریتم کاملاً منسوخ و ناامن Triple-DES (حمله Sweet32)" },
  0x0005: { name: "TLS_RSA_WITH_RC4_128_SHA", security: "insecure", desc: "سایفر شکسته شده و شدیداً ناامن RC4 (ممنوع طبق RFC 7465)" },
};

export const KNOWN_EXTENSIONS: Record<number, { name: string; desc: string }> = {
  0x0000: { name: "server_name (SNI)", desc: "نام دامنه مقصد (SNI) که مرورگر قصد اتصال به آن را دارد." },
  0x0005: { name: "status_request (OCSP)", desc: "درخواست بررسی وضعیت ابطال گواهی سرور بدون نیاز به تماس مستقیم با صادرکننده." },
  0x000a: { name: "supported_groups", desc: "فهرست منحنی‌های بیضوی و گروه‌های مجاز تبادل کلید (مانند x25519 و secp256r1)." },
  0x000b: { name: "ec_point_formats", desc: "قالب نمایش نقاط روی منحنی بیضوی (معمولاً 0 به معنی فشرده‌نشده)." },
  0x000d: { name: "signature_algorithms", desc: "الگوریتم‌های مجاز هش و امضا که کلاینت می‌تواند گواهی سرور را با آن‌ها اعتبارسنجی کند." },
  0x0010: { name: "application_layer_protocol_negotiation (ALPN)", desc: "مذاکره پروتکل لایه کاربرد مانند h2 (HTTP/2) یا http/1.1 پیش از پایان هندشیک." },
  0x0012: { name: "signed_certificate_timestamp (SCT)", desc: "شفافیت گواهی (Certificate Transparency) جهت جلوگیری از صدور گواهی‌های جعلی." },
  0x0015: { name: "padding", desc: "بایت‌های پرکننده برای تنظیم طول بسته ClientHello به منظور خنثی‌کردن باگ‌های برخی فایروال‌ها." },
  0x0017: { name: "extended_master_secret", desc: "افزونه ضروری برای جلوگیری از حملات مرد میانی Triple Handshake در TLS 1.2." },
  0x001b: { name: "compress_certificate", desc: "فشرده‌سازی گواهی‌های حجیم سرور با zlib یا brotli برای افزایش سرعت لود." },
  0x0023: { name: "session_ticket", desc: "مکانیزم از سرگیری جلسه ارتباطی (Session Resumption) بدون نیاز به ذخیره حافظه در سرور." },
  0x002b: { name: "supported_versions", desc: "افزونه کلیدی TLS 1.3 که نسخه واقعی پروتکل (0x0304) در آن اعلام می‌شود." },
  0x002d: { name: "psk_key_exchange_modes", desc: "حالت‌های مجاز تبادل کلید پیش‌تر به اشتراک گذاشته شده در TLS 1.3." },
  0x0033: { name: "key_share", desc: "پارامترهای عمومی کلید موقت کلاینت در TLS 1.3 برای برقراری ارتباط در ۱ رفت‌وبرگشت (1-RTT)." },
  0x44cd: { name: "encrypted_client_hello (ECH)", desc: "رمزگذاری بخش حساس بسته ClientHello شامل SNI برای محافظت از حریم خصوصی در برابر شنودگر شبکه." },
};

export const KNOWN_CURVES: Record<number, string> = {
  0x001d: "x25519 (منحنی پرسرعت و مدرن برنشتاین)",
  0x0017: "secp256r1 / NIST P-256 (منحنی استاندارد ملی آمریکا)",
  0x0018: "secp384r1 / NIST P-384 (منحنی بیضوی قوی‌تر)",
  0x0019: "secp521r1 / NIST P-521 (منحنی ۵۲۱ بیتی)",
  0x001e: "x448 (منحنی بیضوی رده بالا ۴۴۸ بیتی)",
};

export function getCipherName(id: number): string {
  if (KNOWN_CIPHER_SUITES[id]) {
    return KNOWN_CIPHER_SUITES[id].name;
  }
  return `Cipher 0x${id.toString(16).padStart(4, "0").toUpperCase()}`;
}

export function getExtensionName(id: number): string {
  if (KNOWN_EXTENSIONS[id]) {
    return KNOWN_EXTENSIONS[id].name;
  }
  return `Extension 0x${id.toString(16).padStart(4, "0").toUpperCase()}`;
}
