/**
 * FoxIO JA4 TLS Client Fingerprint Implementation
 * Strictly conforms to https://github.com/FoxIO-LLC/ja4 specification.
 */

import { sha256 } from "./crypto";
import { isGrease } from "./ja3";

export interface JA4Input {
  protocol: "t" | "q" | "d" | string;
  version: number;
  hasSni: boolean;
  sniIsIp?: boolean;
  ciphers: number[];
  extensions: number[];
  alpnProtocols?: string[];
  signatureAlgorithms?: number[];
  supportedVersions?: number[];
}

export interface JA4SegmentExplanation {
  title: string;
  value: string;
  formula: string;
  description: string;
  details: string[];
}

export interface JA4Result {
  full: string;
  ja4_a: string;
  ja4_b: string;
  ja4_c: string;
  raw_b: string;
  raw_c: string;
  effectiveVersion: number;
  cipherCount: number;
  extensionCount: number;
  alpnCode: string;
  sniCode: string;
  sortedCiphersHex: string[];
  sortedExtensionsHex: string[];
  sigAlgsHex: string[];
  explanations: {
    a: JA4SegmentExplanation;
    b: JA4SegmentExplanation;
    c: JA4SegmentExplanation;
  };
}

export function mapTlsVersionToJA4(version: number): string {
  if (version === 0x0304) return "13";
  if (version === 0x0303) return "12";
  if (version === 0x0302) return "11";
  if (version === 0x0301) return "10";
  if (version === 0x0300) return "s3";
  if (version === 0x0200) return "s2";
  if (version === 0x0100) return "s1";
  return "00";
}

/**
 * Computes official JA4 fingerprint: ja4_a_ja4_b_ja4_c
 */
export function computeJA4(input: JA4Input): JA4Result {
  const alpnProtocols = input.alpnProtocols || [];
  const signatureAlgorithms = input.signatureAlgorithms || [];
  const supportedVersions = input.supportedVersions || [];

  // 1. Determine effective TLS version (from supported_versions if available)
  let effectiveVersion = input.version;
  if (supportedVersions.length > 0) {
    const nonGreaseVersions = supportedVersions.filter((v) => !isGrease(v));
    if (nonGreaseVersions.length > 0) {
      effectiveVersion = Math.max(...nonGreaseVersions);
    }
  }

  // 2. JA4_a: Protocol + Version + SNI + CiphersCount + ExtensionsCount + ALPN
  const protoChar = (input.protocol ? input.protocol[0].toLowerCase() : "t");
  const verStr = mapTlsVersionToJA4(effectiveVersion);
  const sniChar = input.hasSni && !input.sniIsIp ? "d" : "i";

  const nonGreaseCiphers = input.ciphers.filter((c) => !isGrease(c));
  const nonGreaseExtensions = input.extensions.filter((e) => !isGrease(e));

  const cipherCount = nonGreaseCiphers.length;
  const extensionCount = nonGreaseExtensions.length;

  const cipherCountStr = Math.min(cipherCount, 99).toString().padStart(2, "0");
  const extCountStr = Math.min(extensionCount, 99).toString().padStart(2, "0");

  let alpnCode = "00";
  if (alpnProtocols.length > 0 && alpnProtocols[0].length > 0) {
    const firstAlpn = alpnProtocols[0];
    alpnCode = `${firstAlpn[0]}${firstAlpn[firstAlpn.length - 1]}`;
  }

  const ja4_a = `${protoChar}${verStr}${sniChar}${cipherCountStr}${extCountStr}${alpnCode}`;

  // 3. JA4_b: SHA256 of sorted hex ciphers (truncated to 12 chars)
  let raw_b = "";
  let ja4_b = "000000000000";
  const sortedCiphersHex = nonGreaseCiphers
    .map((c) => c.toString(16).padStart(4, "0").toLowerCase())
    .sort();

  if (sortedCiphersHex.length > 0) {
    raw_b = sortedCiphersHex.join(",");
    ja4_b = sha256(raw_b).substring(0, 12);
  }

  // 4. JA4_c: SHA256 of sorted hex extensions (excluding SNI=0x0000 and ALPN=0x0010) + '_' + unsorted sig_algs
  const cExtensions = nonGreaseExtensions.filter((e) => e !== 0x0000 && e !== 0x0010);
  const sortedExtensionsHex = cExtensions
    .map((e) => e.toString(16).padStart(4, "0").toLowerCase())
    .sort();

  const extPart = sortedExtensionsHex.join(",");

  const nonGreaseSigAlgs = signatureAlgorithms.filter((s) => !isGrease(s));
  const sigAlgsHex = nonGreaseSigAlgs.map((s) => s.toString(16).padStart(4, "0").toLowerCase());

  let raw_c = "";
  let ja4_c = "000000000000";

  if (sigAlgsHex.length > 0) {
    const sigPart = sigAlgsHex.join(",");
    raw_c = extPart ? `${extPart}_${sigPart}` : `_${sigPart}`;
  } else {
    raw_c = extPart;
  }

  if (raw_c.length > 0) {
    ja4_c = sha256(raw_c).substring(0, 12);
  }

  const full = `${ja4_a}_${ja4_b}_${ja4_c}`;

  return {
    full,
    ja4_a,
    ja4_b,
    ja4_c,
    raw_b,
    raw_c,
    effectiveVersion,
    cipherCount,
    extensionCount,
    alpnCode,
    sniCode: sniChar,
    sortedCiphersHex,
    sortedExtensionsHex,
    sigAlgsHex,
    explanations: {
      a: {
        title: "بخش قابل خواندن (JA4_a)",
        value: ja4_a,
        formula: "پروتکل + نسخه + SNI + تعداد سایفرها + تعداد افزونه‌ها + ALPN",
        description: "این بخش ۱۰ نویسه‌ای بدون نیاز به کلید یا هش‌کردن، نوع اتصال و ویژگی‌های سطحی کلاینت را به شکل مستقیم نمایش می‌دهد.",
        details: [
          `پروتکل: ${protoChar === "t" ? "TCP (TLS)" : protoChar === "q" ? "QUIC" : "DTLS"} (علامت '${protoChar}')`,
          `نسخه مؤثر TLS: ${verStr === "13" ? "TLS 1.3" : verStr === "12" ? "TLS 1.2" : verStr} (کد '${verStr}')`,
          `وضعیت SNI: ${sniChar === "d" ? "دامنه معتبر Domain (کد 'd')" : "آدرس IP یا فاقد SNI (کد 'i')"}`,
          `تعداد Cipher Suiteهای معتبر (بدون GREASE): ${cipherCount} (کد '${cipherCountStr}')`,
          `تعداد Extensions معتبر (بدون GREASE): ${extensionCount} (کد '${extCountStr}')`,
          `پروتکل ALPN: حرف اول و آخر اولین پروتکل یعنی '${alpnCode}' (در صورتی که ALPN نباشد: '00')`,
        ],
      },
      b: {
        title: "هش الگوریتم‌های رمزنگاری (JA4_b)",
        value: ja4_b,
        formula: "SHA256(سایفرهای مرتب‌شده بر حسب هگز به ترتیب صعودی)[0:12]",
        description: "سایفرهای کلاینت پس از حذف مقادیر GREASE به فرم هگزادسیمال درآمده و مرتب صعودی می‌شوند. ۱۲ کاراکتر اول SHA256 آنها ذخیره می‌شود.",
        details: [
          `تعداد سایفرهای مورد استفاده: ${sortedCiphersHex.length}`,
          `رشته خام قبل از هش: ${raw_b || "(خالی)"}`,
          `علت مرتب‌سازی: جلوگیری از جعل اثر انگشت صرفاً با جابجایی ترتیب سایفرها.`,
        ],
      },
      c: {
        title: "هش افزونه‌ها و الگوریتم‌های امضا (JA4_c)",
        value: ja4_c,
        formula: "SHA256(افزونه‌های مرتب‌شده_الگوریتم‌های امضای اصلی)[0:12]",
        description: "افزونه‌ها (به جز SNI=0000 و ALPN=0010 که در JA4_a هستند) مرتب صعودی می‌شوند. سپس الگوریتم‌های امضا بدون تغییر ترتیب با خط زیرین متصل می‌شوند.",
        details: [
          `افزونه‌های لحاظ‌شده (بدون SNI و ALPN): ${sortedExtensionsHex.length}`,
          `الگوریتم‌های امضای لحاظ‌شده: ${sigAlgsHex.length}`,
          `رشته خام قبل از هش: ${raw_c || "(خالی)"}`,
          `مزیت بزرگ: تغییر تصادفی ترتیب افزونه‌ها در مرورگرهایی مثل کروم تأثیری روی JA4_c ندارد!`,
        ],
      },
    },
  };
}
