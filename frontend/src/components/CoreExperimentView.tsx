import React, { useState, useMemo } from "react";
import {
  FlaskConical,
  Shuffle,
  RefreshCw,
  CheckCircle2,
  XCircle,
  ArrowLeft,
  Sparkles,
  Zap,
  Info,
  ShieldAlert,
  ShieldCheck,
  Code2
} from "lucide-react";
import { computeJA3, type JA3Result } from "../utils/ja3";
import { computeJA4, type JA4Result } from "../utils/ja4";
import { getExtensionName } from "../data/protocolKnowledge";

export const CoreExperimentView: React.FC = () => {
  // Baseline initial state representing realistic Google Chrome ClientHello
  const initialExtensions = [
    0x0000, // SNI
    0x0017, // EMS
    0xff01, // renegotiation_info
    0x000a, // supported_groups
    0x000b, // ec_point_formats
    0x0023, // session_ticket
    0x0010, // ALPN
    0x0005, // status_request (OCSP)
    0x000d, // signature_algorithms
    0x0012, // SCT
    0x0033, // key_share
    0x002d, // psk_modes
    0x002b, // supported_versions
    0x001b  // compress_certificate
  ];

  const constantCiphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9];
  const constantCurves = [29, 23, 24];
  const constantPointFormats = [0];
  const constantSigAlgs = [0x0403, 0x0804, 0x0401, 0x0503];
  const constantAlpn = ["h2", "http/1.1"];
  const constantVersion = 771; // 0x0303

  // Current working extensions
  const [currentExtensions, setCurrentExtensions] = useState<number[]>(initialExtensions);
  const [shuffledCount, setShuffledCount] = useState<number>(0);
  const [hasRunExperiment, setHasRunExperiment] = useState<boolean>(false);

  // Compute Baseline (Before)
  const baselineJA3: JA3Result = useMemo(() => {
    return computeJA3(constantVersion, constantCiphers, initialExtensions, constantCurves, constantPointFormats);
  }, []);

  const baselineJA4: JA4Result = useMemo(() => {
    return computeJA4({
      protocol: "t",
      version: constantVersion,
      hasSni: true,
      sniIsIp: false,
      ciphers: constantCiphers,
      extensions: initialExtensions,
      alpnProtocols: constantAlpn,
      signatureAlgorithms: constantSigAlgs,
      supportedVersions: [0x0304, 0x0303]
    });
  }, []);

  // Compute Current (After)
  const currentJA3: JA3Result = useMemo(() => {
    return computeJA3(constantVersion, constantCiphers, currentExtensions, constantCurves, constantPointFormats);
  }, [currentExtensions]);

  const currentJA4: JA4Result = useMemo(() => {
    return computeJA4({
      protocol: "t",
      version: constantVersion,
      hasSni: true,
      sniIsIp: false,
      ciphers: constantCiphers,
      extensions: currentExtensions,
      alpnProtocols: constantAlpn,
      signatureAlgorithms: constantSigAlgs,
      supportedVersions: [0x0304, 0x0303]
    });
  }, [currentExtensions]);

  // Execute Experiment: Shuffle Extension Order
  const executeShuffle = () => {
    // Permute array guaranteed to differ from current
    let permuted = [...currentExtensions];
    do {
      permuted = [...permuted].sort(() => Math.random() - 0.5);
    } while (permuted.every((val, idx) => val === currentExtensions[idx]));

    setCurrentExtensions(permuted);
    setShuffledCount((prev) => prev + 1);
    setHasRunExperiment(true);
  };

  // Reset to Baseline
  const resetExperiment = () => {
    setCurrentExtensions(initialExtensions);
    setShuffledCount(0);
    setHasRunExperiment(false);
  };

  const ja3Match = baselineJA3.hash === currentJA3.hash;
  const ja4Match = baselineJA4.full === currentJA4.full;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Hero Classroom Experiment Banner */}
      <div style={{
        background: "linear-gradient(135deg, rgba(6, 182, 212, 0.15) 0%, rgba(168, 85, 247, 0.1) 100%)",
        border: "1px solid rgba(6, 182, 212, 0.35)",
        borderRadius: "var(--radius-xl)",
        padding: "24px 30px",
        boxShadow: "0 0 35px rgba(6, 182, 212, 0.15)"
      }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <span className="badge badge-cyan" style={{ fontSize: "0.85rem", padding: "4px 10px" }}>
                آزمایش شاخص کلاس امنیت شبکه
              </span>
              {shuffledCount > 0 && (
                <span className="badge badge-purple">
                  {shuffledCount} مرتبه جابجایی انجام شد
                </span>
              )}
            </div>
            <h2 style={{ fontSize: "1.45rem", fontWeight: 800, color: "#ffffff", letterSpacing: "-0.01em" }}>
              آیا تغییر ترتیب Extensions اثر انگشت را تغییر می‌دهد؟
            </h2>
            <p style={{ fontSize: "0.95rem", color: "var(--text-muted)", marginTop: 6, maxWidth: 850, lineHeight: 1.7 }}>
              در مرورگرهای مدرن (به‌ویژه Google Chrome)، ترتیب قرارگیری افزونه‌های TLS برای جلوگیری از فرسودگی پروتکل (Protocol Ossification) تصادفی می‌شود.
              در این آزمایش، تنها ترتیب افزونه‌ها جابجا می‌شود و هیچ فیلد دیگری تغییر نمی‌کند تا رفتار JA3 و JA4 در کنار هم سنجیده شود.
            </p>
          </div>

          {/* Action Trigger Buttons */}
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <button
              id="btn-shuffle-extensions"
              onClick={executeShuffle}
              className="btn btn-primary btn-lg"
              style={{
                boxShadow: "0 0 25px rgba(6, 182, 212, 0.5)",
                fontWeight: 700,
                padding: "12px 24px"
              }}
            >
              <Shuffle size={20} />
              <span>تغییر ترتیب Extensions (اجرای آزمایش)</span>
            </button>
            <button
              id="btn-reset-experiment"
              onClick={resetExperiment}
              className="btn btn-secondary btn-lg"
              title="بازنشانی آزمایش به حالت اولیه"
            >
              <RefreshCw size={18} />
              <span>بازنشانی</span>
            </button>
          </div>
        </div>
      </div>

      {/* Side-by-Side Comparison Grid */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "1fr 1fr",
        gap: 24
      }}>
        {/* RIGHT CARD: JA3 Behavior */}
        <div className="panel" style={{
          border: hasRunExperiment && !ja3Match
            ? "2px solid #f43f5e"
            : "1px solid var(--border-medium)",
          background: "linear-gradient(180deg, #10182b 0%, #0c1322 100%)",
          boxShadow: hasRunExperiment && !ja3Match ? "0 0 25px rgba(244, 63, 94, 0.2)" : "none",
          transition: "all 0.3s ease"
        }}>
          <div className="panel-header">
            <div className="panel-title" style={{ color: "#ffffff" }}>
              <span style={{
                background: "rgba(244, 63, 94, 0.2)",
                color: "#fb7185",
                padding: "6px 10px",
                borderRadius: "var(--radius-sm)",
                fontSize: "0.85rem"
              }}>
                نسل اول
              </span>
              <span style={{ fontSize: "1.2rem", fontWeight: 800 }}>اثر انگشت JA3</span>
            </div>
            {hasRunExperiment ? (
              <span className={`badge ${ja3Match ? "badge-emerald" : "badge-rose"}`} style={{ fontSize: "0.85rem", padding: "5px 10px" }}>
                {ja3Match ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
                <span>{ja3Match ? "یکسان ماند" : "❌ هش تغییر کرد! (شکننده)"}</span>
              </span>
            ) : (
              <span className="badge">حالت اولیه (Baseline)</span>
            )}
          </div>

          {/* Hashes Display */}
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                هش قبل از جابجایی (Baseline):
              </span>
              <div className="mono" style={{
                background: "#080d1a",
                padding: "8px 12px",
                borderRadius: "var(--radius-sm)",
                color: "#38bdf8",
                fontSize: "0.95rem"
              }}>
                {baselineJA3.hash}
              </div>
            </div>

            <div>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                هش بعد از جابجایی (Current):
              </span>
              <div className={`mono ${hasRunExperiment && !ja3Match ? "hash-pill changed" : ""}`} style={{
                background: hasRunExperiment && !ja3Match ? "rgba(244, 63, 94, 0.15)" : "#080d1a",
                border: hasRunExperiment && !ja3Match ? "1px solid #f43f5e" : "1px solid var(--border-medium)",
                padding: "8px 12px",
                borderRadius: "var(--radius-sm)",
                color: hasRunExperiment && !ja3Match ? "#fda4af" : "#38bdf8",
                fontSize: "0.95rem",
                fontWeight: 700
              }}>
                {currentJA3.hash}
              </div>
            </div>

            {/* Technical Explanation */}
            <div style={{
              background: "rgba(244, 63, 94, 0.08)",
              border: "1px solid rgba(244, 63, 94, 0.25)",
              borderRadius: "var(--radius-md)",
              padding: "14px",
              marginTop: 6
            }}>
              <strong style={{ color: "#fb7185", fontSize: "0.9rem", display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                <ShieldAlert size={16} />
                <span>علت فنی تغییر هش در JA3:</span>
              </strong>
              <p style={{ fontSize: "0.84rem", color: "var(--text-muted)", lineHeight: 1.6 }}>
                در الگوریتم JA3، فیلد سوم دقیقاً همان رشته افزونه‌ها به ترتیب دریافت‌شده از شبکه است:
                <br />
                <span className="mono" style={{ color: "#fda4af", fontSize: "0.78rem", wordBreak: "break-all" }}>
                  {baselineJA3.parts.extensionsStr.substring(0, 32)}...
                </span>
                <br />
                با تغییر فیزیکی ترتیب بایت‌ها در پیام، رشته خام ورودی به تابع MD5 تغییر می‌کند؛ در نتیجه هش خروجی کاملاً متفاوت خواهد بود.
              </p>
            </div>
          </div>
        </div>

        {/* LEFT CARD: JA4 Behavior */}
        <div className="panel" style={{
          border: hasRunExperiment && ja4Match
            ? "2px solid #10b981"
            : "1px solid var(--border-medium)",
          background: "linear-gradient(180deg, #101c2b 0%, #0c1522 100%)",
          boxShadow: hasRunExperiment && ja4Match ? "0 0 25px rgba(16, 185, 129, 0.25)" : "none",
          transition: "all 0.3s ease"
        }}>
          <div className="panel-header">
            <div className="panel-title" style={{ color: "#ffffff" }}>
              <span style={{
                background: "rgba(16, 185, 129, 0.2)",
                color: "#34d399",
                padding: "6px 10px",
                borderRadius: "var(--radius-sm)",
                fontSize: "0.85rem"
              }}>
                نسل مدرن
              </span>
              <span style={{ fontSize: "1.2rem", fontWeight: 800 }}>اثر انگشت JA4</span>
            </div>
            {hasRunExperiment ? (
              <span className="badge badge-emerald" style={{ fontSize: "0.85rem", padding: "5px 10px" }}>
                <CheckCircle2 size={15} />
                <span>✅ کاملاً یکسان ماند! (مقاوم)</span>
              </span>
            ) : (
              <span className="badge">حالت اولیه (Baseline)</span>
            )}
          </div>

          {/* Fingerprints Display */}
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                اثر انگشت قبل از جابجایی (Baseline):
              </span>
              <div className="mono" style={{
                background: "#080d1a",
                padding: "8px 12px",
                borderRadius: "var(--radius-sm)",
                color: "#34d399",
                fontSize: "0.95rem"
              }}>
                {baselineJA4.full}
              </div>
            </div>

            <div>
              <span style={{ fontSize: "0.8rem", color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                اثر انگشت بعد از جابجایی (Current):
              </span>
              <div className={`mono ${hasRunExperiment && ja4Match ? "hash-pill identical" : ""}`} style={{
                background: hasRunExperiment && ja4Match ? "rgba(16, 185, 129, 0.15)" : "#080d1a",
                border: hasRunExperiment && ja4Match ? "1px solid #10b981" : "1px solid var(--border-medium)",
                padding: "8px 12px",
                borderRadius: "var(--radius-sm)",
                color: "#34d399",
                fontSize: "0.95rem",
                fontWeight: 700
              }}>
                {currentJA4.full}
              </div>
            </div>

            {/* Technical Explanation */}
            <div style={{
              background: "rgba(16, 185, 129, 0.08)",
              border: "1px solid rgba(16, 185, 129, 0.25)",
              borderRadius: "var(--radius-md)",
              padding: "14px",
              marginTop: 6
            }}>
              <strong style={{ color: "#34d399", fontSize: "0.9rem", display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
                <ShieldCheck size={16} />
                <span>علت فنی پایداری اثر انگشت در JA4:</span>
              </strong>
              <p style={{ fontSize: "0.84rem", color: "var(--text-muted)", lineHeight: 1.6 }}>
                در الگوریتم JA4، افزونه‌ها در بخش <strong>JA4_c</strong> پیش از هش‌شدن بر حسب مقدار هگزادسیمال مرتب صعودی می‌شوند (<span className="mono">sort()</span>).
                <br />
                بنابراین صرف‌نظر از این‌که مرورگر با چه ترتیبی افزونه‌ها را ارسال کند، رشته ورودی تابع SHA-256 همیشه یکسان بوده و اثر انگشت پایداری شگفت‌انگیزی دارد.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Raw String Comparative Diff Panel */}
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">
            <Code2 size={20} color="#06b6d4" />
            <span>مقایسه فیلد به فیلد رشته‌های ورودی قبل و بعد از جابجایی</span>
          </div>
          <span className="badge badge-cyan">تحلیل عمیق تفاوت‌ها</span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
          {/* JA3 Raw Comparison */}
          <div>
            <h4 style={{ fontSize: "0.9rem", fontWeight: 700, color: "#ffffff", marginBottom: 8 }}>
              رشته خام JA3 قبل و بعد:
            </h4>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <div>
                <span style={{ fontSize: "0.75rem", color: "var(--text-dim)" }}>قبل:</span>
                <div className="mono" style={{ background: "#080d1a", padding: "6px 10px", borderRadius: 4, fontSize: "0.78rem", wordBreak: "break-all", color: "#38bdf8" }}>
                  {baselineJA3.raw}
                </div>
              </div>
              <div>
                <span style={{ fontSize: "0.75rem", color: "var(--text-dim)" }}>بعد:</span>
                <div className="mono" style={{
                  background: "#080d1a",
                  padding: "6px 10px",
                  borderRadius: 4,
                  fontSize: "0.78rem",
                  wordBreak: "break-all",
                  color: hasRunExperiment && !ja3Match ? "#fb7185" : "#38bdf8",
                  border: hasRunExperiment && !ja3Match ? "1px solid rgba(244, 63, 94, 0.4)" : "none"
                }}>
                  {currentJA3.raw}
                </div>
              </div>
            </div>
          </div>

          {/* JA4 Sorted Extensions Comparison */}
          <div>
            <h4 style={{ fontSize: "0.9rem", fontWeight: 700, color: "#ffffff", marginBottom: 8 }}>
              رشته خام JA4_c (پس از مرتب‌سازی خودکار):
            </h4>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <div>
                <span style={{ fontSize: "0.75rem", color: "var(--text-dim)" }}>قبل:</span>
                <div className="mono" style={{ background: "#080d1a", padding: "6px 10px", borderRadius: 4, fontSize: "0.78rem", wordBreak: "break-all", color: "#34d399" }}>
                  {baselineJA4.raw_c}
                </div>
              </div>
              <div>
                <span style={{ fontSize: "0.75rem", color: "var(--text-dim)" }}>بعد (دقیقاً تطابق ۱۰۰٪):</span>
                <div className="mono" style={{
                  background: "#080d1a",
                  padding: "6px 10px",
                  borderRadius: 4,
                  fontSize: "0.78rem",
                  wordBreak: "break-all",
                  color: "#34d399",
                  border: hasRunExperiment && ja4Match ? "1px solid rgba(16, 185, 129, 0.4)" : "none"
                }}>
                  {currentJA4.raw_c}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
