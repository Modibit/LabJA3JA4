import React, { useState, useEffect } from "react";
import {
  X,
  ChevronRight,
  ChevronLeft,
  Tv,
  CheckCircle2,
  XCircle,
  Shuffle,
  RefreshCw,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  Lightbulb,
  Radio,
  Cpu,
  Activity,
  Layers,
  FlaskConical,
  GitCompare,
  HelpCircle
} from "lucide-react";
import { computeJA3 } from "../utils/ja3";
import { computeJA4 } from "../utils/ja4";

interface PresentationModeProps {
  onClose: () => void;
}

export const PresentationModeView: React.FC<PresentationModeProps> = ({ onClose }) => {
  const [currentStep, setCurrentStep] = useState<number>(1);
  const [showNotes, setShowNotes] = useState<boolean>(true);

  // Core experiment state inside presentation slide 4
  const initialExtensions = [0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b];
  const [slideExtensions, setSlideExtensions] = useState<number[]>(initialExtensions);
  const [slideShuffled, setSlideShuffled] = useState<boolean>(false);

  const baselineJA3 = computeJA3(771, [0x1301, 0x1302, 0xc02b, 0xc02f], initialExtensions, [29, 23], [0]);
  const baselineJA4 = computeJA4({
    protocol: "t",
    version: 771,
    hasSni: true,
    sniIsIp: false,
    ciphers: [0x1301, 0x1302, 0xc02b, 0xc02f],
    extensions: initialExtensions,
    alpnProtocols: ["h2"],
    signatureAlgorithms: [0x0403, 0x0804],
    supportedVersions: [0x0304, 0x0303]
  });

  const currentJA3 = computeJA3(771, [0x1301, 0x1302, 0xc02b, 0xc02f], slideExtensions, [29, 23], [0]);
  const currentJA4 = computeJA4({
    protocol: "t",
    version: 771,
    hasSni: true,
    sniIsIp: false,
    ciphers: [0x1301, 0x1302, 0xc02b, 0xc02f],
    extensions: slideExtensions,
    alpnProtocols: ["h2"],
    signatureAlgorithms: [0x0403, 0x0804],
    supportedVersions: [0x0304, 0x0303]
  });

  const shuffleSlideExtensions = () => {
    let permuted = [...slideExtensions];
    do {
      permuted = [...permuted].sort(() => Math.random() - 0.5);
    } while (permuted.every((val, idx) => val === slideExtensions[idx]));
    setSlideExtensions(permuted);
    setSlideShuffled(true);
  };

  const resetSlideExtensions = () => {
    setSlideExtensions(initialExtensions);
    setSlideShuffled(false);
  };

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "ArrowLeft") {
        setCurrentStep((prev) => Math.min(prev + 1, 7));
      } else if (e.key === "ArrowRight") {
        setCurrentStep((prev) => Math.max(prev - 1, 1));
      } else if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  const steps = [
    { number: 1, title: "TLS Handshake و جایگاه ClientHello" },
    { number: 2, title: "منطق ساخت اثر انگشت JA3" },
    { number: 3, title: "تکامل و ساختار سه‌بخشی JA4" },
    { number: 4, title: "آزمایش زنده کلاسی: جابجایی افزونه‌ها" },
    { number: 5, title: "تحلیل تطبیقی ترافیک کلاینت‌ها" },
    { number: 6, title: "کاربردهای امنیتی و محدودیت‌ها" },
    { number: 7, title: "جمع‌بندی نهایی ۳ پیام کلیدی" },
  ];

  const presenterNotes: Record<number, string> = {
    1: "نکته ارائه: تأکید کنید که ClientHello اولین پیام دست‌دهی است و هنوز هیچ رمزنگاری صورت نگرفته است (متن آشکار). ناظر شبکه بدون نیاز به کلید سرور یا بازکردن HTTPS، فیلدهای آن را مستقیماً شنود می‌کند.",
    2: "نکته ارائه: فرمول JA3 متشکل از ۵ فیلد با جداکننده کاما است: SSLVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats. مقادیر GREASE فیلتر می‌شوند اما ترتیب فیزیکی افزونه‌ها دقیقاً همانطور که آمده هش می‌شود.",
    3: "نکته ارائه: به کلاس نشان دهید که چگونه JA4 به سه بخش تقسیم شده: JA4_a که ۱۰ کاراکتر بدون هش و قابل خواندن است، JA4_b که سایفرهای سورت‌شده است، و JA4_c که افزونه‌های سورت‌شده به علاوه امضاها است.",
    4: "نکته ارائه: دکمه جابجایی را بزنید! به کلاس نشان دهید که JA3 قرمز شده و عوض شد، اما JA4 سبز ماند و بدون تغییر ماند. این لحظه هیجان‌انگیز اصلی کلاس است که علت مهاجرت صنعت از JA3 به JA4 را اثبات می‌کند.",
    5: "نکته ارائه: تفاوت میان مرورگرها و ابزارهایی مانند پایتون را برجسته کنید. به عنوان مثال، پایتون به طور پیش‌فرض ALPN h2 ندارد و در نتیجه در هدرهای JA4_a کد '00' می‌گیرد؛ بنابراین جعل هدر User-Agent بلافاصله کشف می‌شود.",
    6: "نکته ارائه: به محدودیت‌های حیاتی اشاره کنید: اثر انگشت نشان‌دهنده کتابخانه نرم‌افزاری است، نه یک انسان یا کامپیوتر واحد. همچنین با ورود ECH، بخش حساس ClientHello پنهان خواهد شد.",
    7: "نکته ارائه: سه پیام نهایی را با صدای رسا قرائت کرده و اسلاید را برای پرسش و پاسخ دانشجویان و استاد باز بگذارید."
  };

  return (
    <div style={{
      position: "fixed",
      inset: 0,
      zIndex: 100,
      backgroundColor: "#050811",
      color: "#ffffff",
      display: "flex",
      flexDirection: "column",
      overflow: "hidden"
    }}>
      {/* Top Projector Control Bar */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "16px 32px",
        background: "rgba(11, 18, 34, 0.95)",
        borderBottom: "1px solid var(--border-medium)"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{
            background: "linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)",
            color: "#ffffff",
            padding: 8,
            borderRadius: "var(--radius-md)",
            display: "flex"
          }}>
            <Tv size={24} />
          </div>
          <div>
            <span style={{ fontSize: "0.85rem", color: "#38bdf8", fontWeight: 700 }}>
              حالت ارائه در کلاس درس (Projector Mode)
            </span>
            <h2 style={{ fontSize: "1.2rem", fontWeight: 800 }}>
              گام {currentStep} از ۷: {steps[currentStep - 1].title}
            </h2>
          </div>
        </div>

        {/* Navigation & Controls */}
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <button
            onClick={() => setShowNotes(!showNotes)}
            className={`btn btn-sm ${showNotes ? "btn-primary" : "btn-secondary"}`}
          >
            <Lightbulb size={16} />
            <span>{showNotes ? "پنهان‌سازی یادداشت" : "مشاهده یادداشت ارائه‌دهنده"}</span>
          </button>

          <button
            onClick={() => setCurrentStep((prev) => Math.max(prev - 1, 1))}
            disabled={currentStep === 1}
            className="btn btn-secondary"
            style={{ opacity: currentStep === 1 ? 0.4 : 1 }}
          >
            <ChevronRight size={18} />
            <span>گام قبل</span>
          </button>

          <button
            onClick={() => setCurrentStep((prev) => Math.min(prev + 1, 7))}
            disabled={currentStep === 7}
            className="btn btn-primary"
            style={{ opacity: currentStep === 7 ? 0.4 : 1 }}
          >
            <span>گام بعد</span>
            <ChevronLeft size={18} />
          </button>

          <button
            onClick={onClose}
            className="btn btn-outline"
            style={{ padding: "8px 12px" }}
            title="خروج از حالت ارائه (Esc)"
          >
            <X size={20} />
          </button>
        </div>
      </div>

      {/* Step Progress Indicators */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(7, 1fr)",
        gap: 4,
        padding: "8px 32px",
        background: "#080d1a",
        borderBottom: "1px solid var(--border-dim)"
      }}>
        {steps.map((s) => (
          <div
            key={s.number}
            onClick={() => setCurrentStep(s.number)}
            style={{
              height: 6,
              borderRadius: 3,
              background: s.number === currentStep
                ? "#06b6d4"
                : s.number < currentStep
                ? "#10b981"
                : "rgba(255,255,255,0.1)",
              cursor: "pointer",
              transition: "all 0.2s ease"
            }}
            title={`گام ${s.number}: ${s.title}`}
          />
        ))}
      </div>

      {/* Main Slide Content Area (High contrast, large fonts) */}
      <div style={{
        flex: 1,
        overflowY: "auto",
        padding: "40px 60px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        maxWidth: 1300,
        margin: "0 auto",
        width: "100%"
      }}>
        {/* SLIDE 1 */}
        {currentStep === 1 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 30 }}>
            <span className="badge badge-cyan" style={{ fontSize: "1rem", alignSelf: "flex-start", padding: "6px 14px" }}>
              مفهوم بنیادی
            </span>
            <h1 style={{ fontSize: "2.4rem", fontWeight: 800, lineHeight: 1.3 }}>
              دیده‌بانی منفعل در دست‌دهی TLS و جایگاه بسته ClientHello
            </h1>
            <p style={{ fontSize: "1.25rem", color: "var(--text-muted)", lineHeight: 1.8 }}>
              برای رمزنگاری ارتباط وب، مرورگر باید ابتدا با ارسال بسته <strong style={{ color: "#38bdf8" }}>ClientHello</strong> قابلیت‌ها، سایفرها و نسخه‌های پشتیبانی‌شده خود را به سرور اعلام کند.
            </p>

            <div style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr 1fr",
              gap: 20,
              marginTop: 10
            }}>
              <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-medium)", padding: 24, borderRadius: "var(--radius-lg)" }}>
                <div style={{ fontSize: "2rem", marginBottom: 8 }}>🔓</div>
                <h3 style={{ fontSize: "1.2rem", fontWeight: 700, color: "#38bdf8", marginBottom: 6 }}>متن کاملاً آشکار</h3>
                <p style={{ fontSize: "0.95rem", color: "var(--text-muted)" }}>
                  هنوز کلید رمزی تولید نشده است؛ پیام اولیه برای هر ناظر شبکه قابل خواندن است.
                </p>
              </div>

              <div style={{ background: "rgba(6, 182, 212, 0.1)", border: "1px solid rgba(6, 182, 212, 0.3)", padding: 24, borderRadius: "var(--radius-lg)" }}>
                <div style={{ fontSize: "2rem", marginBottom: 8 }}>👁️</div>
                <h3 style={{ fontSize: "1.2rem", fontWeight: 700, color: "#38bdf8", marginBottom: 6 }}>دیده‌بانی منفعل (Passive)</h3>
                <p style={{ fontSize: "0.95rem", color: "var(--text-muted)" }}>
                  نیازی به دستکاری بسته یا داشتن کلید خصوصی سرور نیست. ناظر فقط گوش می‌دهد.
                </p>
              </div>

              <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-medium)", padding: 24, borderRadius: "var(--radius-lg)" }}>
                <div style={{ fontSize: "2rem", marginBottom: 8 }}>🧩</div>
                <h3 style={{ fontSize: "1.2rem", fontWeight: 700, color: "#38bdf8", marginBottom: 6 }}>اثر انگشت در بسته نیست!</h3>
                <p style={{ fontSize: "0.95rem", color: "var(--text-muted)" }}>
                  کلاینت JA3 یا JA4 ارسال نمی‌کند؛ این مقدار خروجی محاسبه ناظر شبکه است.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* SLIDE 2 */}
        {currentStep === 2 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 26 }}>
            <span className="badge badge-rose" style={{ fontSize: "1rem", alignSelf: "flex-start", padding: "6px 14px" }}>
              معماری نسل اول
            </span>
            <h1 style={{ fontSize: "2.3rem", fontWeight: 800 }}>
              منطق و فرمول اثر انگشت JA3 (استاندارد ۲۰۱۷ شرکت Salesforce)
            </h1>
            <p style={{ fontSize: "1.2rem", color: "var(--text-muted)", lineHeight: 1.7 }}>
              ساده، سریع و انقلابی: استخراج ۵ فیلد با فرمت ده‌دهی و هش‌کردن آن با الگوریتم MD5:
            </p>

            <div style={{
              background: "#080d1a",
              border: "1px solid var(--border-medium)",
              padding: "20px 24px",
              borderRadius: "var(--radius-md)",
              fontFamily: "var(--font-mono)",
              fontSize: "1.25rem",
              direction: "ltr",
              textAlign: "left"
            }}>
              <span style={{ color: "#34d399" }}>SSLVersion</span>,
              <span style={{ color: "#38bdf8" }}>CipherSuites</span>,
              <span style={{ color: "#a855f7" }}>Extensions</span>,
              <span style={{ color: "#fbbf24" }}>EllipticCurves</span>,
              <span style={{ color: "#f43f5e" }}>ECPointFormats</span>
            </div>

            <div style={{
              background: "rgba(244, 63, 94, 0.1)",
              border: "1px solid rgba(244, 63, 94, 0.3)",
              padding: "18px 24px",
              borderRadius: "var(--radius-md)"
            }}>
              <strong style={{ color: "#fb7185", fontSize: "1.1rem" }}>نقطه ضعف اساسی JA3 چیست؟</strong>
              <p style={{ fontSize: "1rem", color: "var(--text-muted)", marginTop: 6, lineHeight: 1.7 }}>
                فیلد سوم (<span className="mono" style={{ color: "#a855f7" }}>Extensions</span>) دقیقاً به همان ترتیبی که در بسته دریافت شده هش می‌شود.
                اگر مرورگری مانند کروم ترتیب افزونه‌ها را به صورت تصادفی بر بزند، هش MD5 کلاً تغییر خواهد کرد!
              </p>
            </div>
          </div>
        )}

        {/* SLIDE 3 */}
        {currentStep === 3 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 26 }}>
            <span className="badge badge-emerald" style={{ fontSize: "1rem", alignSelf: "flex-start", padding: "6px 14px" }}>
              معماری نسل جدید
            </span>
            <h1 style={{ fontSize: "2.3rem", fontWeight: 800 }}>
              تکامل و ساختار سه‌بخشی JA4 (استاندارد ۲۰۲۳ شرکت FoxIO)
            </h1>
            <p style={{ fontSize: "1.2rem", color: "var(--text-muted)", lineHeight: 1.7 }}>
              مهندسی دوباره اثر انگشت با تفکیک به سه بخش کاربردی و مرتب‌سازی قطعی:
            </p>

            <div style={{
              display: "grid",
              gridTemplateColumns: "1.2fr 1fr 1fr",
              gap: 20
            }}>
              <div style={{ background: "var(--bg-surface)", border: "2px solid #06b6d4", padding: 20, borderRadius: "var(--radius-lg)" }}>
                <span className="badge badge-cyan" style={{ fontSize: "0.85rem" }}>بخش ۱: JA4_a</span>
                <div className="mono" style={{ fontSize: "1.6rem", fontWeight: 800, color: "#38bdf8", margin: "10px 0" }}>
                  t13d1514h2
                </div>
                <p style={{ fontSize: "0.9rem", color: "var(--text-muted)" }}>
                  ۱۰ کاراکتر قابل خواندن بدون هش: پروتکل، نسخه TLS، نشانگر دامنه SNI، تعداد سایفر و افزونه، و اولین ALPN.
                </p>
              </div>

              <div style={{ background: "var(--bg-surface)", border: "2px solid #3b82f6", padding: 20, borderRadius: "var(--radius-lg)" }}>
                <span className="badge badge-blue" style={{ fontSize: "0.85rem" }}>بخش ۲: JA4_b</span>
                <div className="mono" style={{ fontSize: "1.6rem", fontWeight: 800, color: "#60a5fa", margin: "10px 0" }}>
                  8daaf6152771
                </div>
                <p style={{ fontSize: "0.9rem", color: "var(--text-muted)" }}>
                  هش SHA-256 دوازده کاراکتری از سایفرهای مرتب‌شده بر حسب هگزادسیمال (حذف GREASE).
                </p>
              </div>

              <div style={{ background: "var(--bg-surface)", border: "2px solid #a855f7", padding: 20, borderRadius: "var(--radius-lg)" }}>
                <span className="badge badge-purple" style={{ fontSize: "0.85rem" }}>بخش ۳: JA4_c</span>
                <div className="mono" style={{ fontSize: "1.6rem", fontWeight: 800, color: "#c084fc", margin: "10px 0" }}>
                  bc9a4605e104
                </div>
                <p style={{ fontSize: "0.9rem", color: "var(--text-muted)" }}>
                  هش SHA-256 دوازده کاراکتری از افزونه‌های مرتب‌شده صعودی + الگوریتم‌های امضای اصلی.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* SLIDE 4: THE CORE EXPERIMENT */}
        {currentStep === 4 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div>
                <span className="badge badge-cyan" style={{ fontSize: "1rem" }}>آزمایش زنده</span>
                <h1 style={{ fontSize: "2.1rem", fontWeight: 800, marginTop: 4 }}>
                  آیا تغییر ترتیب Extensions اثر انگشت را تغییر می‌دهد؟
                </h1>
              </div>
              <div style={{ display: "flex", gap: 12 }}>
                <button
                  onClick={shuffleSlideExtensions}
                  className="btn btn-primary btn-lg"
                  style={{ boxShadow: "0 0 25px rgba(6, 182, 212, 0.5)", fontWeight: 700 }}
                >
                  <Shuffle size={20} />
                  <span>تغییر ترتیب افزونه‌ها (اجرا)</span>
                </button>
                <button onClick={resetSlideExtensions} className="btn btn-secondary btn-lg">
                  <RefreshCw size={18} />
                  <span>بازنشانی</span>
                </button>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
              {/* JA3 Result Card */}
              <div style={{
                background: "var(--bg-surface)",
                border: slideShuffled && baselineJA3.hash !== currentJA3.hash ? "2px solid #f43f5e" : "1px solid var(--border-medium)",
                borderRadius: "var(--radius-lg)",
                padding: "24px"
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                  <h3 style={{ fontSize: "1.3rem", fontWeight: 800 }}>اثر انگشت JA3</h3>
                  {slideShuffled ? (
                    <span className="badge badge-rose" style={{ fontSize: "0.9rem" }}>❌ هش تغییر کرد!</span>
                  ) : (
                    <span className="badge">حالت اولیه</span>
                  )}
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: 6 }}>هش قبل:</div>
                <div className="mono" style={{ background: "#080d1a", padding: "8px 12px", borderRadius: 4, color: "#38bdf8", marginBottom: 12 }}>
                  {baselineJA3.hash}
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: 6 }}>هش بعد:</div>
                <div className="mono" style={{
                  background: slideShuffled ? "rgba(244, 63, 94, 0.2)" : "#080d1a",
                  border: slideShuffled ? "1px solid #f43f5e" : "none",
                  padding: "8px 12px",
                  borderRadius: 4,
                  color: slideShuffled ? "#fda4af" : "#38bdf8",
                  fontWeight: 700
                }}>
                  {currentJA3.hash}
                </div>
                <p style={{ fontSize: "0.88rem", color: "var(--text-muted)", marginTop: 12, lineHeight: 1.6 }}>
                  JA3 به دلیل وابستگی به ترتیب افزونه‌ها تغییر یافت!
                </p>
              </div>

              {/* JA4 Result Card */}
              <div style={{
                background: "var(--bg-surface)",
                border: slideShuffled ? "2px solid #10b981" : "1px solid var(--border-medium)",
                borderRadius: "var(--radius-lg)",
                padding: "24px"
              }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                  <h3 style={{ fontSize: "1.3rem", fontWeight: 800 }}>اثر انگشت JA4</h3>
                  {slideShuffled ? (
                    <span className="badge badge-emerald" style={{ fontSize: "0.9rem" }}>✅ کاملاً یکسان ماند!</span>
                  ) : (
                    <span className="badge">حالت اولیه</span>
                  )}
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: 6 }}>اثر انگشت قبل:</div>
                <div className="mono" style={{ background: "#080d1a", padding: "8px 12px", borderRadius: 4, color: "#34d399", marginBottom: 12 }}>
                  {baselineJA4.full}
                </div>
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: 6 }}>اثر انگشت بعد:</div>
                <div className="mono" style={{
                  background: slideShuffled ? "rgba(16, 185, 129, 0.2)" : "#080d1a",
                  border: slideShuffled ? "1px solid #10b981" : "none",
                  padding: "8px 12px",
                  borderRadius: 4,
                  color: "#34d399",
                  fontWeight: 700
                }}>
                  {currentJA4.full}
                </div>
                <p style={{ fontSize: "0.88rem", color: "var(--text-muted)", marginTop: 12, lineHeight: 1.6 }}>
                  JA4 با سورت کردن افزونه‌ها قبل از هش، پایداری ۱۰۰٪ خود را حفظ کرد!
                </p>
              </div>
            </div>
          </div>
        )}

        {/* SLIDE 5 */}
        {currentStep === 5 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 26 }}>
            <span className="badge badge-purple" style={{ fontSize: "1rem", alignSelf: "flex-start", padding: "6px 14px" }}>
              تشخیص هویت کلاینت‌ها
            </span>
            <h1 style={{ fontSize: "2.3rem", fontWeight: 800 }}>
              چگونه اثر انگشت TLS کلاینت‌های مختلف را تفکیک می‌کند؟
            </h1>

            <div style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 20
            }}>
              <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-medium)", padding: 20, borderRadius: "var(--radius-lg)" }}>
                <h3 style={{ fontSize: "1.15rem", color: "#38bdf8", marginBottom: 8 }}>مرورگرها (Chrome / Firefox)</h3>
                <ul style={{ paddingRight: 20, fontSize: "0.95rem", color: "var(--text-muted)", lineHeight: 1.8 }}>
                  <li>پشتیبانی پیش‌فرض از ALPN برابر <span className="mono">h2, http/1.1</span></li>
                  <li>مجموعه غنی از ۱۵+ افزونه شامل فشرده‌سازی گواهی و SCT</li>
                  <li>تزریق مقادیر تصادفی GREASE در کروم</li>
                </ul>
              </div>

              <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-medium)", padding: 20, borderRadius: "var(--radius-lg)" }}>
                <h3 style={{ fontSize: "1.15rem", color: "#fbbf24", marginBottom: 8 }}>اسکریپت‌ها (Python / Curl)</h3>
                <ul style={{ paddingRight: 20, fontSize: "0.95rem", color: "var(--text-muted)", lineHeight: 1.8 }}>
                  <li>پایتون به طور پیش‌فرض فاقد ALPN است (<span className="mono">00</span> در JA4_a)</li>
                  <li>تعداد افزونه‌ها به مراتب کمتر از مرورگر واقعی است</li>
                  <li>حتی اگر هدر User-Agent ادعای کروم کند، اثر انگشت TLS جعل را افشا می‌کند!</li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* SLIDE 6 */}
        {currentStep === 6 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            <span className="badge badge-amber" style={{ fontSize: "1rem", alignSelf: "flex-start", padding: "6px 14px" }}>
              محدودیت‌ها و آینده
            </span>
            <h1 style={{ fontSize: "2.3rem", fontWeight: 800 }}>
              کاربرد در SOC و ۳ محدودیت اساسی که نباید فراموش شود
            </h1>

            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-dim)", padding: 18, borderRadius: "var(--radius-md)", display: "flex", gap: 14, alignItems: "center" }}>
                <div style={{ fontSize: "1.8rem" }}>1️⃣</div>
                <div>
                  <strong style={{ fontSize: "1.05rem", color: "#ffffff" }}>اثر انگشت مساوی با یک کاربر یا کامپیوتر واحد نیست</strong>
                  <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", marginTop: 2 }}>
                    اثر انگشت TLS تنها پشته شبکه و کتابخانه را مشخص می‌کند، نه هویت یک شخص را.
                  </p>
                </div>
              </div>

              <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-dim)", padding: 18, borderRadius: "var(--radius-md)", display: "flex", gap: 14, alignItems: "center" }}>
                <div style={{ fontSize: "1.8rem" }}>2️⃣</div>
                <div>
                  <strong style={{ fontSize: "1.05rem", color: "#ffffff" }}>امکان جعل با ابزارهای شبیه‌ساز (مانند uTLS و curl_impersonate)</strong>
                  <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", lineHeight: 1.6 }}>
                    نفوذگران می‌توانند بسته‌های ClientHello خود را دقیقاً با سایفرها و افزونه‌های کروم ارسال کنند تا اثر انگشت کروم جعل شود.
                  </p>
                </div>
              </div>

              <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-dim)", padding: 18, borderRadius: "var(--radius-md)", display: "flex", gap: 14, alignItems: "center" }}>
                <div style={{ fontSize: "1.8rem" }}>3️⃣</div>
                <div>
                  <strong style={{ fontSize: "1.05rem", color: "#ffffff" }}>رمزگذاری کامل ClientHello با فناوری نوین ECH</strong>
                  <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", lineHeight: 1.6 }}>
                    با فراگیر شدن پروتکل ECH، نام دامنه و افزونه‌ها از دید ناظر شبکه پنهان خواهد شد.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* SLIDE 7: FINAL TAKEAWAY (The 3 Core Messages) */}
        {currentStep === 7 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 30, textAlign: "center", alignItems: "center" }}>
            <span className="badge badge-emerald" style={{ fontSize: "1.05rem", padding: "6px 16px" }}>
              جمع‌بندی پایانی دمو
            </span>
            <h1 style={{ fontSize: "2.6rem", fontWeight: 900, color: "#ffffff" }}>
              ۳ پیام کلیدی آزمایشگاه اثر انگشت TLS
            </h1>

            <div style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr 1fr",
              gap: 24,
              marginTop: 10,
              textAlign: "right"
            }}>
              <div style={{
                background: "linear-gradient(180deg, rgba(6, 182, 212, 0.15) 0%, rgba(6, 182, 212, 0.05) 100%)",
                border: "2px solid #06b6d4",
                padding: "28px 24px",
                borderRadius: "var(--radius-xl)",
                display: "flex",
                flexDirection: "column",
                gap: 12
              }}>
                <div style={{
                  width: 44,
                  height: 44,
                  borderRadius: "50%",
                  background: "#06b6d4",
                  color: "#ffffff",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontWeight: 800,
                  fontSize: "1.2rem"
                }}>
                  ۱
                </div>
                <strong style={{ fontSize: "1.15rem", color: "#ffffff" }}>
                  دیده‌بانی از مشخصات اتصال
                </strong>
                <p style={{ fontSize: "0.95rem", color: "var(--text-muted)", lineHeight: 1.7 }}>
                  JA3 و JA4 از مشخصات اتصال پیام ابتدایی ClientHello اثر انگشت می‌سازند؛ بدون نیاز به کلید سرور یا ارسال فیلد توسط کلاینت.
                </p>
              </div>

              <div style={{
                background: "linear-gradient(180deg, rgba(16, 185, 129, 0.15) 0%, rgba(16, 185, 129, 0.05) 100%)",
                border: "2px solid #10b981",
                padding: "28px 24px",
                borderRadius: "var(--radius-xl)",
                display: "flex",
                flexDirection: "column",
                gap: 12
              }}>
                <div style={{
                  width: 44,
                  height: 44,
                  borderRadius: "50%",
                  background: "#10b981",
                  color: "#ffffff",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontWeight: 800,
                  fontSize: "1.2rem"
                }}>
                  ۲
                </div>
                <strong style={{ fontSize: "1.15rem", color: "#ffffff" }}>
                  پایداری JA4 در برابر جابجایی
                </strong>
                <p style={{ fontSize: "0.95rem", color: "var(--text-muted)", lineHeight: 1.7 }}>
                  JA4 با سورت کردن افزونه‌ها و سایفرها، در برابر شافلینگ تصادفی مرورگرها کاملاً مقاوم و پایدار است.
                </p>
              </div>

              <div style={{
                background: "linear-gradient(180deg, rgba(245, 158, 11, 0.15) 0%, rgba(245, 158, 11, 0.05) 100%)",
                border: "2px solid #f59e0b",
                padding: "28px 24px",
                borderRadius: "var(--radius-xl)",
                display: "flex",
                flexDirection: "column",
                gap: 12
              }}>
                <div style={{
                  width: 44,
                  height: 44,
                  borderRadius: "50%",
                  background: "#f59e0b",
                  color: "#ffffff",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontWeight: 800,
                  fontSize: "1.2rem"
                }}>
                  ۳
                </div>
                <strong style={{ fontSize: "1.15rem", color: "#ffffff" }}>
                  نشانه امنیتی، نه اثبات بدافزار
                </strong>
                <p style={{ fontSize: "0.95rem", color: "var(--text-muted)", lineHeight: 1.7 }}>
                  اثر انگشت یک شاخص ارزیابی (IoC) برای کشف ناهنجاری و جعل هویت است، نه اثبات قطعی آلودگی یا هویت یک کاربر.
                </p>
              </div>
            </div>

            <div style={{ marginTop: 20 }}>
              <button onClick={onClose} className="btn btn-primary btn-lg">
                <span>پایان ارائه و بازگشت به آزمایشگاه تعاملی</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Presenter Notes Footer (Collapsible) */}
      {showNotes && (
        <div style={{
          background: "#09101f",
          borderTop: "1px solid var(--border-medium)",
          padding: "14px 32px",
          display: "flex",
          alignItems: "center",
          gap: 12,
          fontSize: "0.92rem",
          color: "#fbbf24"
        }}>
          <Lightbulb size={20} style={{ flexShrink: 0 }} />
          <span>{presenterNotes[currentStep]}</span>
        </div>
      )}
    </div>
  );
};
