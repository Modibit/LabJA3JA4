import React, { useState } from "react";
import {
  HelpCircle,
  KeyRound,
  Send,
  Users,
  Wrench,
  EyeOff,
  Shuffle,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  CheckCircle2,
  XCircle
} from "lucide-react";

interface MythItem {
  id: string;
  icon: React.ReactNode;
  myth: string;
  reality: string;
  details: string;
  tag: string;
  badgeColor: string;
}

export const MythsAndLimitationsView: React.FC = () => {
  const [expandedId, setExpandedId] = useState<string | null>("keys");

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const myths: MythItem[] = [
    {
      id: "keys",
      icon: <KeyRound size={22} color="#06b6d4" />,
      myth: "آیا برای محاسبه اثر انگشت به کلید خصوصی سرور یا رمزگشایی HTTPS نیاز داریم؟",
      reality: "خیر! ClientHello در ابتدای اتصال به صورت کاملاً آشکار (Cleartext) ارسال می‌شود.",
      details: "فرایند اثر انگشت‌نگاری پیش از تکمیل تبادل کلید انجام می‌شود. بنابراین ناظر شبکه بدون نیاز به گواهی، کلید خصوصی، یا نفوذ در ترافیک (MitM)، صرفاً با گوش‌دادن به بسته اولیه قادر به استخراج این اثر انگشت است.",
      tag: "امنیت رمزنگاری",
      badgeColor: "#06b6d4"
    },
    {
      id: "sent_field",
      icon: <Send size={22} color="#10b981" />,
      myth: "آیا مقدار هش JA3 یا JA4 به عنوان یک فیلد درون بسته شبکه ارسال می‌شود؟",
      reality: "خیر! کلاینت اصلاً مقداری به نام اثر انگشت ارسال نمی‌کند.",
      details: "اثر انگشت یک محاسبه یک‌طرفه توسط ابزار دیده‌بانی شبکه (مانند فایروال یا سنسور IDS) است. کلاینت فقط قابلیت‌های خود را اعلام می‌کند و هیچ آگاهی از محاسبه یا فرمول JA3/JA4 ندارد.",
      tag: "معماری شبکه",
      badgeColor: "#10b981"
    },
    {
      id: "single_user",
      icon: <Users size={22} color="#f59e0b" />,
      myth: "آیا یک اثر انگشت یکسان به معنی اتصال همان کاربر یا یک کامپیوتر مشخص است؟",
      reality: "خیر! اثر انگشت نشان‌دهنده پشته نرم‌افزاری و کتابخانه TLS است؛ نه کاربر انسانی.",
      details: "میلیون‌ها کاربر در سراسر جهان که از نسخه یکسانی از Google Chrome روی Windows استفاده می‌کنند، دقیقاً اثر انگشت یکسانی تولید خواهند کرد. اثر انگشت TLS نباید با هویت شخصی یا اثر انگشت فیزیکی اشتباه گرفته شود.",
      tag: "حریم خصوصی",
      badgeColor: "#f59e0b"
    },
    {
      id: "library_changes",
      icon: <Wrench size={22} color="#a855f7" />,
      myth: "آیا اثر انگشت یک نرم‌افزار همواره در گذر زمان ثابت باقی می‌ماند؟",
      reality: "خیر! با یک به‌روزرسانی ساده OpenSSL یا فعال‌سازی گزینه‌های اتصال، اثر انگشت تغییر می‌کند.",
      details: "حتی اضافه شدن یک افزونه اختیاری، تغییر ترتیب ترجیحی سایفرها، یا به‌روزرسانی کتابخانه cURL و Python می‌تواند اثر انگشت قبلی را باطل کند و یک مقدار جدید تولید نماید.",
      tag: "پایداری پشته",
      badgeColor: "#a855f7"
    },
    {
      id: "ech",
      icon: <EyeOff size={22} color="#f43f5e" />,
      myth: "فناوری ECH (Encrypted Client Hello) چه تغییری در این معادله ایجاد می‌کند؟",
      reality: "با ECH، بخش حساس ClientHello (شامل نام دامنه SNI و افزونه‌ها) برای ناظر پنهان می‌شود!",
      details: "در پروتکل نوین ECH، کلاینت بخش اصلی بسته را با کلید عمومی منتشرشده سرور در DNS (از طریق رکوردهای HTTPS) رمزنگاری می‌کند. ناظر فقط یک پیام بیرونی ساختگی (Outer ClientHello) را می‌بیند و اثر انگشت واقعی پنهان می‌ماند.",
      tag: "آینده TLS",
      badgeColor: "#f43f5e"
    },
    {
      id: "reordering",
      icon: <Shuffle size={22} color="#3b82f6" />,
      myth: "آیا تغییر ترتیب افزونه‌ها در شبکه به معنی تفاوت واقعی در قابلیت‌های کلاینت است؟",
      reality: "خیر! قابلیت‌ها یکسان است و این ضعف JA3 بود که JA4 آن را حل کرد.",
      details: "مرورگرهایی مثل کروم برای جلوگیری از وابستگی فایروال‌ها به ترتیب خاص، افزونه‌ها را به صورت تصادفی مرتب می‌کنند. JA3 فریب این جابجایی ترتیبی را می‌خورد اما JA4 با سورت کردن افزونه‌ها پیش از هش‌کردن، پایداری خود را حفظ می‌کند.",
      tag: "تفاوت JA3 و JA4",
      badgeColor: "#3b82f6"
    }
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Header Banner */}
      <div className="panel" style={{ border: "1px solid rgba(245, 158, 11, 0.3)" }}>
        <div className="panel-header">
          <div className="panel-title">
            <HelpCircle size={22} color="#f59e0b" />
            <span>JA3 و JA4 چه چیزی را نمی‌توانند تشخیص دهند؟ (رفع ابهام و محدودیت‌ها)</span>
          </div>
          <span className="badge badge-amber">نکات کلیدی برای آزمون و دفاع کلاسی</span>
        </div>

        <p style={{ fontSize: "0.92rem", color: "var(--text-muted)", lineHeight: 1.7 }}>
          در تحلیل امنیتی شبکه، شناخت محدودیت‌های یک ابزار به اندازه شناخت توانایی‌های آن اهمیت دارد.
          برای درک عمیق‌تر هر مفهوم و پرهیز از نتیجه‌گیری‌های اشتباه، روی هر کارت کلیک کنید:
        </p>
      </div>

      {/* Grid of Interactive Myth Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: 18 }}>
        {myths.map((m) => {
          const isExpanded = expandedId === m.id;
          return (
            <div
              key={m.id}
              onClick={() => toggleExpand(m.id)}
              style={{
                background: "var(--bg-card)",
                border: isExpanded ? `2px solid ${m.badgeColor}` : "1px solid var(--border-medium)",
                borderRadius: "var(--radius-lg)",
                padding: "18px 20px",
                cursor: "pointer",
                transition: "all 0.2s ease",
                boxShadow: isExpanded ? `0 0 20px ${m.badgeColor}22` : "var(--shadow-card)",
                display: "flex",
                flexDirection: "column",
                gap: 12
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <span className="badge" style={{ backgroundColor: `${m.badgeColor}22`, color: m.badgeColor, borderColor: `${m.badgeColor}55` }}>
                  {m.tag}
                </span>
                <div style={{ color: "var(--text-muted)" }}>
                  {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                </div>
              </div>

              <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                <div style={{
                  background: `${m.badgeColor}18`,
                  padding: 8,
                  borderRadius: "var(--radius-md)",
                  display: "flex",
                  flexShrink: 0
                }}>
                  {m.icon}
                </div>
                <div>
                  <h3 style={{ fontSize: "0.98rem", fontWeight: 700, color: "#ffffff", marginBottom: 6 }}>
                    {m.myth}
                  </h3>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <CheckCircle2 size={16} color={m.badgeColor} style={{ flexShrink: 0 }} />
                    <span style={{ fontSize: "0.85rem", fontWeight: 600, color: m.badgeColor }}>
                      {m.reality}
                    </span>
                  </div>
                </div>
              </div>

              {isExpanded && (
                <div style={{
                  background: "var(--bg-surface)",
                  border: "1px solid var(--border-dim)",
                  borderRadius: "var(--radius-md)",
                  padding: "12px 14px",
                  fontSize: "0.84rem",
                  color: "var(--text-muted)",
                  lineHeight: 1.7,
                  marginTop: 4
                }}>
                  {m.details}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
