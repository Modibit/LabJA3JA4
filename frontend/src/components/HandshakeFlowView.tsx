import React, { useState } from "react";
import {
  Laptop,
  Radio,
  Server,
  ArrowLeft,
  Info,
  CheckCircle,
  Eye,
  Lock,
  Unlock,
  Sparkles,
  Zap
} from "lucide-react";
import { getCipherName, getExtensionName } from "../data/protocolKnowledge";

export const HandshakeFlowView: React.FC = () => {
  const [selectedPacket, setSelectedPacket] = useState<"client_hello" | "server_hello" | "encrypted" | null>("client_hello");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Educational Banner */}
      <div style={{
        background: "linear-gradient(135deg, rgba(6, 182, 212, 0.1) 0%, rgba(59, 130, 246, 0.05) 100%)",
        border: "1px solid rgba(6, 182, 212, 0.25)",
        borderRadius: "var(--radius-lg)",
        padding: "20px 24px",
        display: "flex",
        alignItems: "flex-start",
        gap: 16
      }}>
        <div style={{
          background: "rgba(6, 182, 212, 0.2)",
          color: "#38bdf8",
          padding: 10,
          borderRadius: "var(--radius-md)",
          display: "flex"
        }}>
          <Info size={24} />
        </div>
        <div>
          <h2 style={{ fontSize: "1.15rem", fontWeight: 700, color: "#ffffff", marginBottom: 6 }}>
            معماری دیده‌بانی منفعل (Passive Observation) در TLS
          </h2>
          <p style={{ fontSize: "0.92rem", color: "var(--text-muted)", lineHeight: 1.7 }}>
            برخلاف تصور رایج، کلاینت هیچ‌گاه مقداری به نام اثر انگشت JA3 یا JA4 در بسته ارسال نمی‌کند!
            این ناظر شبکه (Network Observer مانند Zeek، Wireshark، WAF یا فایروال) است که فیلدهای پیام اولیه 
            <strong style={{ color: "#38bdf8" }}> ClientHello </strong>
            را پیش از شروع رمزنگاری استخراج کرده و اثر انگشت را در حافظه خود محاسبه می‌نماید.
          </p>
        </div>
      </div>

      {/* Visual Sequence Handshake Diagram */}
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">
            <Radio size={20} color="#06b6d4" />
            <span>جریان ارتباط کلاینت، ناظر شبکه و سرور (TLS Handshake)</span>
          </div>
          <span className="badge badge-cyan">روی بسته‌ها کلیک کنید</span>
        </div>

        {/* Actors Row */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          gap: 16,
          marginBottom: 32,
          textAlign: "center"
        }}>
          {/* Client Actor */}
          <div style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-medium)",
            borderRadius: "var(--radius-md)",
            padding: "16px",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 8
          }}>
            <div style={{
              width: 52,
              height: 52,
              borderRadius: "50%",
              background: "rgba(59, 130, 246, 0.15)",
              color: "#60a5fa",
              display: "flex",
              alignItems: "center",
              justifyContent: "center"
            }}>
              <Laptop size={26} />
            </div>
            <strong style={{ fontSize: "1.05rem" }}>کلاینت (Client)</strong>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              مرورگر، ابزار curl، یا اسکریپت پایتون
            </span>
          </div>

          {/* Observer Actor */}
          <div style={{
            background: "rgba(6, 182, 212, 0.08)",
            border: "1px solid rgba(6, 182, 212, 0.3)",
            borderRadius: "var(--radius-md)",
            padding: "16px",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 8,
            boxShadow: "0 0 20px rgba(6, 182, 212, 0.15)"
          }}>
            <div style={{
              width: 52,
              height: 52,
              borderRadius: "50%",
              background: "rgba(6, 182, 212, 0.2)",
              color: "#38bdf8",
              display: "flex",
              alignItems: "center",
              justifyContent: "center"
            }}>
              <Eye size={26} />
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <strong style={{ fontSize: "1.05rem", color: "#38bdf8" }}>ناظر شبکه (Observer)</strong>
              <span className="badge badge-emerald">محل محاسبه JA3/4</span>
            </div>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              فایروال، WAF، سنسور Zeek یا Wireshark
            </span>
          </div>

          {/* Server Actor */}
          <div style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-medium)",
            borderRadius: "var(--radius-md)",
            padding: "16px",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 8
          }}>
            <div style={{
              width: 52,
              height: 52,
              borderRadius: "50%",
              background: "rgba(16, 185, 129, 0.15)",
              color: "#34d399",
              display: "flex",
              alignItems: "center",
              justifyContent: "center"
            }}>
              <Server size={26} />
            </div>
            <strong style={{ fontSize: "1.05rem" }}>سرور مقصد (Server)</strong>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              وب‌سرور امن HTTPS (Nginx / Cloudflare)
            </span>
          </div>
        </div>

        {/* Handshake Sequence Packets */}
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {/* Packet 1: TCP Handshake */}
          <div style={{
            padding: "12px 18px",
            background: "var(--bg-surface)",
            border: "1px solid var(--border-dim)",
            borderRadius: "var(--radius-md)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            opacity: 0.7
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <span className="badge">گام ۰</span>
              <span style={{ fontWeight: 600 }}>دست‌دهی اولیه TCP (TCP 3-Way Handshake: SYN, SYN-ACK, ACK)</span>
            </div>
            <span style={{ fontSize: "0.82rem", color: "var(--text-dim)" }}>ایجاد سوکت اتصال شبکه در لایه ۴</span>
          </div>

          {/* Packet 2: ClientHello (The Core!) */}
          <div
            onClick={() => setSelectedPacket("client_hello")}
            style={{
              padding: "16px 20px",
              background: selectedPacket === "client_hello"
                ? "linear-gradient(90deg, rgba(6, 182, 212, 0.18) 0%, rgba(59, 130, 246, 0.15) 100%)"
                : "rgba(6, 182, 212, 0.06)",
              border: selectedPacket === "client_hello"
                ? "2px solid #06b6d4"
                : "1px dashed rgba(6, 182, 212, 0.4)",
              borderRadius: "var(--radius-md)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              cursor: "pointer",
              boxShadow: selectedPacket === "client_hello" ? "0 0 20px rgba(6, 182, 212, 0.25)" : "none",
              transition: "all 0.2s ease"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
              <div style={{
                background: "#06b6d4",
                color: "#ffffff",
                padding: "6px 10px",
                borderRadius: "var(--radius-sm)",
                fontWeight: 700,
                fontSize: "0.85rem"
              }}>
                گام ۱: پیام کلیدی
              </div>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <strong style={{ fontSize: "1.05rem", color: "#38bdf8" }}>
                    ارسال بسته ClientHello (متن آشکار / Cleartext)
                  </strong>
                  <span className="badge badge-emerald">کلیک برای مشاهده جزئیات</span>
                </div>
                <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginTop: 2 }}>
                  کلاینت → ناظر شبکه (دیده‌بانی و محاسبه JA3/JA4) → سرور مقصد
                </div>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#38bdf8" }}>
              <Unlock size={18} />
              <span style={{ fontSize: "0.85rem", fontWeight: 600 }}>قابل شنود بدون کلید</span>
            </div>
          </div>

          {/* Packet 3: ServerHello */}
          <div
            onClick={() => setSelectedPacket("server_hello")}
            style={{
              padding: "14px 18px",
              background: selectedPacket === "server_hello" ? "rgba(59, 130, 246, 0.12)" : "var(--bg-surface)",
              border: selectedPacket === "server_hello" ? "1px solid #3b82f6" : "1px solid var(--border-dim)",
              borderRadius: "var(--radius-md)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              cursor: "pointer"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <span className="badge">گام ۲</span>
              <span style={{ fontWeight: 600 }}>پاسخ سرور: ServerHello + انتخاب سایفر + کلیدهای موقت (یا JA3S/JA4S)</span>
            </div>
            <span style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>پایان بخش آشکار و شروع تبادل کلید</span>
          </div>

          {/* Packet 4: Encrypted Traffic */}
          <div
            onClick={() => setSelectedPacket("encrypted")}
            style={{
              padding: "14px 18px",
              background: selectedPacket === "encrypted" ? "rgba(16, 185, 129, 0.12)" : "var(--bg-surface)",
              border: selectedPacket === "encrypted" ? "1px solid #10b981" : "1px solid var(--border-dim)",
              borderRadius: "var(--radius-md)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              cursor: "pointer"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <span className="badge badge-emerald">گام ۳</span>
              <span style={{ fontWeight: 600 }}>تبادل داده‌های کاربردی با رمزنگاری سرتاسری (Application Data)</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6, color: "#34d399", fontSize: "0.85rem" }}>
              <Lock size={16} />
              <span>کاملاً رمزنگاری شده (ناظر محتوا را نمی‌بیند)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Packet Inspector Panel */}
      {selectedPacket === "client_hello" && (
        <div className="panel" style={{ border: "1px solid rgba(6, 182, 212, 0.4)" }}>
          <div className="panel-header">
            <div className="panel-title">
              <Sparkles size={20} color="#06b6d4" />
              <span>کالبدشکافی ساختار بسته ClientHello (ورودی الگوریتم‌های JA3 و JA4)</span>
            </div>
            <span className="badge badge-cyan">داده‌های استخراج‌شده از بسته</span>
          </div>

          <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", marginBottom: 16 }}>
            ناظر شبکه با خواندن بایت‌های این پیام، مقادیر فیلدهای زیر را استخراج می‌کند. توجه کنید که مقادیر زیر به عنوان یک نمونه استاندارد از مرورگر کروم آورده شده‌اند:
          </p>

          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
            gap: 16
          }}>
            {/* Field: Legacy Version */}
            <div style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-dim)",
              borderRadius: "var(--radius-md)",
              padding: "14px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                <strong style={{ color: "#38bdf8" }}>نسخه پروتکل (ClientHello Version)</strong>
                <span className="mono badge badge-cyan">0x0303 (771)</span>
              </div>
              <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                در TLS 1.3 برای حفظ سازگاری با فایروال‌های قدیمی به صورت 0x0303 (TLS 1.2) پر می‌شود و نسخه اصلی در افزونه supported_versions قرار می‌گیرد.
              </p>
            </div>

            {/* Field: SNI */}
            <div style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-dim)",
              borderRadius: "var(--radius-md)",
              padding: "14px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                <strong style={{ color: "#38bdf8" }}>نام دامنه مقصد (Server Name Indication)</strong>
                <span className="mono badge badge-emerald">www.example.com</span>
              </div>
              <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                نشان می‌دهد کلاینت قصد بازکردن چه وب‌سایتی را دارد. در JA4 وجود دامنه با حرف 'd' و عدم وجود یا IP با حرف 'i' مشخص می‌شود.
              </p>
            </div>

            {/* Field: ALPN */}
            <div style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-dim)",
              borderRadius: "var(--radius-md)",
              padding: "14px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                <strong style={{ color: "#38bdf8" }}>مذاکره لایه کاربرد (ALPN)</strong>
                <span className="mono badge badge-purple">h2, http/1.1</span>
              </div>
              <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                اعلام پشتیبانی از HTTP/2 یا HTTP/1.1. در JA4 کاراکتر اول و آخر اولین انتخاب ('h2') ثبت می‌شود.
              </p>
            </div>

            {/* Field: Supported Groups */}
            <div style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-dim)",
              borderRadius: "var(--radius-md)",
              padding: "14px"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                <strong style={{ color: "#38bdf8" }}>منحنی‌های بیضوی (Supported Groups)</strong>
                <span className="mono badge badge-amber">x25519 (29), secp256r1 (23)</span>
              </div>
              <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                فهرست منحنی‌های مورد پذیرش کلاینت برای تبادل کلید امن بیضوی (ECDHE).
              </p>
            </div>
          </div>

          {/* Cipher Suites Breakdown */}
          <div style={{ marginTop: 20 }}>
            <h3 style={{ fontSize: "0.95rem", fontWeight: 700, marginBottom: 10, color: "#ffffff" }}>
              فهرست سایفرهای اعلامی کلاینت (Cipher Suites)
            </h3>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {[0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9].map((cid) => (
                <div key={cid} style={{
                  background: "var(--bg-surface)",
                  border: "1px solid var(--border-medium)",
                  borderRadius: "var(--radius-sm)",
                  padding: "6px 12px",
                  fontSize: "0.82rem",
                  display: "flex",
                  alignItems: "center",
                  gap: 8
                }}>
                  <span className="mono" style={{ color: "#38bdf8" }}>0x{cid.toString(16)}</span>
                  <span>{getCipherName(cid)}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Extensions List */}
          <div style={{ marginTop: 20 }}>
            <h3 style={{ fontSize: "0.95rem", fontWeight: 700, marginBottom: 10, color: "#ffffff" }}>
              افزونه‌های همراه بسته (TLS Extensions)
            </h3>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {[0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0017, 0x0023, 0x002b, 0x0033].map((extId) => (
                <div key={extId} style={{
                  background: "var(--bg-surface)",
                  border: "1px solid var(--border-medium)",
                  borderRadius: "var(--radius-sm)",
                  padding: "6px 12px",
                  fontSize: "0.82rem",
                  display: "flex",
                  alignItems: "center",
                  gap: 8
                }}>
                  <span className="mono" style={{ color: "#a855f7" }}>0x{extId.toString(16).padStart(4, "0")}</span>
                  <span>{getExtensionName(extId)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {selectedPacket === "server_hello" && (
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <Server size={20} color="#3b82f6" />
              <span>پاسخ سرور و اثر انگشت طرف سرور (JA3S و JA4S)</span>
            </div>
          </div>
          <p style={{ fontSize: "0.9rem", color: "var(--text-muted)" }}>
            سرور از بین سایفرها و افزونه‌های پیشنهادی کلاینت، دقیقاً یک سایفر و مجموعه‌ای از افزونه‌های مورد توافق را برمی‌گرداند.
            از روی پاسخ سرور نیز می‌توان اثر انگشت سرور (JA3S یا JA4S) ساخت، اما در مبحث تشخیص کلاینت، تمرکز روی ClientHello است.
          </p>
        </div>
      )}

      {selectedPacket === "encrypted" && (
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <Lock size={20} color="#10b981" />
              <span>داده‌های رمزنگاری‌شده (پس از اتمام هندشیک)</span>
            </div>
          </div>
          <p style={{ fontSize: "0.9rem", color: "var(--text-muted)" }}>
            در این مرحله، تمام URLها، هدرهای HTTP، کوکی‌ها و محتوای صفحات وب با کلید متقارن سشن رمزنگاری شده و ناظر شبکه قادر به خواندن محتوای درونی بدون کلید خصوصی نخواهد بود.
            دقیقاً به همین دلیل است که اثر انگشت TLS مبتنی بر بسته اولیه ClientHello تا این حد در مانیتورینگ امنیتی شبکه و پایش بدافزارها ارزش دارد!
          </p>
        </div>
      )}
    </div>
  );
};
