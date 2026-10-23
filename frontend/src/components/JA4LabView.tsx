import React, { useState, useMemo } from "react";
import {
  Activity,
  CheckCircle2,
  Copy,
  Check,
  RefreshCw,
  Shuffle,
  Info,
  Shield,
  Layers,
  ArrowRight,
  ExternalLink,
  Code2
} from "lucide-react";
import { computeJA4, type JA4Input, type JA4Result } from "../utils/ja4";
import { isGrease } from "../utils/ja3";
import { getCipherName, getExtensionName } from "../data/protocolKnowledge";

export const JA4LabView: React.FC = () => {
  // Baseline modern browser configuration
  const [protocol, setProtocol] = useState<"t" | "q" | "d">("t");
  const [version, setVersion] = useState<number>(0x0303);
  const [supportedVersions, setSupportedVersions] = useState<number[]>([0x0304, 0x0303]); // TLS 1.3
  const [hasSni, setHasSni] = useState<boolean>(true);
  const [sniIsIp, setSniIsIp] = useState<boolean>(false);
  const [alpnOption, setAlpnOption] = useState<string>("h2");

  const [ciphers, setCiphers] = useState<number[]>([
    0x2a2a, // GREASE
    0x1301, 0x1302, 0x1303,
    0xc02b, 0xc02f, 0xc02c, 0xc030,
    0xcca9, 0xcca8, 0xc013, 0xc014,
    0x009c, 0x009d, 0x002f, 0x0035
  ]);

  const [extensions, setExtensions] = useState<number[]>([
    0x3a3a, // GREASE
    0x0000, // SNI
    0x0017, // EMS
    0x000a, // supported_groups
    0x000b, // ec_point_formats
    0x0023, // session_ticket
    0x0010, // ALPN
    0x0005, // status_request
    0x000d, // signature_algorithms
    0x0012, // SCT
    0x0033, // key_share
    0x002d, // psk_modes
    0x002b, // supported_versions
    0x001b  // compress_certificate
  ]);

  const [sigAlgs, setSigAlgs] = useState<number[]>([
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
  ]);

  const [selectedSegment, setSelectedSegment] = useState<"a" | "b" | "c">("a");
  const [copied, setCopied] = useState<boolean>(false);

  // Derive ALPN list from state
  const alpnProtocols = useMemo(() => {
    if (alpnOption === "h2") return ["h2", "http/1.1"];
    if (alpnOption === "h1") return ["http/1.1"];
    if (alpnOption === "mqtt") return ["mqtt"];
    return [];
  }, [alpnOption]);

  // Compute JA4 live
  const ja4Result: JA4Result = useMemo(() => {
    return computeJA4({
      protocol,
      version,
      hasSni,
      sniIsIp,
      ciphers,
      extensions,
      alpnProtocols,
      signatureAlgorithms: sigAlgs,
      supportedVersions,
    });
  }, [protocol, version, hasSni, sniIsIp, ciphers, extensions, alpnProtocols, sigAlgs, supportedVersions]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const shuffleExtensions = () => {
    const shuffled = [...extensions].sort(() => Math.random() - 0.5);
    setExtensions(shuffled);
  };

  const activeExp = ja4Result.explanations[selectedSegment];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Overview Banner */}
      <div className="panel" style={{ border: "1px solid rgba(16, 185, 129, 0.3)" }}>
        <div className="panel-header">
          <div className="panel-title">
            <Activity size={22} color="#10b981" />
            <span>آزمایشگاه نسل جدید اثر انگشت TLS — استاندارد FoxIO JA4</span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={shuffleExtensions} className="btn btn-secondary btn-sm" title="تغییر ترتیب افزونه‌ها برای بررسی پایداری JA4">
              <Shuffle size={14} color="#10b981" />
              <span>آزمایش تغییر ترتیب افزونه‌ها</span>
            </button>
            <a
              href="https://github.com/FoxIO-LLC/ja4"
              target="_blank"
              rel="noreferrer"
              className="btn btn-outline btn-sm"
              title="مشاهده مخزن رسمی FoxIO در گیت‌هاب"
            >
              <ExternalLink size={14} />
              <span>مستندات رسمی FoxIO</span>
            </a>
          </div>
        </div>

        {/* 3 Dissected Interactive Segments of JA4 */}
        <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", marginBottom: 14 }}>
          اثر انگشت JA4 به سه بخش تفکیک‌شده مجزا تقسیم می‌شود که خوانایی و مقاومت در برابر تغییرات تصادفی را به همراه دارد. روی هر بخش کلیک کنید:
        </p>

        <div style={{
          display: "grid",
          gridTemplateColumns: "1.2fr 1fr 1fr",
          gap: 16,
          marginBottom: 20
        }}>
          {/* Segment A */}
          <div
            onClick={() => setSelectedSegment("a")}
            style={{
              background: selectedSegment === "a" ? "rgba(6, 182, 212, 0.18)" : "var(--bg-surface)",
              border: selectedSegment === "a" ? "2px solid #06b6d4" : "1px solid var(--border-medium)",
              borderRadius: "var(--radius-md)",
              padding: "16px",
              cursor: "pointer",
              transition: "all 0.18s ease"
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span className="badge badge-cyan">بخش اول (JA4_a)</span>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>۱۰ کاراکتر قابل خواندن</span>
            </div>
            <div className="mono" style={{ fontSize: "1.35rem", fontWeight: 800, color: "#38bdf8" }}>
              {ja4Result.ja4_a}
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: 6 }}>
              پروتکل، نسخه، SNI، تعداد و ALPN
            </div>
          </div>

          {/* Segment B */}
          <div
            onClick={() => setSelectedSegment("b")}
            style={{
              background: selectedSegment === "b" ? "rgba(59, 130, 246, 0.18)" : "var(--bg-surface)",
              border: selectedSegment === "b" ? "2px solid #3b82f6" : "1px solid var(--border-medium)",
              borderRadius: "var(--radius-md)",
              padding: "16px",
              cursor: "pointer",
              transition: "all 0.18s ease"
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span className="badge badge-blue">بخش دوم (JA4_b)</span>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>۱۲ کاراکتر هش</span>
            </div>
            <div className="mono" style={{ fontSize: "1.35rem", fontWeight: 800, color: "#60a5fa" }}>
              {ja4Result.ja4_b}
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: 6 }}>
              هش SHA256 سایفرهای مرتب‌شده
            </div>
          </div>

          {/* Segment C */}
          <div
            onClick={() => setSelectedSegment("c")}
            style={{
              background: selectedSegment === "c" ? "rgba(168, 85, 247, 0.18)" : "var(--bg-surface)",
              border: selectedSegment === "c" ? "2px solid #a855f7" : "1px solid var(--border-medium)",
              borderRadius: "var(--radius-md)",
              padding: "16px",
              cursor: "pointer",
              transition: "all 0.18s ease"
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span className="badge badge-purple">بخش سوم (JA4_c)</span>
              <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>۱۲ کاراکتر هش</span>
            </div>
            <div className="mono" style={{ fontSize: "1.35rem", fontWeight: 800, color: "#c084fc" }}>
              {ja4Result.ja4_c}
            </div>
            <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: 6 }}>
              هش افزونه‌های مرتب + امضاها
            </div>
          </div>
        </div>

        {/* Assembled Full JA4 String */}
        <div className="hash-pill" style={{ background: "#080d1a", borderColor: "rgba(16, 185, 129, 0.4)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>اثر انگشت کامل JA4:</span>
            <span style={{ fontSize: "1.2rem", fontWeight: 800, color: "#34d399", letterSpacing: "0.02em" }}>
              {ja4Result.full}
            </span>
          </div>
          <button
            onClick={() => copyToClipboard(ja4Result.full)}
            className="btn btn-outline btn-sm"
          >
            {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
            <span>{copied ? "کپی شد" : "کپی"}</span>
          </button>
        </div>
      </div>

      {/* Deep-Dive Segment Details Card */}
      <div className="panel" style={{ border: "1px solid var(--border-medium)" }}>
        <div className="panel-header">
          <div className="panel-title">
            <Code2 size={20} color="#06b6d4" />
            <span>کالبدشکافی دقیق {activeExp.title}</span>
          </div>
          <span className="mono badge badge-cyan">{activeExp.value}</span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {/* Formula */}
          <div style={{
            background: "var(--bg-surface)",
            padding: "12px 16px",
            borderRadius: "var(--radius-md)",
            border: "1px solid var(--border-dim)"
          }}>
            <span style={{ fontSize: "0.82rem", color: "var(--text-dim)", display: "block", marginBottom: 4 }}>
              قاعده و نحوه تولید این بخش:
            </span>
            <span style={{ fontWeight: 600, color: "#38bdf8", fontSize: "0.95rem" }}>
              {activeExp.formula}
            </span>
          </div>

          {/* Description */}
          <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", lineHeight: 1.7 }}>
            {activeExp.description}
          </p>

          {/* Detail Points */}
          <ul style={{ paddingRight: 20, display: "flex", flexDirection: "column", gap: 6, fontSize: "0.85rem", color: "var(--text-main)" }}>
            {activeExp.details.map((d, i) => (
              <li key={i}>{d}</li>
            ))}
          </ul>

          {/* Raw string preview for B and C */}
          {selectedSegment === "b" && (
            <div style={{ marginTop: 8 }}>
              <span style={{ fontSize: "0.8rem", color: "var(--text-dim)", display: "block", marginBottom: 4 }}>
                رشته خام هگزادسیمال سایفرها قبل از هش‌شدن (مرتب صعودی):
              </span>
              <div className="mono" style={{
                background: "#080d1a",
                padding: "8px 12px",
                borderRadius: "var(--radius-sm)",
                fontSize: "0.82rem",
                wordBreak: "break-all",
                color: "#60a5fa"
              }}>
                {ja4Result.raw_b}
              </div>
            </div>
          )}

          {selectedSegment === "c" && (
            <div style={{ marginTop: 8 }}>
              <span style={{ fontSize: "0.8rem", color: "var(--text-dim)", display: "block", marginBottom: 4 }}>
                رشته خام هگزادسیمال افزونه‌ها و امضاها قبل از هش‌شدن:
              </span>
              <div className="mono" style={{
                background: "#080d1a",
                padding: "8px 12px",
                borderRadius: "var(--radius-sm)",
                fontSize: "0.82rem",
                wordBreak: "break-all",
                color: "#c084fc"
              }}>
                {ja4Result.raw_c}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Interactive Parameter Controls */}
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">
            <Layers size={20} color="#a855f7" />
            <span>تنظیمات و متغیرهای پیام ClientHello برای آزمایش اثر انگشت JA4</span>
          </div>
          <span className="badge badge-purple">تغییرات زنده اعمال می‌شود</span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 16 }}>
          {/* Protocol Switcher */}
          <div>
            <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: 6 }}>
              پروتکل انتقال (Protocol):
            </label>
            <div style={{ display: "flex", gap: 8 }}>
              {(["t", "q", "d"] as const).map((p) => (
                <button
                  key={p}
                  onClick={() => setProtocol(p)}
                  className={`btn btn-sm ${protocol === p ? "btn-primary" : "btn-secondary"}`}
                  style={{ flex: 1 }}
                >
                  {p === "t" ? "TCP (t)" : p === "q" ? "QUIC (q)" : "DTLS (d)"}
                </button>
              ))}
            </div>
          </div>

          {/* SNI State */}
          <div>
            <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: 6 }}>
              وضعیت نام دامنه سرور (SNI):
            </label>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                onClick={() => { setHasSni(true); setSniIsIp(false); }}
                className={`btn btn-sm ${hasSni && !sniIsIp ? "btn-primary" : "btn-secondary"}`}
                style={{ flex: 1 }}
              >
                دامنه وب‌سایت (d)
              </button>
              <button
                onClick={() => { setHasSni(false); setSniIsIp(true); }}
                className={`btn btn-sm ${!hasSni || sniIsIp ? "btn-primary" : "btn-secondary"}`}
                style={{ flex: 1 }}
              >
                آدرس IP مستقیم (i)
              </button>
            </div>
          </div>

          {/* ALPN Protocol */}
          <div>
            <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: 6 }}>
              پروتکل لایه کاربرد (ALPN):
            </label>
            <div style={{ display: "flex", gap: 8 }}>
              {[
                { id: "h2", label: "HTTP/2 (h2)" },
                { id: "h1", label: "HTTP/1.1 (h1)" },
                { id: "mqtt", label: "MQTT (mt)" },
                { id: "none", label: "فاقد ALPN (00)" }
              ].map((a) => (
                <button
                  key={a.id}
                  onClick={() => setAlpnOption(a.id)}
                  className={`btn btn-sm ${alpnOption === a.id ? "btn-primary" : "btn-secondary"}`}
                >
                  {a.label}
                </button>
              ))}
            </div>
          </div>

          {/* TLS Version */}
          <div>
            <label style={{ display: "block", fontSize: "0.85rem", fontWeight: 600, marginBottom: 6 }}>
              نسخه اعلامی TLS:
            </label>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                onClick={() => setSupportedVersions([0x0304, 0x0303])}
                className={`btn btn-sm ${supportedVersions.includes(0x0304) ? "btn-primary" : "btn-secondary"}`}
                style={{ flex: 1 }}
              >
                TLS 1.3 (کد 13)
              </button>
              <button
                onClick={() => setSupportedVersions([0x0303])}
                className={`btn btn-sm ${!supportedVersions.includes(0x0304) ? "btn-primary" : "btn-secondary"}`}
                style={{ flex: 1 }}
              >
                TLS 1.2 (کد 12)
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
