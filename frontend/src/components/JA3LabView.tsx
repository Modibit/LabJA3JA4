import React, { useState, useMemo } from "react";
import {
  Cpu,
  RefreshCw,
  Shuffle,
  ShieldCheck,
  Copy,
  Check,
  Plus,
  Trash2,
  Sparkles,
  AlertCircle,
  HelpCircle,
  Filter
} from "lucide-react";
import { computeJA3, isGrease } from "../utils/ja3";
import { getCipherName, getExtensionName } from "../data/protocolKnowledge";

export const JA3LabView: React.FC = () => {
  // Baseline initial state (Chrome standard sample)
  const defaultVersion = 771; // 0x0303 (TLS 1.2)
  const defaultCiphers = [49195, 49199, 49196, 49200, 52393, 52392, 49161, 49162, 156, 157, 47, 53];
  const defaultExtensions = [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27];
  const defaultCurves = [29, 23, 24];
  const defaultPointFormats = [0];

  const [version, setVersion] = useState<number>(defaultVersion);
  const [ciphers, setCiphers] = useState<number[]>(defaultCiphers);
  const [extensions, setExtensions] = useState<number[]>(defaultExtensions);
  const [curves, setCurves] = useState<number[]>(defaultCurves);
  const [pointFormats, setPointFormats] = useState<number[]>(defaultPointFormats);

  const [copied, setCopied] = useState<boolean>(false);
  const [previousHash, setPreviousHash] = useState<string | null>(null);
  const [isOfficialVectorActive, setIsOfficialVectorActive] = useState<boolean>(false);

  // Live computation
  const currentJA3 = useMemo(() => {
    return computeJA3(version, ciphers, extensions, curves, pointFormats);
  }, [version, ciphers, extensions, curves, pointFormats]);

  const hashChanged = previousHash !== null && previousHash !== currentJA3.hash;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // 1. Load Official Salesforce JA3 Test Vector
  const loadOfficialVector = () => {
    setPreviousHash(currentJA3.hash);
    setVersion(769); // TLS 1.0
    setCiphers([47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4]);
    setExtensions([0, 10, 11]);
    setCurves([23, 24, 25]);
    setPointFormats([0]);
    setIsOfficialVectorActive(true);
  };

  // 2. Inject GREASE values (RFC 8701)
  const injectGrease = () => {
    setPreviousHash(currentJA3.hash);
    setIsOfficialVectorActive(false);
    // Inject GREASE in ciphers and extensions
    const greaseCipher = 0x2a2a; // 10794
    const greaseExt = 0x3a3a;    // 14906
    const greaseCurve = 0x4a4a;  // 19018

    if (!ciphers.includes(greaseCipher)) {
      setCiphers([greaseCipher, ...ciphers]);
    }
    if (!extensions.includes(greaseExt)) {
      setExtensions([greaseExt, ...extensions]);
    }
    if (!curves.includes(greaseCurve)) {
      setCurves([greaseCurve, ...curves]);
    }
  };

  // 3. Shuffle Extensions (Change Order)
  const shuffleExtensions = () => {
    setPreviousHash(currentJA3.hash);
    setIsOfficialVectorActive(false);
    const shuffled = [...extensions].sort(() => Math.random() - 0.5);
    setExtensions(shuffled);
  };

  // 4. Reset to baseline
  const resetToDefault = () => {
    setPreviousHash(null);
    setVersion(defaultVersion);
    setCiphers(defaultCiphers);
    setExtensions(defaultExtensions);
    setCurves(defaultCurves);
    setPointFormats(defaultPointFormats);
    setIsOfficialVectorActive(false);
  };

  // Remove single item
  const removeCipher = (index: number) => {
    setPreviousHash(currentJA3.hash);
    setIsOfficialVectorActive(false);
    setCiphers(ciphers.filter((_, i) => i !== index));
  };

  const removeExtension = (index: number) => {
    setPreviousHash(currentJA3.hash);
    setIsOfficialVectorActive(false);
    setExtensions(extensions.filter((_, i) => i !== index));
  };

  // Add sample cipher
  const addSampleCipher = () => {
    setPreviousHash(currentJA3.hash);
    setIsOfficialVectorActive(false);
    const candidate = 0x1303; // 4867 (TLS_CHACHA20_POLY1305_SHA256)
    if (!ciphers.includes(candidate)) {
      setCiphers([...ciphers, candidate]);
    }
  };

  // Add sample extension
  const addSampleExtension = () => {
    setPreviousHash(currentJA3.hash);
    setIsOfficialVectorActive(false);
    const candidate = 0x44cd; // 17613 (encrypted_client_hello)
    if (!extensions.includes(candidate)) {
      setExtensions([...extensions, candidate]);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Header Panel */}
      <div className="panel" style={{ border: "1px solid rgba(6, 182, 212, 0.3)" }}>
        <div className="panel-header">
          <div className="panel-title">
            <Cpu size={22} color="#06b6d4" />
            <span>آزمایشگاه اثر انگشت JA3 (استاندارد رسمی Salesforce)</span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button id="btn-load-official-ja3" onClick={loadOfficialVector} className="btn btn-secondary btn-sm" title="بارگذاری بردار آزمون رسمی گیت‌هاب Salesforce">
              <ShieldCheck size={15} color="#10b981" />
              <span>تست بردار رسمی Salesforce</span>
            </button>
            <button id="btn-inject-grease" onClick={injectGrease} className="btn btn-secondary btn-sm" title="تزریق مقادیر GREASE و مشاهده فیلترشدن آنها طبق RFC 8701">
              <Filter size={15} color="#f59e0b" />
              <span>تزریق GREASE</span>
            </button>
            <button id="btn-shuffle-ja3" onClick={shuffleExtensions} className="btn btn-secondary btn-sm" title="تغییر تصادفی ترتیب افزونه‌ها">
              <Shuffle size={15} color="#a855f7" />
              <span>تغییر ترتیب افزونه‌ها</span>
            </button>
            <button id="btn-reset-ja3" onClick={resetToDefault} className="btn btn-outline btn-sm" title="بازنشانی به مقادیر پیش‌فرض">
              <RefreshCw size={15} />
              <span>بازنشانی</span>
            </button>
          </div>
        </div>

        {/* Verification Alert when official vector active */}
        {isOfficialVectorActive && (
          <div style={{
            background: "rgba(16, 185, 129, 0.12)",
            border: "1px solid rgba(16, 185, 129, 0.3)",
            borderRadius: "var(--radius-md)",
            padding: "12px 16px",
            marginBottom: 16,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between"
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <ShieldCheck size={20} color="#10b981" />
              <div>
                <strong style={{ color: "#34d399", fontSize: "0.92rem" }}>
                  اعتبارسنجی با بردار رسمی Salesforce JA3 با موفقیت انجام شد!
                </strong>
                <p style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginTop: 2 }}>
                  رشته خام: <span className="mono">769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0</span>
                </p>
              </div>
            </div>
            <span className="badge badge-emerald">هش MD5 منطبق: ada70206e40642a3e4461f35503241d5</span>
          </div>
        )}

        {/* Output Hash Card */}
        <div style={{
          background: "var(--bg-surface)",
          border: "1px solid var(--border-medium)",
          borderRadius: "var(--radius-md)",
          padding: "18px 20px",
          display: "flex",
          flexDirection: "column",
          gap: 12
        }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
            <span style={{ fontSize: "0.9rem", fontWeight: 700, color: "var(--text-muted)" }}>
              اثر انگشت نهایی JA3 (هش MD5)
            </span>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {previousHash && (
                <span className={`badge ${hashChanged ? "badge-rose" : "badge-emerald"}`}>
                  {hashChanged ? "هش تغییر کرد ⚠️" : "بدون تغییر در هش"}
                </span>
              )}
              {currentJA3.greaseFilteredCiphers.length > 0 && (
                <span className="badge badge-amber">
                  فیلترشدن {currentJA3.greaseFilteredCiphers.length} مقدار GREASE
                </span>
              )}
            </div>
          </div>

          <div className={`hash-pill ${hashChanged ? "changed" : ""}`}>
            <span style={{ fontWeight: 700, fontSize: "1.15rem", letterSpacing: "0.05em" }}>
              {currentJA3.hash}
            </span>
            <button
              onClick={() => copyToClipboard(currentJA3.hash)}
              className="btn btn-outline btn-sm"
              style={{ padding: "4px 8px" }}
              title="کپی هش MD5"
            >
              {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
              <span>{copied ? "کپی شد" : "کپی"}</span>
            </button>
          </div>

          {previousHash && hashChanged && (
            <div style={{ fontSize: "0.82rem", color: "var(--text-dim)", display: "flex", gap: 8 }}>
              <span>هش قبلی:</span>
              <span className="mono" style={{ textDecoration: "line-through", color: "#fb7185" }}>{previousHash}</span>
            </div>
          )}
        </div>

        {/* 5-Segment Color Coded Formula Breakdown */}
        <div style={{ marginTop: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
            <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text-muted)" }}>
              رشته خام JA3 (قبل از اعمال تابع هش MD5) — تفکیک ۵ بخشی:
            </span>
            <span style={{ fontSize: "0.78rem", color: "var(--text-dim)" }}>
              فرمول: SSLVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
            </span>
          </div>

          <div style={{
            background: "#080d1a",
            border: "1px solid var(--border-medium)",
            borderRadius: "var(--radius-md)",
            padding: "14px 16px",
            fontFamily: "var(--font-mono)",
            fontSize: "0.88rem",
            direction: "ltr",
            textAlign: "left",
            wordBreak: "break-all",
            lineHeight: 1.8
          }}>
            {/* Segment 1: Version */}
            <span style={{ color: "#34d399", fontWeight: 700 }} title="بخش اول: SSLVersion">
              {currentJA3.parts.versionStr}
            </span>
            <span style={{ color: "#ffffff", fontWeight: 900 }}>,</span>

            {/* Segment 2: Ciphers */}
            <span style={{ color: "#38bdf8" }} title="بخش دوم: CipherSuites (جدا شده با خط تیره)">
              {currentJA3.parts.ciphersStr || "(empty)"}
            </span>
            <span style={{ color: "#ffffff", fontWeight: 900 }}>,</span>

            {/* Segment 3: Extensions */}
            <span style={{ color: "#a855f7" }} title="بخش سوم: Extensions (جدا شده با خط تیره، وابسته به ترتیب!)">
              {currentJA3.parts.extensionsStr || "(empty)"}
            </span>
            <span style={{ color: "#ffffff", fontWeight: 900 }}>,</span>

            {/* Segment 4: Curves */}
            <span style={{ color: "#fbbf24" }} title="بخش چهارم: EllipticCurves">
              {currentJA3.parts.curvesStr || "(empty)"}
            </span>
            <span style={{ color: "#ffffff", fontWeight: 900 }}>,</span>

            {/* Segment 5: Formats */}
            <span style={{ color: "#f43f5e" }} title="بخش پنجم: ECPointFormats">
              {currentJA3.parts.pointFormatsStr || "(empty)"}
            </span>
          </div>

          {/* Color Legend */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: 14, marginTop: 10, fontSize: "0.78rem" }}>
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: "#34d399" }} />
              نسخه SSLVersion ({version})
            </span>
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: "#38bdf8" }} />
              سایفرها ({currentJA3.ciphers.length} عدد)
            </span>
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: "#a855f7" }} />
              افزونه‌ها ({currentJA3.extensions.length} عدد)
            </span>
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: "#fbbf24" }} />
              منحنی‌ها ({currentJA3.curves.length} عدد)
            </span>
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: "#f43f5e" }} />
              قالب نقاط ({currentJA3.pointFormats.length} عدد)
            </span>
          </div>
        </div>
      </div>

      {/* Interactive Controls & Tags */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {/* Ciphers Editor */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <span>سایفرهای کلاینت (Cipher Suites)</span>
              <span className="badge badge-cyan">{ciphers.length} مورد</span>
            </div>
            <button onClick={addSampleCipher} className="btn btn-secondary btn-sm">
              <Plus size={14} />
              <span>افزودن ChaCha20</span>
            </button>
          </div>

          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, maxHeight: 220, overflowY: "auto", padding: 4 }}>
            {ciphers.map((c, idx) => {
              const grease = isGrease(c);
              return (
                <div
                  key={`${c}-${idx}`}
                  style={{
                    background: grease ? "rgba(245, 158, 11, 0.15)" : "var(--bg-surface)",
                    border: grease ? "1px dashed #f59e0b" : "1px solid var(--border-medium)",
                    borderRadius: "var(--radius-sm)",
                    padding: "4px 8px",
                    fontSize: "0.8rem",
                    display: "flex",
                    alignItems: "center",
                    gap: 6
                  }}
                >
                  <span className="mono" style={{ color: grease ? "#fbbf24" : "#38bdf8", fontWeight: 600 }}>
                    {c} (0x{c.toString(16)})
                  </span>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    {grease ? "[GREASE]" : getCipherName(c).replace("TLS_", "").substring(0, 16)}
                  </span>
                  <button
                    onClick={() => removeCipher(idx)}
                    style={{ background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer" }}
                    title="حذف این سایفر"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        {/* Extensions Editor */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <span>افزونه‌ها (TLS Extensions)</span>
              <span className="badge badge-purple">{extensions.length} مورد</span>
            </div>
            <div style={{ display: "flex", gap: 6 }}>
              <button onClick={shuffleExtensions} className="btn btn-secondary btn-sm" title="تغییر ترتیب افزونه‌ها">
                <Shuffle size={14} />
                <span>بر زدن</span>
              </button>
              <button onClick={addSampleExtension} className="btn btn-secondary btn-sm">
                <Plus size={14} />
                <span>افزودن ECH</span>
              </button>
            </div>
          </div>

          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, maxHeight: 220, overflowY: "auto", padding: 4 }}>
            {extensions.map((ext, idx) => {
              const grease = isGrease(ext);
              return (
                <div
                  key={`${ext}-${idx}`}
                  style={{
                    background: grease ? "rgba(245, 158, 11, 0.15)" : "var(--bg-surface)",
                    border: grease ? "1px dashed #f59e0b" : "1px solid var(--border-medium)",
                    borderRadius: "var(--radius-sm)",
                    padding: "4px 8px",
                    fontSize: "0.8rem",
                    display: "flex",
                    alignItems: "center",
                    gap: 6
                  }}
                >
                  <span className="mono" style={{ color: grease ? "#fbbf24" : "#a855f7", fontWeight: 600 }}>
                    {ext} (0x{ext.toString(16).padStart(4, "0")})
                  </span>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    {grease ? "[GREASE]" : getExtensionName(ext).split(" ")[0]}
                  </span>
                  <button
                    onClick={() => removeExtension(idx)}
                    style={{ background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer" }}
                    title="حذف این افزونه"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
