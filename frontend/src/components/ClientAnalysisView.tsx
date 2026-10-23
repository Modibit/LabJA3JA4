import React, { useState, useMemo } from "react";
import {
  GitCompare,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Laptop,
  Terminal,
  Bot,
  FileCode,
  Search,
  Eye
} from "lucide-react";
import { CLIENT_PROFILES, type ClientProfile } from "../data/sampleProfiles";
import { computeJA3 } from "../utils/ja3";
import { computeJA4 } from "../utils/ja4";

export const ClientAnalysisView: React.FC = () => {
  // Select profiles to compare (default Chrome and Python Requests)
  const [selectedIds, setSelectedIds] = useState<string[]>(["chrome_desktop", "python_urllib"]);
  const [activeAnalystProfileId, setActiveAnalystProfileId] = useState<string>("python_urllib");

  const toggleSelectProfile = (id: string) => {
    if (selectedIds.includes(id)) {
      if (selectedIds.length > 1) {
        setSelectedIds(selectedIds.filter((item) => item !== id));
      }
    } else {
      setSelectedIds([...selectedIds, id]);
    }
  };

  // Compute fingerprints for each profile
  const profilesWithFingerprints = useMemo(() => {
    return CLIENT_PROFILES.map((p) => {
      const ja3 = computeJA3(p.version, p.ciphers, p.extensions, p.curves, p.pointFormats);
      const isSniIp = !p.sni || /^\d+\.\d+\.\d+\.\d+$/.test(p.sni);
      const ja4 = computeJA4({
        protocol: "t",
        version: p.version,
        hasSni: Boolean(p.sni),
        sniIsIp: isSniIp,
        ciphers: p.ciphers,
        extensions: p.extensions,
        alpnProtocols: p.alpn,
        signatureAlgorithms: p.sigAlgs,
        supportedVersions: p.supportedVersions
      });

      return {
        profile: p,
        ja3,
        ja4
      };
    });
  }, []);

  const activeAnalystProfile = useMemo(() => {
    return profilesWithFingerprints.find((item) => item.profile.id === activeAnalystProfileId) || profilesWithFingerprints[0];
  }, [profilesWithFingerprints, activeAnalystProfileId]);

  const selectedData = useMemo(() => {
    return profilesWithFingerprints.filter((item) => selectedIds.includes(item.profile.id));
  }, [profilesWithFingerprints, selectedIds]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Educational Notice Banner */}
      <div style={{
        background: "rgba(245, 158, 11, 0.08)",
        border: "1px solid rgba(245, 158, 11, 0.3)",
        borderRadius: "var(--radius-lg)",
        padding: "16px 20px",
        display: "flex",
        alignItems: "center",
        gap: 14
      }}>
        <AlertTriangle size={24} color="#f59e0b" style={{ flexShrink: 0 }} />
        <div style={{ fontSize: "0.88rem", color: "var(--text-muted)", lineHeight: 1.6 }}>
          <strong style={{ color: "#fbbf24" }}>تذکر آموزشی و امنیتی بسیار مهم:</strong>
          {" "}تمامی پروفایل‌های زیر داده‌های آموزشی شبیه‌سازی‌شده بر اساس الگوهای واقعی پشته‌های شبکه هستند.
          در علم امنیت سایبری، <strong style={{ color: "#ffffff" }}>اثر انگشت TLS تنها یک شاخص مشکوک (Indicator of Compromise) است؛ نه اثبات قطعی بدافزار یا هویت تک‌تک کاربران!</strong>
        </div>
      </div>

      {/* Profiles Selection Grid */}
      <div className="panel">
        <div className="panel-header">
          <div className="panel-title">
            <GitCompare size={20} color="#06b6d4" />
            <span>انتخاب کلاینت‌ها برای مقایسه اثر انگشت</span>
          </div>
          <span className="badge badge-cyan">{selectedIds.length} کلاینت در حال مقایسه</span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14 }}>
          {CLIENT_PROFILES.map((p) => {
            const isSelected = selectedIds.includes(p.id);
            return (
              <div
                key={p.id}
                onClick={() => toggleSelectProfile(p.id)}
                style={{
                  background: isSelected ? "rgba(6, 182, 212, 0.12)" : "var(--bg-surface)",
                  border: isSelected ? "2px solid #06b6d4" : "1px solid var(--border-medium)",
                  borderRadius: "var(--radius-md)",
                  padding: "14px",
                  cursor: "pointer",
                  transition: "all 0.18s ease",
                  display: "flex",
                  flexDirection: "column",
                  gap: 8
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span className="badge" style={{ backgroundColor: `${p.badgeColor}22`, color: p.badgeColor, borderColor: `${p.badgeColor}55` }}>
                    {p.badge}
                  </span>
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => {}} // handled by div click
                    style={{ cursor: "pointer" }}
                  />
                </div>
                <strong style={{ fontSize: "0.95rem", color: isSelected ? "#38bdf8" : "#ffffff" }}>
                  {p.name}
                </strong>
                <span style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
                  {p.description.substring(0, 75)}...
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Side-by-Side Comparison Table */}
      <div className="panel" style={{ overflowX: "auto" }}>
        <div className="panel-header">
          <div className="panel-title">
            <Search size={20} color="#a855f7" />
            <span>جدول مقایسه تطبیقی فیلد به فیلد (Comparison Matrix)</span>
          </div>
        </div>

        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem", textAlign: "right" }}>
          <thead>
            <tr style={{ borderBottom: "2px solid var(--border-medium)", background: "var(--bg-surface)" }}>
              <th style={{ padding: "12px 14px", color: "var(--text-muted)" }}>ویژگی کلاینت</th>
              {selectedData.map(({ profile }) => (
                <th key={profile.id} style={{ padding: "12px 14px", color: "#ffffff", fontWeight: 700 }}>
                  {profile.name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {/* TLS Version */}
            <tr style={{ borderBottom: "1px solid var(--border-dim)" }}>
              <td style={{ padding: "10px 14px", color: "var(--text-muted)", fontWeight: 600 }}>نسخه TLS</td>
              {selectedData.map(({ profile, ja4 }) => (
                <td key={profile.id} style={{ padding: "10px 14px" }}>
                  <span className="badge badge-cyan">
                    {ja4.effectiveVersion === 0x0304 ? "TLS 1.3" : "TLS 1.2"}
                  </span>
                </td>
              ))}
            </tr>

            {/* SNI */}
            <tr style={{ borderBottom: "1px solid var(--border-dim)" }}>
              <td style={{ padding: "10px 14px", color: "var(--text-muted)", fontWeight: 600 }}>دامنه SNI</td>
              {selectedData.map(({ profile }) => (
                <td key={profile.id} style={{ padding: "10px 14px" }}>
                  {profile.sni ? (
                    <span className="mono" style={{ color: "#34d399" }}>{profile.sni}</span>
                  ) : (
                    <span className="badge badge-rose">فاقد SNI (اسکن مستقیم IP)</span>
                  )}
                </td>
              ))}
            </tr>

            {/* ALPN */}
            <tr style={{ borderBottom: "1px solid var(--border-dim)" }}>
              <td style={{ padding: "10px 14px", color: "var(--text-muted)", fontWeight: 600 }}>پروتکل ALPN</td>
              {selectedData.map(({ profile }) => (
                <td key={profile.id} style={{ padding: "10px 14px" }}>
                  {profile.alpn.length > 0 ? (
                    <span className="mono badge badge-purple">{profile.alpn.join(", ")}</span>
                  ) : (
                    <span className="badge" style={{ color: "#94a3b8" }}>فاقد ALPN (کد 00)</span>
                  )}
                </td>
              ))}
            </tr>

            {/* Ciphers Count */}
            <tr style={{ borderBottom: "1px solid var(--border-dim)" }}>
              <td style={{ padding: "10px 14px", color: "var(--text-muted)", fontWeight: 600 }}>تعداد سایفرها</td>
              {selectedData.map(({ profile, ja4 }) => (
                <td key={profile.id} style={{ padding: "10px 14px" }}>
                  <span className="mono">{ja4.cipherCount} سایفر معتبر</span>
                </td>
              ))}
            </tr>

            {/* Extensions Count */}
            <tr style={{ borderBottom: "1px solid var(--border-dim)" }}>
              <td style={{ padding: "10px 14px", color: "var(--text-muted)", fontWeight: 600 }}>تعداد افزونه‌ها</td>
              {selectedData.map(({ profile, ja4 }) => (
                <td key={profile.id} style={{ padding: "10px 14px" }}>
                  <span className="mono">{ja4.extensionCount} افزونه</span>
                </td>
              ))}
            </tr>

            {/* JA3 Hash */}
            <tr style={{ borderBottom: "1px solid var(--border-dim)", background: "rgba(244, 63, 94, 0.04)" }}>
              <td style={{ padding: "12px 14px", color: "#fb7185", fontWeight: 700 }}>اثر انگشت JA3</td>
              {selectedData.map(({ profile, ja3 }) => (
                <td key={profile.id} style={{ padding: "12px 14px" }}>
                  <span className="mono" style={{ color: "#38bdf8", fontSize: "0.82rem" }}>
                    {ja3.hash}
                  </span>
                </td>
              ))}
            </tr>

            {/* JA4 String */}
            <tr style={{ borderBottom: "1px solid var(--border-dim)", background: "rgba(16, 185, 129, 0.04)" }}>
              <td style={{ padding: "12px 14px", color: "#34d399", fontWeight: 700 }}>اثر انگشت JA4</td>
              {selectedData.map(({ profile, ja4 }) => (
                <td key={profile.id} style={{ padding: "12px 14px" }}>
                  <span className="mono" style={{ color: "#34d399", fontSize: "0.85rem", fontWeight: 700 }}>
                    {ja4.full}
                  </span>
                </td>
              ))}
            </tr>
          </tbody>
        </table>
      </div>

      {/* SOC Security Analyst Panel */}
      <div className="panel" style={{ border: "1px solid rgba(245, 158, 11, 0.4)" }}>
        <div className="panel-header">
          <div className="panel-title">
            <Eye size={20} color="#f59e0b" />
            <span>میز کار تحلیلگر امنیت شبکه (SOC Analyst Investigation Panel)</span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            {CLIENT_PROFILES.map((p) => (
              <button
                key={p.id}
                onClick={() => setActiveAnalystProfileId(p.id)}
                className={`btn btn-sm ${activeAnalystProfileId === p.id ? "btn-primary" : "btn-outline"}`}
              >
                {p.badge}
              </button>
            ))}
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 20 }}>
          {/* Analysis Details */}
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <strong style={{ fontSize: "1.1rem", color: "#ffffff" }}>
                  {activeAnalystProfile.profile.name}
                </strong>
                <span className={`badge ${
                  activeAnalystProfile.profile.securityAnalysis.riskScore.includes("بالا")
                    ? "badge-rose"
                    : activeAnalystProfile.profile.securityAnalysis.riskScore.includes("متوسط")
                    ? "badge-amber"
                    : "badge-emerald"
                }`}>
                  سطح ریسک: {activeAnalystProfile.profile.securityAnalysis.riskScore}
                </span>
              </div>
              <p style={{ fontSize: "0.88rem", color: "var(--text-muted)" }}>
                نمونه User-Agent گزارش‌شده: <span className="mono" style={{ color: "#38bdf8", fontSize: "0.8rem" }}>{activeAnalystProfile.profile.userAgentExample}</span>
              </p>
            </div>

            {/* Key characteristics */}
            <div>
              <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text-dim)", display: "block", marginBottom: 6 }}>
                ویژگی‌های کلیدی اثر انگشت این کلاینت:
              </span>
              <ul style={{ paddingRight: 20, display: "flex", flexDirection: "column", gap: 6, fontSize: "0.84rem", color: "var(--text-main)" }}>
                {activeAnalystProfile.profile.securityAnalysis.fingerprintCharacteristics.map((f, i) => (
                  <li key={i}>{f}</li>
                ))}
              </ul>
            </div>

            {/* SOC Notes */}
            <div style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-dim)",
              borderRadius: "var(--radius-md)",
              padding: "14px"
            }}>
              <strong style={{ fontSize: "0.85rem", color: "#38bdf8", display: "block", marginBottom: 4 }}>
                یادداشت کارشناس امنیت (SOC Playbook):
              </strong>
              <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", lineHeight: 1.6 }}>
                {activeAnalystProfile.profile.securityAnalysis.analystNotes}
              </p>
            </div>
          </div>

          {/* Detection Rules & Pitfalls */}
          <div style={{
            background: "rgba(6, 182, 212, 0.05)",
            border: "1px solid rgba(6, 182, 212, 0.2)",
            borderRadius: "var(--radius-md)",
            padding: "16px",
            display: "flex",
            flexDirection: "column",
            gap: 12
          }}>
            <strong style={{ fontSize: "0.95rem", color: "#ffffff", display: "flex", alignItems: "center", gap: 8 }}>
              <ShieldCheck size={18} color="#06b6d4" />
              <span>سناریوی کشف جعل هویت (User-Agent Spoofing)</span>
            </strong>

            <p style={{ fontSize: "0.84rem", color: "var(--text-muted)", lineHeight: 1.6 }}>
              مهاجمان معمولاً هدر متنی <span className="mono">User-Agent</span> را به کروم یا فایرفاکس تغییر می‌دهند تا در لاگ‌های وب‌سرور شبیه مرورگر عادی به نظر برسند.
              اما تغییر User-Agent در سطح لایه ۷ هیچ تأثیری بر پیام <span className="mono">ClientHello</span> لایه ۵ ندارد!
            </p>

            <div style={{
              background: "#080d1a",
              padding: "10px 14px",
              borderRadius: "var(--radius-sm)",
              fontSize: "0.8rem",
              lineHeight: 1.6
            }}>
              <span style={{ color: "#fb7185", fontWeight: 700 }}>قاعده تشخیص:</span>
              <br />
              اگر <span className="mono">User-Agent</span> شامل <span className="mono">Chrome</span> باشد، اما <span className="mono">JA4_a</span> برابر <span className="mono">t13d...00</span> باشد (فاقد ALPN h2)، ارتباط ۱۰۰٪ اسکریپت خودکار جعلی است!
            </div>

            <div style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: 4 }}>
              <strong>هشدار خطای مثبت (False Positive):</strong>
              {" "}{activeAnalystProfile.profile.securityAnalysis.falsePositiveWarning}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
