import React, { useEffect, useState } from "react";
import {
  Shield,
  Activity,
  Tv,
  Cpu,
  Layers,
  FlaskConical,
  GitCompare,
  Search,
  FileSpreadsheet,
  HelpCircle,
  CheckCircle2,
  AlertTriangle
} from "lucide-react";

export type ActiveTab =
  | "handshake"
  | "ja3"
  | "ja4"
  | "experiment"
  | "clients"
  | "pcap"
  | "myths";

import { BACKEND_URL } from "../config";

interface HeaderProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  onOpenPresentation: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onTabChange,
  onOpenPresentation,
}) => {
  const [backendStatus, setBackendStatus] = useState<{
    online: boolean;
    tshark: boolean;
  }>({ online: false, tshark: false });

  useEffect(() => {
    // Check backend status gracefully
    fetch(`${BACKEND_URL}/api/system/status`)
      .then((res) => res.json())
      .then((data) => {
        setBackendStatus({
          online: true,
          tshark: Boolean(data.tshark_installed),
        });
      })
      .catch(() => {
        // Backend not running, browser pure client parser active
        setBackendStatus({ online: false, tshark: false });
      });
  }, []);

  const navItems: { id: ActiveTab; label: string; icon: React.ReactNode }[] = [
    { id: "handshake", label: "جریان هندشیک TLS", icon: <Layers size={17} /> },
    { id: "ja3", label: "آزمایشگاه JA3", icon: <Cpu size={17} /> },
    { id: "ja4", label: "آزمایشگاه JA4", icon: <Activity size={17} /> },
    { id: "experiment", label: "آزمایش اصلی (JA3 vs JA4)", icon: <FlaskConical size={17} /> },
    { id: "clients", label: "تشخیص کلاینت و SOC", icon: <GitCompare size={17} /> },
    { id: "pcap", label: "تحلیل فایل PCAP", icon: <FileSpreadsheet size={17} /> },
    { id: "myths", label: "رفع ابهام و محدودیت‌ها", icon: <HelpCircle size={17} /> },
  ];

  return (
    <header style={{
      background: "linear-gradient(180deg, #0b1222 0%, #070b14 100%)",
      borderBottom: "1px solid var(--border-medium)",
      position: "sticky",
      top: 0,
      zIndex: 50,
      boxShadow: "0 4px 20px rgba(0,0,0,0.6)"
    }}>
      {/* Top Banner */}
      <div style={{
        maxWidth: 1400,
        margin: "0 auto",
        padding: "12px 24px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexWrap: "wrap",
        gap: 12
      }}>
        {/* Brand & Title */}
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{
            width: 44,
            height: 44,
            borderRadius: "var(--radius-md)",
            background: "linear-gradient(135deg, #06b6d4 0%, #3b82f6 100%)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "#ffffff",
            boxShadow: "0 0 15px rgba(6, 182, 212, 0.4)"
          }}>
            <Shield size={24} />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <h1 style={{ fontSize: "1.25rem", fontWeight: 800, color: "#ffffff", letterSpacing: "-0.01em" }}>
                TLS Fingerprint Lab
              </h1>
              <span className="badge badge-cyan">نسخه تعاملی کلاسی</span>
            </div>
            <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              آزمایشگاه تحلیل عملی اثر انگشت TLS — استاندارد JA3 و JA4
            </p>
          </div>
        </div>

        {/* Status Indicators & Action */}
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          {/* Offline Ready Badge */}
          <div className="badge badge-emerald" title="این نرم‌افزار به صورت ۱۰۰٪ محلی و بدون نیاز به اینترنت اجرا می‌شود.">
            <span className="pulsing-dot" />
            <span>آفلاین و محلی (Offline Ready)</span>
          </div>

          {/* Engine Status */}
          {backendStatus.online ? (
            <div className="badge badge-cyan" title="بک‌اند پایتون FastAPI متصل است.">
              <CheckCircle2 size={13} />
              <span>موتور سرور فعال {backendStatus.tshark ? "(با tshark)" : "(پارس بومی)"}</span>
            </div>
          ) : (
            <div className="badge" style={{ color: "#94a3b8", background: "rgba(148, 163, 184, 0.1)" }} title="موتور محاسباتی و پارسر باینری PCAP به صورت بومی در مرورگر در حال اجرا است.">
              <Cpu size={13} />
              <span>موتور بومی مرورگر (TS Engine)</span>
            </div>
          )}

          {/* Presentation Mode Button */}
          <button
            id="btn-presentation-mode"
            onClick={onOpenPresentation}
            className="btn btn-primary"
            style={{ padding: "8px 18px", fontSize: "0.9rem" }}
            title="حالت بهینه‌شده تمام‌صفحه برای نمایش روی پروژکتور در کلاس درس"
          >
            <Tv size={18} />
            <span>حالت ارائه در کلاس (Presentation)</span>
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div style={{
        maxWidth: 1400,
        margin: "0 auto",
        padding: "0 24px",
        display: "flex",
        alignItems: "center",
        gap: 6,
        overflowX: "auto",
        borderTop: "1px solid var(--border-dim)"
      }}>
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              id={`tab-${item.id}`}
              onClick={() => onTabChange(item.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "12px 16px",
                fontSize: "0.88rem",
                fontWeight: isActive ? 700 : 500,
                color: isActive ? "#38bdf8" : "var(--text-muted)",
                background: "transparent",
                border: "none",
                borderBottom: isActive ? "3px solid #06b6d4" : "3px solid transparent",
                cursor: "pointer",
                transition: "all 0.18s ease",
                whiteSpace: "nowrap"
              }}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
