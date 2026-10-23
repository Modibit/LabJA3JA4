import React, { useState, useEffect } from "react";
import {
  FileSpreadsheet,
  Upload,
  FileCheck,
  AlertCircle,
  CheckCircle2,
  Download,
  Eye,
  Info,
  Clock,
  Radio,
  Layers,
  ChevronDown,
  ChevronUp
} from "lucide-react";
import { parsePcapArrayBuffer, type ParsedClientHelloPacket } from "../utils/pcapParser";
import { BACKEND_URL } from "../config";

interface SampleItem {
  id: string;
  title: string;
  client_name: string;
  description: string;
  sni: string;
  alpn: string[];
}

export const PcapAnalyzerView: React.FC = () => {
  const [packets, setPackets] = useState<ParsedClientHelloPacket[]>([]);
  const [selectedPacketIdx, setSelectedPacketIdx] = useState<number | null>(null);
  const [activeFileName, setActiveFileName] = useState<string | null>(null);
  const [fileSizeBytes, setFileSizeBytes] = useState<number | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [warningMessage, setWarningMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [samplesList, setSamplesList] = useState<SampleItem[]>([]);

  // Fetch sample list from backend if available
  useEffect(() => {
    fetch(`${BACKEND_URL}/api/pcap/samples`)
      .then((res) => res.json())
      .then((data) => {
        if (data.samples) {
          setSamplesList(data.samples);
        }
      })
      .catch(() => {
        // Fallback static list when backend not running
        setSamplesList([
          {
            id: "chrome_browser.pcap",
            title: "مرورگر Chrome 124+ (همراه با GREASE و TLS 1.3)",
            client_name: "Google Chrome",
            description: "ارتباط واقعی کلاینت مدرن شامل افزونه‌های تصادفی GREASE و ALPN h2.",
            sni: "www.google.com",
            alpn: ["h2", "http/1.1"]
          },
          {
            id: "curl_client.pcap",
            title: "دستور curl 8.x (مبتنی بر OpenSSL)",
            client_name: "cURL CLI Tool",
            description: "درخواست خط فرمان curl برای وب‌سایت curl.se با پشته OpenSSL.",
            sni: "curl.se",
            alpn: ["h2", "http/1.1"]
          },
          {
            id: "python_requests.pcap",
            title: "اسکریپت پایتون (Python Requests / Urllib3)",
            client_name: "Python Automation Client",
            description: "ترافیک اسکریپت خودکار پایتون فاقد ALPN چندگانه.",
            sni: "api.github.com",
            alpn: []
          },
          {
            id: "automated_scanner.pcap",
            title: "ربات اسکنر امنیتی / ابزار شناسایی خودکار",
            client_name: "Automated Port/TLS Scanner",
            description: "ترافیک ابزار بررسی شبکه بدون SNI و با سایفرهای ضعیف.",
            sni: "",
            alpn: []
          }
        ]);
      });
  }, []);

  // Process uploaded PCAP file
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setActiveFileName(file.name);
    setFileSizeBytes(file.size);
    setErrorMessage(null);
    setWarningMessage(null);
    setLoading(true);

    try {
      const buffer = await file.arrayBuffer();
      const results = parsePcapArrayBuffer(buffer);

      if (results.length === 0) {
        setWarningMessage("فایل به درستی خوانده شد، اما هیچ بسته حاوی پیام معتبر TLS ClientHello (دست‌دهی اولیه) در آن یافت نشد.");
      } else {
        setSelectedPacketIdx(0);
      }
      setPackets(results);
    } catch (err: any) {
      setErrorMessage(`خطا در تجزیه فایل PCAP: ${err.message || String(err)}`);
      setPackets([]);
    } finally {
      setLoading(false);
    }
  };

  // Load and parse a pre-bundled sample
  const loadSample = async (sampleId: string) => {
    setActiveFileName(sampleId);
    setErrorMessage(null);
    setWarningMessage(null);
    setLoading(true);

    try {
      // First try fetching binary from backend
      const res = await fetch(`${BACKEND_URL}/api/pcap/samples/${sampleId}/download`);
      if (res.ok) {
        const buffer = await res.arrayBuffer();
        setFileSizeBytes(buffer.byteLength);
        const results = parsePcapArrayBuffer(buffer);
        setPackets(results);
        setSelectedPacketIdx(results.length > 0 ? 0 : null);
      } else {
        throw new Error("Backend not available");
      }
    } catch {
      // If backend is not active, synthesize client-side sample
      loadClientSynthesizedSample(sampleId);
    } finally {
      setLoading(false);
    }
  };

  const loadClientSynthesizedSample = (sampleId: string) => {
    // Generate sample directly in frontend
    if (sampleId === "chrome_browser.pcap") {
      const sampleBuffer = createMockPcapBuffer(0x0303, [0x2a2a, 0x1301, 0x1302, 0xc02b], [0x3a3a, 0x0000, 0x0010, 0x002b], "www.google.com", ["h2"]);
      setFileSizeBytes(sampleBuffer.byteLength);
      const results = parsePcapArrayBuffer(sampleBuffer);
      setPackets(results);
      setSelectedPacketIdx(0);
    } else if (sampleId === "curl_client.pcap") {
      const sampleBuffer = createMockPcapBuffer(0x0303, [0x1302, 0x1303, 0xc02b], [0x0000, 0x0010, 0x002b], "curl.se", ["h2", "http/1.1"]);
      setFileSizeBytes(sampleBuffer.byteLength);
      const results = parsePcapArrayBuffer(sampleBuffer);
      setPackets(results);
      setSelectedPacketIdx(0);
    } else if (sampleId === "python_requests.pcap") {
      const sampleBuffer = createMockPcapBuffer(0x0303, [0x1301, 0x1302, 0xc02b], [0x0000, 0x000a, 0x000b], "api.github.com", []);
      setFileSizeBytes(sampleBuffer.byteLength);
      const results = parsePcapArrayBuffer(sampleBuffer);
      setPackets(results);
      setSelectedPacketIdx(0);
    } else {
      const sampleBuffer = createMockPcapBuffer(0x0301, [0x002f, 0x0035], [0x000a], "", []);
      setFileSizeBytes(sampleBuffer.byteLength);
      const results = parsePcapArrayBuffer(sampleBuffer);
      setPackets(results);
      setSelectedPacketIdx(0);
    }
  };

  // Helper to create synthetic valid PCAP ArrayBuffer
  function createMockPcapBuffer(clientVer: number, ciphers: number[], exts: number[], sni: string, alpn: string[]): ArrayBuffer {
    // Build real binary bytes matching libpcap format
    const extBytes: number[] = [];
    for (const e of exts) {
      if (e === 0x0000 && sni) {
        const nameBytes = new TextEncoder().encode(sni);
        const data = [0, 0, (nameBytes.length + 3) >> 8, (nameBytes.length + 3) & 0xff, 0, (nameBytes.length >> 8), nameBytes.length & 0xff, ...nameBytes];
        extBytes.push((e >> 8), e & 0xff, 0, data.length, ...data);
      } else if (e === 0x0010 && alpn.length > 0) {
        const pBytes = new TextEncoder().encode(alpn[0]);
        const data = [0, pBytes.length + 1, pBytes.length, ...pBytes];
        extBytes.push((e >> 8), e & 0xff, 0, data.length, ...data);
      } else {
        extBytes.push((e >> 8), e & 0xff, 0, 0);
      }
    }

    const cipherBytes: number[] = [];
    for (const c of ciphers) {
      cipherBytes.push((c >> 8), c & 0xff);
    }

    const chBody = [
      (clientVer >> 8), clientVer & 0xff,
      ...new Array(32).fill(0x11), // 32 bytes random
      0, // session id len
      (cipherBytes.length >> 8), cipherBytes.length & 0xff,
      ...cipherBytes,
      1, 0, // compression
      (extBytes.length >> 8), extBytes.length & 0xff,
      ...extBytes
    ];

    const hsLen = chBody.length;
    const hsBytes = [1, (hsLen >> 16) & 0xff, (hsLen >> 8) & 0xff, hsLen & 0xff, ...chBody];
    const recLen = hsBytes.length;
    const tlsBytes = [0x16, 3, 1, (recLen >> 8) & 0xff, recLen & 0xff, ...hsBytes];

    // TCP Header (20 bytes)
    const tcp = [
      0xcc, 0x12, 0x01, 0xbb, // src 52242, dst 443
      0, 0, 0x03, 0xe8, 0, 0, 0, 1, // seq, ack
      0x50, 0x18, 0xfa, 0xf0, 0, 0, 0, 0
    ];
    const tcpData = [...tcp, ...tlsBytes];

    // IPv4 Header (20 bytes)
    const ipTotal = 20 + tcpData.length;
    const ip = [
      0x45, 0, (ipTotal >> 8), ipTotal & 0xff, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0,
      192, 168, 1, 105, 142, 250, 180, 206
    ];
    const ipData = [...ip, ...tcpData];

    // Ethernet (14 bytes)
    const eth = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
    const ethData = [...eth, ...ipData];

    // PCAP packet header (16 bytes)
    const pktLen = ethData.length;
    const pktHdr = [
      0x66, 0x22, 0x11, 0x00, 0, 0, 0, 0,
      (pktLen >> 24) & 0xff, (pktLen >> 16) & 0xff, (pktLen >> 8) & 0xff, pktLen & 0xff,
      (pktLen >> 24) & 0xff, (pktLen >> 16) & 0xff, (pktLen >> 8) & 0xff, pktLen & 0xff
    ];

    // Global PCAP Header (24 bytes)
    const globalHdr = [
      0xa1, 0xb2, 0xc3, 0xd4, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0xff, 0xff, 0, 0, 0, 1
    ];

    const finalBytes = new Uint8Array([...globalHdr, ...pktHdr, ...ethData]);
    return finalBytes.buffer;
  }

  const selectedPacket = packets.find((p) => p.packetIndex === selectedPacketIdx) || packets[0];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
      {/* Upload and Samples Bar */}
      <div className="panel" style={{ border: "1px solid rgba(6, 182, 212, 0.3)" }}>
        <div className="panel-header">
          <div className="panel-title">
            <FileSpreadsheet size={22} color="#06b6d4" />
            <span>پردازش و تحلیل فایل واقعی ترافیک ضبط‌شده (PCAP / PCAPNG)</span>
          </div>
          <span className="badge badge-emerald">تحلیل محلی ۱۰۰٪ آفلاین</span>
        </div>

        <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", marginBottom: 18 }}>
          شما می‌توانید فایل‌های ضبط‌شده ترافیک شبکه خود را بارگذاری کنید یا با یک کلیک از نمونه‌های آموزشی همراه پروژه استفاده نمایید.
          بسته‌های TLS استخراج شده و اثر انگشت‌های JA3 و JA4 برای هر اتصال به صورت زنده محاسبه خواهند شد.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 20 }}>
          {/* Upload Drop Zone */}
          <div style={{
            background: "var(--bg-surface)",
            border: "2px dashed var(--border-medium)",
            borderRadius: "var(--radius-md)",
            padding: "24px",
            textAlign: "center",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            gap: 10,
            cursor: "pointer"
          }}>
            <Upload size={32} color="#06b6d4" />
            <strong style={{ fontSize: "0.95rem" }}>بارگذاری فایل .pcap یا .pcapng</strong>
            <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
              فایل ضبط‌شده شبکه از Wireshark یا tcpdump را اینجا رها کنید
            </span>
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={handleFileUpload}
              style={{
                marginTop: 6,
                fontSize: "0.82rem",
                color: "var(--text-muted)",
                cursor: "pointer"
              }}
            />
          </div>

          {/* Pre-bundled Quick Samples */}
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text-dim)" }}>
              نمونه‌های ترافیک آماده همراه پروژه (یک کلیک برای اجرا):
            </span>
            {samplesList.map((s) => (
              <button
                key={s.id}
                onClick={() => loadSample(s.id)}
                className="btn btn-secondary btn-sm"
                style={{
                  justifyContent: "space-between",
                  padding: "8px 12px",
                  textAlign: "right"
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <FileCheck size={16} color="#06b6d4" />
                  <span>{s.title}</span>
                </div>
                <span className="badge badge-cyan">{s.sni || "بدون SNI"}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Warning or Error Notifications */}
        {warningMessage && (
          <div style={{
            background: "rgba(245, 158, 11, 0.12)",
            border: "1px solid rgba(245, 158, 11, 0.3)",
            borderRadius: "var(--radius-md)",
            padding: "12px 16px",
            marginTop: 16,
            display: "flex",
            alignItems: "center",
            gap: 10,
            fontSize: "0.88rem",
            color: "#fbbf24"
          }}>
            <AlertCircle size={18} />
            <span>{warningMessage}</span>
          </div>
        )}

        {errorMessage && (
          <div style={{
            background: "rgba(244, 63, 94, 0.12)",
            border: "1px solid rgba(244, 63, 94, 0.3)",
            borderRadius: "var(--radius-md)",
            padding: "12px 16px",
            marginTop: 16,
            display: "flex",
            alignItems: "center",
            gap: 10,
            fontSize: "0.88rem",
            color: "#fb7185"
          }}>
            <AlertCircle size={18} />
            <span>{errorMessage}</span>
          </div>
        )}

        {activeFileName && (
          <div style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginTop: 16,
            padding: "8px 14px",
            background: "rgba(6, 182, 212, 0.08)",
            borderRadius: "var(--radius-sm)",
            fontSize: "0.82rem"
          }}>
            <span>فایل فعال: <strong className="mono" style={{ color: "#38bdf8" }}>{activeFileName}</strong> {fileSizeBytes ? `(${Math.round(fileSizeBytes / 1024)} KB)` : ""}</span>
            <span className="badge badge-emerald">{packets.length} پیام ClientHello شناسایی شد</span>
          </div>
        )}
      </div>

      {/* Packets List Table */}
      {packets.length > 0 && (
        <div className="panel" style={{ overflowX: "auto" }}>
          <div className="panel-header">
            <div className="panel-title">
              <Radio size={20} color="#10b981" />
              <span>فهرست بسته‌های TLS ClientHello شناسایی‌شده در فایل</span>
            </div>
            <span className="badge badge-cyan">روی هر ردیف کلیک کنید تا جزئیات نمایش یابد</span>
          </div>

          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem", textAlign: "right" }}>
            <thead>
              <tr style={{ borderBottom: "2px solid var(--border-medium)", background: "var(--bg-surface)" }}>
                <th style={{ padding: "10px 12px" }}>شماره</th>
                <th style={{ padding: "10px 12px" }}>زمان</th>
                <th style={{ padding: "10px 12px" }}>مبدأ (Source IP:Port)</th>
                <th style={{ padding: "10px 12px" }}>مقصد (Destination)</th>
                <th style={{ padding: "10px 12px" }}>دامنه (SNI)</th>
                <th style={{ padding: "10px 12px" }}>ALPN</th>
                <th style={{ padding: "10px 12px" }}>اثر انگشت JA3</th>
                <th style={{ padding: "10px 12px" }}>اثر انگشت JA4</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((pkt) => {
                const isSelected = selectedPacket && selectedPacket.packetIndex === pkt.packetIndex;
                return (
                  <tr
                    key={pkt.packetIndex}
                    onClick={() => setSelectedPacketIdx(pkt.packetIndex)}
                    style={{
                      borderBottom: "1px solid var(--border-dim)",
                      cursor: "pointer",
                      background: isSelected ? "rgba(6, 182, 212, 0.12)" : "transparent",
                      transition: "background 0.15s ease"
                    }}
                  >
                    <td style={{ padding: "10px 12px" }}>
                      <span className="badge badge-cyan">#{pkt.packetIndex}</span>
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <span className="mono" style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                        {pkt.timestampStr}
                      </span>
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <span className="mono" style={{ color: "#ffffff" }}>
                        {pkt.srcIp}:{pkt.srcPort}
                      </span>
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <span className="mono" style={{ color: "#94a3b8" }}>
                        {pkt.dstIp}:{pkt.dstPort}
                      </span>
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      {pkt.clientHello.sni ? (
                        <span className="mono badge badge-emerald">{pkt.clientHello.sni}</span>
                      ) : (
                        <span className="badge" style={{ color: "#94a3b8" }}>(فاقد SNI)</span>
                      )}
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <span className="mono" style={{ color: "#a855f7" }}>
                        {pkt.clientHello.alpn.join(",") || "00"}
                      </span>
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <span className="mono" style={{ color: "#38bdf8", fontSize: "0.78rem" }}>
                        {pkt.ja3.hash.substring(0, 16)}...
                      </span>
                    </td>
                    <td style={{ padding: "10px 12px" }}>
                      <span className="mono" style={{ color: "#34d399", fontSize: "0.8rem", fontWeight: 700 }}>
                        {pkt.ja4.full}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Selected Packet Inspector */}
      {selectedPacket && (
        <div className="panel" style={{ border: "1px solid rgba(16, 185, 129, 0.3)" }}>
          <div className="panel-header">
            <div className="panel-title">
              <Eye size={20} color="#10b981" />
              <span>کالبدشکافی بسته انتخاب‌شده #{selectedPacket.packetIndex}</span>
            </div>
            <span className="mono badge badge-emerald">{selectedPacket.srcIp}:{selectedPacket.srcPort}</span>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
            {/* JA3 Result for this packet */}
            <div>
              <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#fb7185", display: "block", marginBottom: 6 }}>
                اثر انگشت JA3 محاسبه‌شده:
              </span>
              <div className="mono" style={{ background: "#080d1a", padding: "8px 12px", borderRadius: "var(--radius-sm)", color: "#38bdf8", marginBottom: 6 }}>
                {selectedPacket.ja3.hash}
              </div>
              <span style={{ fontSize: "0.75rem", color: "var(--text-dim)", display: "block", marginBottom: 4 }}>
                رشته خام:
              </span>
              <div className="mono" style={{ background: "#080d1a", padding: "6px 10px", borderRadius: 4, fontSize: "0.78rem", wordBreak: "break-all", color: "#94a3b8" }}>
                {selectedPacket.ja3.raw}
              </div>
            </div>

            {/* JA4 Result for this packet */}
            <div>
              <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#34d399", display: "block", marginBottom: 6 }}>
                اثر انگشت JA4 محاسبه‌شده:
              </span>
              <div className="mono" style={{ background: "#080d1a", padding: "8px 12px", borderRadius: "var(--radius-sm)", color: "#34d399", fontWeight: 700, marginBottom: 6 }}>
                {selectedPacket.ja4.full}
              </div>
              <div style={{ display: "flex", gap: 8, fontSize: "0.8rem" }}>
                <span className="badge badge-cyan">JA4_a: {selectedPacket.ja4.ja4_a}</span>
                <span className="badge badge-blue">JA4_b: {selectedPacket.ja4.ja4_b}</span>
                <span className="badge badge-purple">JA4_c: {selectedPacket.ja4.ja4_c}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
