import React, { useState } from "react";
import { Header, type ActiveTab } from "./components/Header";
import { HandshakeFlowView } from "./components/HandshakeFlowView";
import { JA3LabView } from "./components/JA3LabView";
import { JA4LabView } from "./components/JA4LabView";
import { CoreExperimentView } from "./components/CoreExperimentView";
import { ClientAnalysisView } from "./components/ClientAnalysisView";
import { PcapAnalyzerView } from "./components/PcapAnalyzerView";
import { MythsAndLimitationsView } from "./components/MythsAndLimitationsView";
import { PresentationModeView } from "./components/PresentationModeView";
import { Shield, ExternalLink } from "lucide-react";

export function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>("experiment");
  const [isPresentationOpen, setIsPresentationOpen] = useState<boolean>(false);

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      {/* Presentation Fullscreen Overlay */}
      {isPresentationOpen && (
        <PresentationModeView onClose={() => setIsPresentationOpen(false)} />
      )}

      {/* Main Header with Navigation */}
      <Header
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onOpenPresentation={() => setIsPresentationOpen(true)}
      />

      {/* Main Content Area */}
      <main style={{
        flex: 1,
        maxWidth: 1400,
        margin: "0 auto",
        width: "100%",
        padding: "28px 24px"
      }}>
        {activeTab === "handshake" && <HandshakeFlowView />}
        {activeTab === "ja3" && <JA3LabView />}
        {activeTab === "ja4" && <JA4LabView />}
        {activeTab === "experiment" && <CoreExperimentView />}
        {activeTab === "clients" && <ClientAnalysisView />}
        {activeTab === "pcap" && <PcapAnalyzerView />}
        {activeTab === "myths" && <MythsAndLimitationsView />}
      </main>

      {/* Footer */}
      <footer style={{
        borderTop: "1px solid var(--border-medium)",
        background: "#050811",
        padding: "24px",
        marginTop: 40
      }}>
        <div style={{
          maxWidth: 1400,
          margin: "0 auto",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: 16,
          fontSize: "0.85rem",
          color: "var(--text-muted)"
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Shield size={18} color="#06b6d4" />
            <span>
              پروژه درسی امنیت شبکه — آزمایشگاه تعاملی اثر انگشت TLS (JA3 و JA4)
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
            <a
              href="https://github.com/salesforce/ja3"
              target="_blank"
              rel="noreferrer"
              style={{ color: "var(--text-muted)", textDecoration: "none", display: "flex", alignItems: "center", gap: 6 }}
            >
              <span>مستندات Salesforce JA3</span>
              <ExternalLink size={13} />
            </a>
            <a
              href="https://github.com/FoxIO-LLC/ja4"
              target="_blank"
              rel="noreferrer"
              style={{ color: "var(--text-muted)", textDecoration: "none", display: "flex", alignItems: "center", gap: 6 }}
            >
              <span>مستندات FoxIO JA4</span>
              <ExternalLink size={13} />
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
