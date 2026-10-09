import { useEffect, useRef, useState, type ChangeEvent, type FormEvent, type ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  ChevronDown,
  File,
  Link as LinkIcon,
  Loader2,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  UploadCloud,
  X,
} from "lucide-react";

import "./Dashboard.css";
import { apiRequest, clearSession, getUsername } from "../services/api";

type Threat = {
  id: string;
  title: string;
  vendor?: string | null;
  product?: string | null;
  description?: string | null;
  cvss?: number | null;
  kev?: boolean;
  published?: string | null;
  source?: string | null;
  risk_level?: string;
  risk_score?: number;
  threat_category?: string;
  analysis?: {
    ai_summary?: string | null;
    threat_category?: string | null;
    risk_score?: number | null;
    risk_level?: string | null;
  } | null;
};

type Overview = {
  total_threats?: number;
  analyzed_threats?: number;
  severity_distribution?: Record<string, number>;
            recent_critical_threats?: Threat[];
};

type ScanResult = {
  kind?: string;
  target?: string;
  verdict?: string;
  risk_score?: number;
  signals?: string[];
  note?: string;
  sha256?: string | null;
  message?: string;
};

export default function Dashboard() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(false);

  const [scanType, setScanType] = useState<"url" | "file">("url");
  const [url, setUrl] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    loadDashboard();
  }, []);

  async function loadDashboard() {
    try {
      setLoading(true);
      setApiError(false);

      const [overviewData, threatsData] = await Promise.all([
        apiRequest<Overview>("/dashboard/overview"),
        apiRequest<{ items?: Threat[] }>("/threats/?page_size=50"),
      ]);

      setOverview(overviewData);
      setThreats(threatsData.items ?? []);
    } catch (error) {
      console.error(error);
      setApiError(true);
    } finally {
      setLoading(false);
    }
  }

  async function handleUrlScan(event: FormEvent) {
    event.preventDefault();

    if (!url.trim()) return;

    try {
      setScanning(true);
      setScanResult(null);

      const result = await apiRequest<ScanResult>("/scans/url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: url.trim(),
        }),
      });

      setScanResult(result);
    } catch (error) {
      console.error(error);
      setScanResult({
        verdict: "Unable to scan",
        message: "The scan service could not be reached.",
      });
    } finally {
      setScanning(false);
    }
  }

  async function handleFileScan() {
    if (!selectedFile) return;

    try {
      setScanning(true);
      setScanResult(null);

      const formData = new FormData();
      formData.append("file", selectedFile);

      const result = await apiRequest<ScanResult>("/scans/file", {
        method: "POST",
        body: formData,
      });

      setScanResult(result);
    } catch (error) {
      console.error(error);
      setScanResult({
        verdict: "Unable to scan",
        message: "The file scan service could not be reached.",
      });
    } finally {
      setScanning(false);
    }
  }

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0] ?? null;
    setSelectedFile(file);
  }

  const totalThreats = overview?.total_threats ?? 0;
  const analyzedThreats = overview?.analyzed_threats ?? 0;
  const criticalCount = overview?.severity_distribution?.Critical ?? 0;

  const criticalThreats =
    overview?.recent_critical_threats?.length
      ? overview.recent_critical_threats
      : threats.filter((threat) => threat.analysis?.risk_level?.toLowerCase() === "critical");

  const distribution =
    overview?.severity_distribution ?? {};

  return (
    <div className="dashboard-page">

      {/* =====================================================
          TOP BAR
      ====================================================== */}

      <header className="topbar">

        <div className="brand">

          <div className="brand-icon">
            <Shield size={20} />
          </div>

          <div className="brand-copy">
            <strong>CTI Hub</strong>
            <span>Detect · Analyze · Stay Ahead</span>
          </div>

        </div>

        <div className="topbar-right">

          <div
            className={`api-status ${
              apiError ? "api-offline" : ""
            }`}
          >
            <span className="api-dot" />

            {apiError
              ? "API Offline"
              : "API Connected"}
          </div>

          <button className="user-profile" onClick={() => { clearSession(); window.location.assign("/login"); }} title="Sign out">

            <div className="user-avatar">
              {getUsername().slice(0, 1).toUpperCase()}
            </div>

            <span>{getUsername()}</span>

            <ChevronDown size={15} />

          </button>

        </div>

      </header>

      {apiError && (
        <div className="api-error-banner" role="alert">
          The API is unavailable. Start the FastAPI server at 127.0.0.1:8000, then refresh this page.
          <button onClick={loadDashboard}>Retry</button>
        </div>
      )}


      {/* =====================================================
          HERO
      ====================================================== */}

      <section className="dashboard-hero">
        <iframe
          className="planet-background"
          src="/planet-background.html"
          title="CTI Hub cyber threat visualization"
          aria-hidden="true"
        />

        <div className="hero-overlay" />

        <div className="hero-content">
          <div className="hero-badge">
            THREAT INTELLIGENCE PLATFORM
          </div>

          <h1>
            Welcome to CTI
            <br />
            Hub
          </h1>

          <h2>
            Smarter Threat Intelligence. Safer Tomorrow.
          </h2>

          <p>
            Detect, analyze and respond to cyber threats with
            AI-powered threat intelligence and real-time security analysis.
          </p>
        </div>
      </section>


      {/* =====================================================
          METRICS
      ====================================================== */}

      <section className="metrics-grid">

        <MetricCard
          icon={<ShieldCheck size={21} />}
          title="Total Threats"
          value={totalThreats.toLocaleString()}
          change="Live"
          tone="blue"
        />

        <MetricCard
          icon={<AlertTriangle size={21} />}
          title="Critical Threats"
          value={criticalCount.toLocaleString()}
          change="Live"
          tone="red"
        />

        <MetricCard
          icon={<CheckCircle2 size={21} />}
          title="Awaiting Analysis"
          value={Math.max(totalThreats - analyzedThreats, 0).toLocaleString()}
          change="Live"
          tone="green"
        />

        <MetricCard
          icon={<Sparkles size={21} />}
          title="AI Analysis"
          value={analyzedThreats.toLocaleString()}
          change="Live"
          tone="purple"
        />

      </section>


      {/* =====================================================
          MAIN CONTENT
      ====================================================== */}

      <main className="dashboard-content">

        {/* TRIAGE + SECURITY */}

        <section className="two-column">

          <div className="panel triage-panel">

            <div className="panel-heading">

              <div className="panel-title">

                <div className="panel-icon blue">
                  <LinkIcon size={18} />
                </div>

                <div>
                  <h3>Link & File Triage</h3>

                  <p>
                    Check URLs and files for malicious
                    content, phishing, and other threats.
                  </p>
                </div>

              </div>

            </div>


            <div className="scan-tabs">

              <button
                className={
                  scanType === "url"
                    ? "active"
                    : ""
                }
                onClick={() => setScanType("url")}
              >
                <LinkIcon size={14} />
                URL
              </button>

              <button
                className={
                  scanType === "file"
                    ? "active"
                    : ""
                }
                onClick={() => setScanType("file")}
              >
                <File size={14} />
                File
              </button>

            </div>


            {scanType === "url" ? (

              <form
                className="scan-form"
                onSubmit={handleUrlScan}
              >

                <div className="scan-input">

                  <LinkIcon size={17} />

                  <input
                    value={url}
                    onChange={(event) =>
                      setUrl(event.target.value)
                    }
                    placeholder="Enter URL (e.g. https://example.com)"
                  />

                </div>

                <button
                  className="scan-button"
                  type="submit"
                  disabled={scanning}
                >

                  {scanning ? (
                    <Loader2
                      size={16}
                      className="spin"
                    />
                  ) : (
                    <Search size={16} />
                  )}

                  Scan URL

                </button>

                <span className="scan-or">
                  OR
                </span>

                <button
                  type="button"
                  className="file-button"
                  onClick={() => setScanType("file")}
                >
                  <UploadCloud size={16} />
                  Scan File
                </button>

              </form>

            ) : (

              <div className="scan-form">

                <input
                  ref={fileInputRef}
                  type="file"
                  hidden
                  onChange={handleFileChange}
                />

                <button
                  type="button"
                  className="file-picker"
                  onClick={() =>
                    fileInputRef.current?.click()
                  }
                >

                  <UploadCloud size={18} />

                  <span>
                    {selectedFile
                      ? selectedFile.name
                      : "Choose a file to scan"}
                  </span>

                </button>

                <button
                  type="button"
                  className="scan-button"
                  disabled={
                    !selectedFile || scanning
                  }
                  onClick={handleFileScan}
                >

                  {scanning ? (
                    <Loader2
                      size={16}
                      className="spin"
                    />
                  ) : (
                    <Search size={16} />
                  )}

                  Scan File

                </button>

              </div>

            )}


            {scanResult && (

              <div className="scan-result">

                <div className="result-header">
                  <ShieldCheck size={18} />

                  <strong>
                    {scanResult.verdict ??
                      "Scan Complete"}
                  </strong>
                </div>

                {scanResult.risk_score !== undefined && (
                  <p>
                    Risk Score:{" "}
                    <strong>
                      {scanResult.risk_score}
                    </strong>
                  </p>
                )}

                {scanResult.kind && (
                  <p>
                    Type: {scanResult.kind.toUpperCase()}
                  </p>
                )}
                {scanResult.signals?.map((signal) => <p key={signal}>{signal}</p>)}
                {scanResult.sha256 && <p>SHA-256: <code>{scanResult.sha256}</code></p>}
                {(scanResult.note ?? scanResult.message) && <p>{scanResult.note ?? scanResult.message}</p>}

              </div>

            )}

          </div>


          {/* SECURITY AT A GLANCE */}

          <div className="panel security-panel">

            <div className="panel-heading">

              <div className="panel-title">

                <div className="panel-icon purple">
                  <Sparkles size={18} />
                </div>

                <div>
                  <h3>Security at a Glance</h3>
                </div>

              </div>

            </div>


            <div className="security-list">

              <SecurityItem text="Provides static URL and file triage" />

              <SecurityItem text="Uses AI-powered analysis" />

              <SecurityItem text="Shows risk signals for analyst review" />

              <SecurityItem text="Real-time threat intelligence" />

            </div>

          </div>

        </section>


        {/* CRITICAL THREATS + STATISTICS */}

        <section className="bottom-grid">

          <div className="panel critical-panel">

            <div className="panel-heading">

              <div className="panel-title">

                <div className="panel-icon red">
                  <AlertTriangle size={18} />
                </div>

                <div>
                  <h3>Recent Critical Threats</h3>

                  <p>
                    Latest high-risk vulnerabilities in your threat feed.
                  </p>
                </div>

              </div>

              <button className="view-all">
                View All →
              </button>

            </div>


            {criticalThreats.length === 0 ? (

              <div className="empty-state">

                <div className="empty-icon">
                  <Search size={25} />
                </div>

                <strong>
                  No critical threats found
                </strong>

                <span>
                  Great! No critical threats
                  detected in your recent scans.
                </span>

              </div>

            ) : (

              <div className="threat-list">

                {criticalThreats
                  .slice(0, 5)
                  .map((threat) => (

                    <button
                      key={threat.id}
                      className="threat-row"
                      onClick={() =>
                        setSelectedThreat(threat)
                      }
                    >

                      <div className="threat-severity">
                        <AlertTriangle size={15} />
                      </div>

                      <div className="threat-info">

                        <strong>
                          {threat.title || "Critical Threat"}
                        </strong>

                        <span>
                          {threat.threat_category ?? threat.analysis?.threat_category ?? threat.vendor ?? "Threat detected"}
                        </span>

                      </div>

                      <span className="severity-badge">
                        {threat.risk_level ?? threat.analysis?.risk_level ?? "Critical"}
                      </span>

                    </button>

                  ))}

              </div>

            )}

          </div>


          {/* STATISTICS */}

          <div className="panel statistics-panel">

            <div className="panel-heading">

              <div className="panel-title">

                <div className="panel-icon purple">
                  <BarChart3 size={18} />
                </div>

                <div>
                  <h3>Threat Statistics</h3>
                </div>

              </div>

              <span className="period">
                Last 7 days
              </span>

            </div>


            <div className="statistics-content">

              <div className="donut">

                <div className="donut-center">
                  <strong>
                    {totalThreats}
                  </strong>

                  <span>
                    Total Threats
                  </span>
                </div>

              </div>


              <div className="legend">

                <LegendItem
                  label="Critical"
                  value={String(distribution.Critical ?? 0)}
                  className="malware"
                />

                <LegendItem
                  label="High"
                  value={String(distribution.High ?? 0)}
                  className="phishing"
                />

                <LegendItem
                  label="Medium"
                  value={String(distribution.Medium ?? 0)}
                  className="suspicious"
                />

                <LegendItem
                  label="Low"
                  value={String(distribution.Low ?? 0)}
                  className="low-risk"
                />

              </div>

            </div>

          </div>

        </section>


        {/* FULL THREAT TABLE */}

        {threats.length > 0 && (

          <section className="panel full-width-threats">

            <div className="panel-heading">

              <div className="panel-title">

                <div className="panel-icon blue">
                  <Activity size={18} />
                </div>

                <div>
                  <h3>Threat Intelligence</h3>

                  <p>
                    Recent threat intelligence
                    collected by CTI Hub.
                  </p>
                </div>

              </div>

            </div>


            <div className="threat-table">

              <div className="table-header">
                <span>Threat</span>
                <span>Type</span>
                <span>Severity</span>
                <span>Source</span>
              </div>

              {threats.slice(0, 10).map((threat) => (

                <button
                  key={threat.id}
                  className="table-row"
                  onClick={() =>
                    setSelectedThreat(threat)
                  }
                >

                  <span>
                    {threat.title || "Threat"}
                  </span>

                  <span>
                    {threat.analysis?.threat_category ?? "Pending analysis"}
                  </span>

                  <span>
                    {threat.analysis?.risk_level ?? "Pending"}
                  </span>

                  <span>
                    {threat.source ??
                      "CTI Hub"}
                  </span>

                </button>

              ))}

            </div>

          </section>

        )}

      </main>


      {/* =====================================================
          THREAT DETAILS
      ====================================================== */}

      {selectedThreat && (

        <div
          className="details-overlay"
          onClick={() =>
            setSelectedThreat(null)
          }
        >

          <div
            className="details-card"
            onClick={(event) =>
              event.stopPropagation()
            }
          >

            <button
              className="details-close"
              onClick={() =>
                setSelectedThreat(null)
              }
            >
              <X size={18} />
            </button>

            <Shield size={28} />

            <h2>
              {selectedThreat.title || "Threat Details"}
            </h2>

            <p>
              Type:{" "}
              {selectedThreat.analysis?.threat_category ?? "Pending analysis"}
            </p>

            <p>
              Severity:{" "}
              {selectedThreat.analysis?.risk_level ?? "Pending"}
            </p>

            {selectedThreat.description && <p>{selectedThreat.description}</p>}
            {selectedThreat.cvss != null && <p>CVSS: {selectedThreat.cvss}{selectedThreat.kev ? " · CISA KEV" : ""}</p>}
            {selectedThreat.analysis?.ai_summary && <p>{selectedThreat.analysis.ai_summary}</p>}

          </div>

        </div>

      )}

    </div>
  );
}


/* =========================================================
   SMALL COMPONENTS
========================================================= */

function MetricCard({
  icon,
  title,
  value,
  change,
  tone,
}: {
  icon: ReactNode;
  title: string;
  value: string;
  change: string;
  tone: string;
}) {
  return (
    <div className={`metric-card ${tone}`}>

      <div className="metric-icon">
        {icon}
      </div>

      <div className="metric-content">

        <span>{title}</span>

        <strong>{value}</strong>

        <small>
          <b>{change === "Live" ? change : `↑ ${change}`}</b>
          <span>{change === "Live" ? "from API" : "vs. last 7 days"}</span>
        </small>

      </div>

    </div>
  );
}


function SecurityItem({
  text,
}: {
  text: string;
}) {
  return (
    <div className="security-item">

      <div className="security-check">
        <ShieldCheck size={14} />
      </div>

      <span>{text}</span>

    </div>
  );
}


function LegendItem({
  label,
  value,
  className,
}: {
  label: string;
  value: string;
  className: string;
}) {
  return (
    <div className="legend-item">

      <span className={`legend-dot ${className}`} />

      <span className="legend-label">
        {label}
      </span>

      <strong>{value}</strong>

    </div>
  );
}
