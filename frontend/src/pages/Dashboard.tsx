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

const API_BASE = "http://127.0.0.1:8000/api/v1";

type Threat = {
  id: number | string;
  title?: string;
  name?: string;
  severity?: string;
  threat_type?: string;
  type?: string;
  source?: string;
  url?: string;
  created_at?: string;
};

type Overview = {
  total_threats?: number;
  analyzed_threats?: number;
  severity_distribution?: Record<string, number>;
  recent_critical_threats?: Threat[];
};

type ScanResult = {
  verdict?: string;
  risk_score?: number;
  threat_type?: string;
  summary?: string;
  message?: string;
};

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${url}`, options);

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }

  return response.json();
}

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
        request<Overview>("/dashboard/overview"),
        request<{ items?: Threat[] }>("/threats/?page_size=50"),
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

      const result = await request<ScanResult>("/scans/url", {
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

      const result = await request<ScanResult>("/scans/file", {
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

  const totalThreats = overview?.total_threats ?? 36;
  const analyzedThreats = overview?.analyzed_threats ?? 0;

  const totalScans = 1248;
  const safeLinks = Math.max(0, totalScans - totalThreats);

  const criticalThreats =
    overview?.recent_critical_threats?.length
      ? overview.recent_critical_threats
      : threats.filter(
          (threat) =>
            threat.severity?.toLowerCase() === "critical"
        );

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

          <div className="user-profile">

            <div className="user-avatar">
              S
            </div>

            <span>Sumit</span>

            <ChevronDown size={15} />

          </div>

        </div>

      </header>


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
          title="Total Scans"
          value={totalScans.toLocaleString()}
          change="+12%"
          tone="blue"
        />

        <MetricCard
          icon={<AlertTriangle size={21} />}
          title="Threats Detected"
          value={totalThreats.toLocaleString()}
          change="+8%"
          tone="red"
        />

        <MetricCard
          icon={<CheckCircle2 size={21} />}
          title="Safe Links & Files"
          value={safeLinks.toLocaleString()}
          change="+15%"
          tone="green"
        />

        <MetricCard
          icon={<Sparkles size={21} />}
          title="AI Analysis"
          value={analyzedThreats.toLocaleString()}
          change="+12%"
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

                {scanResult.threat_type && (
                  <p>
                    Type: {scanResult.threat_type}
                  </p>
                )}

                <p>
                  {scanResult.summary ??
                    scanResult.message}
                </p>

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

              <SecurityItem text="Detects malicious URLs & files" />

              <SecurityItem text="Uses AI-powered analysis" />

              <SecurityItem text="Provides risk score & verdict" />

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
                    Latest high-risk indicators
                    detected across your scans.
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
                          {threat.title ??
                            threat.name ??
                            "Critical Threat"}
                        </strong>

                        <span>
                          {threat.threat_type ??
                            threat.type ??
                            "Threat detected"}
                        </span>

                      </div>

                      <span className="severity-badge">
                        {threat.severity ??
                          "Critical"}
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
                  label="Malware"
                  value="44%"
                  className="malware"
                />

                <LegendItem
                  label="Phishing"
                  value="22%"
                  className="phishing"
                />

                <LegendItem
                  label="Suspicious"
                  value="19%"
                  className="suspicious"
                />

                <LegendItem
                  label="Low Risk"
                  value="15%"
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
                    {threat.title ??
                      threat.name ??
                      "Threat"}
                  </span>

                  <span>
                    {threat.threat_type ??
                      threat.type ??
                      "Unknown"}
                  </span>

                  <span>
                    {threat.severity ??
                      "Unknown"}
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
              {selectedThreat.title ??
                selectedThreat.name ??
                "Threat Details"}
            </h2>

            <p>
              Type:{" "}
              {selectedThreat.threat_type ??
                selectedThreat.type ??
                "Unknown"}
            </p>

            <p>
              Severity:{" "}
              {selectedThreat.severity ??
                "Unknown"}
            </p>

            {selectedThreat.url && (
              <p>
                URL: {selectedThreat.url}
              </p>
            )}

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
          <b>↑ {change}</b>
          <span>vs. last 7 days</span>
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