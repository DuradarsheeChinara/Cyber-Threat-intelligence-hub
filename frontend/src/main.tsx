import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import "./styles.css";

const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000/api/v1";
type Analysis = { ai_summary?: string; threat_category?: string; risk_score?: number; risk_level?: string; risk_breakdown?: Record<string, unknown>; embedding_dimensions?: number };
type Threat = { id: string; title: string; vendor?: string; product?: string; description?: string; cvss?: number; kev?: boolean; published?: string; analysis?: Analysis };
type Overview = { total_threats: number; analyzed_threats: number; severity_distribution: Record<string, number>; recent_critical_threats: Threat[] };

async function request<T>(path: string): Promise<T> { const response = await fetch(`${API}${path}`); if (!response.ok) throw new Error(`API ${response.status}`); return response.json(); }
function Badge({ value }: { value?: string }) { return <span className={`badge ${value?.toLowerCase() ?? "unknown"}`}>{value ?? "Pending"}</span>; }

function App() {
  const [overview, setOverview] = useState<Overview | null>(null); const [threats, setThreats] = useState<Threat[]>([]); const [selected, setSelected] = useState<Threat | null>(null); const [query, setQuery] = useState(""); const [severity, setSeverity] = useState(""); const [error, setError] = useState("");
  useEffect(() => { Promise.all([request<Overview>("/dashboard/overview"), request<{items: Threat[]}>("/threats/?page_size=50")]).then(([o, t]) => { setOverview(o); setThreats(t.items); }).catch(e => setError(e.message)); }, []);
  const visible = threats.filter(t => `${t.title} ${t.vendor ?? ""}`.toLowerCase().includes(query.toLowerCase()) && (!severity || t.analysis?.risk_level === severity));
  const selectThreat = (id: string) => request<Threat>(`/threats/${id}`).then(setSelected).catch(e => setError(e.message));
  if (error) return <main><h1>CTI Hub</h1><p className="error">Unable to reach the API: {error}</p></main>;
  const chart = Object.entries(overview?.severity_distribution ?? {}).map(([name, count]) => ({ name, count }));
  return <main><header><div><h1>Cyber Threat Intelligence Hub</h1><p>AI-assisted vulnerability prioritization</p></div><div className="counts"><b>{overview?.total_threats ?? "-"}</b> threats · <b>{overview?.analyzed_threats ?? "-"}</b> analyzed</div></header>
    <section className="cards"><article><h2>Severity distribution</h2><ResponsiveContainer width="100%" height={220}><BarChart data={chart}><XAxis dataKey="name" /><YAxis /><Tooltip /><Bar dataKey="count" fill="#22c55e" /></BarChart></ResponsiveContainer></article><article><h2>Recent critical threats</h2>{overview?.recent_critical_threats.length ? overview.recent_critical_threats.map(t => <button className="critical" key={t.id} onClick={() => selectThreat(t.id)}>{t.id} — {t.title}</button>) : <p>No critical threats processed yet.</p>}</article></section>
    <section className="threats"><div className="section-title"><h2>Threat feed</h2><input placeholder="Filter by title or vendor" value={query} onChange={e => setQuery(e.target.value)} /><select aria-label="Filter by severity" value={severity} onChange={e => setSeverity(e.target.value)}><option value="">All severities</option>{["Low", "Medium", "High", "Critical"].map(level => <option key={level}>{level}</option>)}</select></div><div className="table">{visible.map(t => <button className="row" key={t.id} onClick={() => selectThreat(t.id)}><span>{t.id}</span><strong>{t.title}</strong><span>{t.vendor ?? "Unknown"}</span><Badge value={t.analysis?.risk_level} /><span>{t.analysis?.risk_score ?? "-"}</span></button>)}</div></section>
    {selected && <aside><button className="close" onClick={() => setSelected(null)}>×</button><h2>{selected.id}</h2><Badge value={selected.analysis?.risk_level} /><h3>{selected.title}</h3><p><b>Vendor/product:</b> {selected.vendor ?? "Unknown"} / {selected.product ?? "Unknown"}</p><p><b>CVSS:</b> {selected.cvss ?? "Unavailable"} · <b>KEV:</b> {selected.kev ? "Yes" : "No"}</p><h3>AI analysis</h3><p>{selected.analysis?.ai_summary ?? "Analysis is queued or unavailable."}</p><p><b>Category:</b> {selected.analysis?.threat_category ?? "Pending"}</p><pre>{JSON.stringify(selected.analysis?.risk_breakdown ?? {}, null, 2)}</pre><h3>Raw advisory</h3><p>{selected.description}</p></aside>}</main>;
}
createRoot(document.getElementById("root")!).render(<App />);
