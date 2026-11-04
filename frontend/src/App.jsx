import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api.js";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const CLASS_LABEL = {
  idor: "IDOR",
  missing_authorization: "Missing authz",
  reflected_input: "Reflected input",
  verbose_error: "Verbose error",
  sensitive_data_exposure: "Sensitive data",
  cors_misconfiguration: "CORS",
};

export default function App() {
  const [health, setHealth] = useState(null);
  const [project, setProject] = useState(null);
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState("pending");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState(null);

  useEffect(() => { api.health().then(setHealth).catch(() => setHealth({ ok: false })); }, []);

  const load = async (promise) => {
    setBusy(true); setError("");
    try {
      const p = await promise;
      setProject(p);
      setSelected(p.findings[0]?.id ?? null);
      setFilter("pending");
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  const findings = project?.findings ?? [];
  const visible = useMemo(
    () => findings.filter((f) => filter === "all" || f.status === filter),
    [findings, filter],
  );
  const current = findings.find((f) => f.id === selected);

  const patch = useCallback(async (fid, change) => {
    const updated = await api.update(project.id, fid, change);
    setProject((p) => ({ ...p, findings: p.findings.map((f) => (f.id === fid ? updated : f)) }));
    return updated;
  }, [project]);

  const deciding = useRef(false);
  const decide = useCallback(async (status) => {
    if (!current || deciding.current) return; // ignore key repeats while a save is in flight
    deciding.current = true;
    try {
      const idx = visible.findIndex((f) => f.id === current.id);
      await patch(current.id, { status });
      const next = visible[idx + 1] ?? visible[idx - 1];
      if (filter !== "all" && next) setSelected(next.id);
    } finally { deciding.current = false; }
  }, [current, visible, patch, filter]);

  // keyboard triage: j/k to move, a accept, r reject
  useEffect(() => {
    const onKey = (e) => {
      if (["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName) || !project || report) return;
      const idx = visible.findIndex((f) => f.id === selected);
      if (e.key === "j" && visible[idx + 1]) setSelected(visible[idx + 1].id);
      if (e.key === "k" && visible[idx - 1]) setSelected(visible[idx - 1].id);
      if (e.key === "a") decide("accepted");
      if (e.key === "r") decide("rejected");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [visible, selected, decide, project, report]);

  const counts = useMemo(() => {
    const c = { pending: 0, accepted: 0, rejected: 0, all: findings.length };
    findings.forEach((f) => { c[f.status] += 1; });
    return c;
  }, [findings]);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">B→R</span>
          <span>Burp-to-Report</span>
        </div>
        {project && <span className="project-name">{project.name}</span>}
        <div className="spacer" />
        {health && <ModeBadge health={health} />}
        {project && (
          <>
            <button className="ghost" onClick={() => { setProject(null); setReport(null); }}>New</button>
            <button className="primary" disabled={!counts.accepted}
              onClick={async () => setReport(await api.report(project.id, false))}>
              Report ({counts.accepted})
            </button>
          </>
        )}
      </header>

      {!project && <Upload busy={busy} error={error} onUpload={(f, n, s) => load(api.upload(f, n, s))}
        onDemo={() => load(api.demo())} />}

      {project && (
        <>
          <Stats stats={project.stats} />
          <main className="workspace">
            <aside className="list">
              <div className="tabs">
                {["pending", "accepted", "rejected", "all"].map((t) => (
                  <button key={t} className={filter === t ? "tab active" : "tab"} onClick={() => setFilter(t)}>
                    {t} <span className="count">{counts[t]}</span>
                  </button>
                ))}
              </div>
              {visible.length === 0 && <p className="empty">Nothing here.</p>}
              {visible.map((f) => (
                <button key={f.id} className={`row ${f.id === selected ? "sel" : ""}`} onClick={() => setSelected(f.id)}>
                  <span className={`sev sev-${f.severity}`}>{f.severity}</span>
                  <span className="row-main">
                    <span className="row-title">{f.title}</span>
                    <span className="row-meta">{CLASS_LABEL[f.vuln_class]} · {f.endpoint}</span>
                  </span>
                  <Confidence value={f.confidence} />
                </button>
              ))}
              {project.suppressed?.length > 0 && (
                <details className="suppressed">
                  <summary>{project.suppressed.length} signal(s) dismissed by the model</summary>
                  {project.suppressed.map((s, i) => (
                    <p key={i}><b>{CLASS_LABEL[s.signal.vuln_class]}</b>: {s.signal.reason}. <i>{s.model_rationale}</i></p>
                  ))}
                </details>
              )}
              <p className="hint">Keys: <kbd>j</kbd>/<kbd>k</kbd> move · <kbd>a</kbd> accept · <kbd>r</kbd> reject</p>
            </aside>
            {current ? <Detail key={current.id} pid={project.id} f={current} onPatch={patch} onDecide={decide} />
              : <section className="detail empty">Select a finding.</section>}
          </main>
        </>
      )}

      {report && <ReportModal md={report} name={project?.name} onClose={() => setReport(null)} />}
    </div>
  );
}

function ModeBadge({ health }) {
  if (!health.ok) return <span className="badge bad">backend offline</span>;
  const label = { cloud: `Muse Spark · ${health.model}`, local: `Local · ${health.model}`, off: "Heuristics only" }[health.mode];
  return <span className={`badge mode-${health.mode}`} title={health.mode === "local" ? "Traffic stays on this machine" : ""}>{label}</span>;
}

function Upload({ busy, error, onUpload, onDemo }) {
  const [file, setFile] = useState(null);
  const [name, setName] = useState("");
  const [scope, setScope] = useState("");
  const [drag, setDrag] = useState(false);
  return (
    <section className="upload">
      <h1>Triage a Burp history in minutes, not hours.</h1>
      <p className="lede">Load a Burp Suite XML export or a HAR file from a test you're authorized to run.
        Heuristics flag candidates, Muse Spark reviews each one against reference material, and you decide what goes in the report.</p>
      <label className={`drop ${drag ? "drag" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); setFile(e.dataTransfer.files[0]); }}>
        <input type="file" accept=".xml,.har,.json" onChange={(e) => setFile(e.target.files[0])} hidden />
        {file ? <span className="mono">{file.name} · {(file.size / 1024).toFixed(1)} KB</span>
          : <span>Drop an export here or <u>browse</u></span>}
      </label>
      <div className="fields">
        <input placeholder="Assessment name" value={name} onChange={(e) => setName(e.target.value)} />
        <input placeholder="In-scope hosts, comma separated (optional)" value={scope} onChange={(e) => setScope(e.target.value)} />
      </div>
      <div className="actions">
        <button className="primary" disabled={!file || busy} onClick={() => onUpload(file, name, scope)}>
          {busy ? "Analyzing…" : "Analyze"}
        </button>
        <button className="ghost" disabled={busy} onClick={onDemo}>Try the ShopLab demo</button>
      </div>
      {error && <p className="error">{error}</p>}
    </section>
  );
}

function Stats({ stats }) {
  const items = [
    ["requests", stats.total],
    ["after noise filter", stats.kept],
    ["heuristic signals", stats.signals],
    ["dismissed by model", stats.suppressed_by_model],
    ["findings", stats.findings],
  ];
  return (
    <div className="stats">
      {items.map(([label, v], i) => (
        <div key={label} className="stat">
          <b>{v ?? 0}</b><span>{label}</span>{i < items.length - 1 && <i>→</i>}
        </div>
      ))}
      <div className="stat muted"><span>{stats.seconds}s</span></div>
    </div>
  );
}

function Confidence({ value }) {
  return (
    <span className="conf" title={`Tool confidence ${Math.round(value * 100)}%`}>
      <span style={{ width: `${Math.round(value * 100)}%` }} />
    </span>
  );
}

function Detail({ pid, f, onPatch, onDecide }) {
  const [draft, setDraft] = useState({ title: f.title, severity: f.severity, rationale: f.rationale,
    remediation: f.remediation, tester_notes: f.tester_notes });
  const [exchange, setExchange] = useState(null);
  const [exId, setExId] = useState(f.exchange_ids[0]);
  const dirty = Object.keys(draft).some((k) => draft[k] !== f[k]);

  useEffect(() => { api.exchange(pid, exId).then(setExchange).catch(() => setExchange(null)); }, [pid, exId]);
  const set = (k) => (e) => setDraft((d) => ({ ...d, [k]: e.target.value }));

  return (
    <section className="detail">
      <div className="detail-head">
        <input className="title-input" value={draft.title} onChange={set("title")} />
        <div className="detail-meta">
          <select value={draft.severity} onChange={set("severity")} className={`sev-select sev-${draft.severity}`}>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
          <span className="mono">{f.endpoint}</span>
          <span className="tag">{f.triaged_by === "heuristic" ? "heuristic only" : `reviewed by ${f.triaged_by}`}</span>
          <span className={`status st-${f.status}`}>{f.status}</span>
        </div>
      </div>

      <div className="grid">
        <div className="col">
          <h3>Rationale</h3>
          <textarea rows={6} value={draft.rationale} onChange={set("rationale")} />
          <h3>Evidence <small>quoted from captured traffic, checked verbatim</small></h3>
          <ul className="evidence">{f.evidence.map((e, i) => <li key={i} className="mono">{e}</li>)}</ul>
          <h3>Remediation</h3>
          <textarea rows={3} value={draft.remediation} onChange={set("remediation")} />
          <h3>Tester notes</h3>
          <textarea rows={3} placeholder="Confirmed with account B, 14:02…" value={draft.tester_notes} onChange={set("tester_notes")} />
          {f.references.length > 0 && <p className="refs">Grounded in: {f.references.map((r) => <span key={r} className="tag">{r}</span>)}</p>}
          {f.validation_notes.length > 0 && (
            <details className="vnotes"><summary>Validation notes ({f.validation_notes.length})</summary>
              <ul>{f.validation_notes.map((n, i) => <li key={i}>{n}</li>)}</ul></details>
          )}
        </div>
        <div className="col traffic">
          <div className="traffic-head">
            <h3>Traffic</h3>
            {f.exchange_ids.length > 1 && f.exchange_ids.map((id) => (
              <button key={id} className={id === exId ? "tab active" : "tab"} onClick={() => setExId(id)}>#{id}</button>
            ))}
          </div>
          {exchange ? <>
            <pre className="http">{highlight(exchange.request, f.evidence)}</pre>
            <pre className="http resp">{highlight(exchange.response, f.evidence)}</pre>
          </> : <p className="empty">Loading…</p>}
        </div>
      </div>

      <footer className="detail-actions">
        <button className="ghost" disabled={!dirty} onClick={() => onPatch(f.id, draft)}>Save edits</button>
        <div className="spacer" />
        <button className="reject" onClick={async () => { if (dirty) await onPatch(f.id, draft); onDecide("rejected"); }}>Reject</button>
        <button className="accept" onClick={async () => { if (dirty) await onPatch(f.id, draft); onDecide("accepted"); }}>Accept</button>
      </footer>
    </section>
  );
}

function highlight(text, evidence) {
  const needles = evidence.map((e) => e.trim()).filter((e) => e.length > 3 && text.includes(e));
  if (!needles.length) return text;
  const parts = [];
  let rest = text;
  while (rest) {
    let best = null;
    for (const n of needles) {
      const i = rest.indexOf(n);
      if (i >= 0 && (!best || i < best.i)) best = { i, n };
    }
    if (!best) { parts.push(rest); break; }
    parts.push(rest.slice(0, best.i), <mark key={parts.length}>{best.n}</mark>);
    rest = rest.slice(best.i + best.n.length);
  }
  return parts;
}

function ReportModal({ md, name, onClose }) {
  const [copied, setCopied] = useState(false);
  const download = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
    a.download = `${(name || "report").replace(/\W+/g, "-").toLowerCase()}-findings.md`;
    a.click();
  };
  return (
    <div className="modal-bg" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>Report</h2>
          <div className="spacer" />
          <button className="ghost" onClick={async () => { await navigator.clipboard.writeText(md); setCopied(true); }}>
            {copied ? "Copied" : "Copy Markdown"}</button>
          <button className="primary" onClick={download}>Download .md</button>
          <button className="ghost" onClick={onClose}>Close</button>
        </div>
        <pre className="report">{md}</pre>
      </div>
    </div>
  );
}
