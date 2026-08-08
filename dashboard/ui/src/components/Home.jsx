import React, { useState, useEffect, useRef, useCallback } from "react";
import { Shield, AlertTriangle, Activity, Ban, Wifi, ScanLine, Cpu, CheckCircle2, Radar } from "lucide-react";

// ---- Simulated packet + classification generator (display-only) ----
const LABELS = ["Benign", "Port Scan", "DoS / DDoS", "Brute Force", "Botnet C2", "Web Attack"];
const LABEL_COLOR = {
  "Benign": "var(--cyan)",
  "Port Scan": "var(--amber)",
  "DoS / DDoS": "var(--red)",
  "Brute Force": "var(--red)",
  "Botnet C2": "var(--violet)",
  "Web Attack": "var(--amber)",
};
const PROTOCOLS = ["TCP", "UDP", "ICMP", "TLS"];
const FLAG_SETS = ["SYN", "SYN,ACK", "ACK", "FIN,ACK", "RST", "PSH,ACK"];

let idc = 1;
function randIp() {
  return `${10 + Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 255)}.${Math.floor(
    Math.random() * 255
  )}.${Math.floor(Math.random() * 255)}`;
}
function softmaxish() {
  // pick a dominant label, distribute rest of probability mass
  const benignBias = Math.random() < 0.62;
  const dominant = benignBias ? "Benign" : LABELS[1 + Math.floor(Math.random() * (LABELS.length - 1))];
  const domProb = 0.58 + Math.random() * 0.4;
  let rest = 1 - domProb;
  const others = LABELS.filter((l) => l !== dominant);
  const scores = { [dominant]: domProb };
  others.forEach((l, i) => {
    const share = i === others.length - 1 ? rest : rest * Math.random() * 0.6;
    scores[l] = Math.max(0.005, share);
    rest -= scores[l];
  });
  // normalize
  const total = Object.values(scores).reduce((a, b) => a + b, 0);
  Object.keys(scores).forEach((k) => (scores[k] = scores[k] / total));
  return { dominant, scores };
}
function makePacket() {
  const { dominant, scores } = softmaxish();
  return {
    id: idc++,
    time: new Date(),
    src: randIp(),
    dst: randIp(),
    sport: 1024 + Math.floor(Math.random() * 60000),
    dport: [22, 80, 443, 3389, 8080, 53, 3306, 445][Math.floor(Math.random() * 8)],
    proto: PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)],
    flags: FLAG_SETS[Math.floor(Math.random() * FLAG_SETS.length)],
    length: 40 + Math.floor(Math.random() * 1460),
    ttl: [64, 128, 255][Math.floor(Math.random() * 3)],
    entropy: (Math.random() * 8).toFixed(2),
    latencyMs: (0.4 + Math.random() * 2.1).toFixed(2),
    verdict: dominant,
    scores,
  };
}

function timeStr(d) {
  return d.toLocaleTimeString("en-US", { hour12: false });
}

export default function Home() {
  const [packets, setPackets] = useState(() => Array.from({ length: 10 }, makePacket).sort((a, b) => b.time - a.time));
  const [selectedId, setSelectedId] = useState(null);
  const [totalAnalyzed, setTotalAnalyzed] = useState(4820);
  const [threatsFound, setThreatsFound] = useState(96);
  const [history, setHistory] = useState(() => Array.from({ length: 40 }, () => 900 + Math.random() * 500));
  const [stageActive, setStageActive] = useState(0);
  const startRef = useRef(Date.now());

  const addPacket = useCallback(() => {
    const p = makePacket();
    setPackets((prev) => [p, ...prev].slice(0, 30));
    setTotalAnalyzed((n) => n + 1);
    if (p.verdict !== "Benign") setThreatsFound((n) => n + 1);
  }, []);

  useEffect(() => {
    const interval = setInterval(addPacket, 1300);
    const stageInterval = setInterval(() => setStageActive((s) => (s + 1) % 4), 420);
    const chartInterval = setInterval(() => setHistory((h) => [...h.slice(1), 900 + Math.random() * 700]), 1600);
    return () => {
      clearInterval(interval);
      clearInterval(stageInterval);
      clearInterval(chartInterval);
    };
  }, [addPacket]);

  const selected = packets.find((p) => p.id === selectedId) || packets[0];

  const maxH = Math.max(...history);
  const minH = Math.min(...history);
  const points = history
    .map((v, i) => {
      const x = (i / (history.length - 1)) * 100;
      const y = 100 - ((v - minH) / (maxH - minH || 1)) * 90 - 5;
      return `${x},${y}`;
    })
    .join(" ");

  const breakdown = LABELS.map((label) => {
    const count = packets.filter((p) => p.verdict === label).length;
    return { label, count };
  });
  const maxCount = Math.max(1, ...breakdown.map((b) => b.count));

  const flagged = packets.filter((p) => p.verdict !== "Benign").slice(0, 10);
  const benignRate = ((packets.filter((p) => p.verdict === "Benign").length / packets.length) * 100).toFixed(0);

  const stages = [
    { key: "capture", label: "Capture", icon: Wifi },
    { key: "extract", label: "Extract Features", icon: ScanLine },
    { key: "classify", label: "Classify", icon: Cpu },
    { key: "verdict", label: "Verdict", icon: CheckCircle2 },
  ];

  return (
    <div className="pc-root">
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

        .pc-root {
          --void: #0a0d13;
          --panel: #10141c;
          --panel-2: #141924;
          --border: #212836;
          --text: #e7ebf3;
          --dim: #647089;
          --dimmer: #3d465a;
          --cyan: #4fd1c5;
          --amber: #f2b84b;
          --red: #ef5a5a;
          --violet: #8b7fe8;
          background: var(--void);
          color: var(--text);
          font-family: 'JetBrains Mono', monospace;
          min-height: 100vh;
          padding: 18px;
          box-sizing: border-box;
          background-image:
            radial-gradient(circle at 15% 8%, rgba(79,209,197,0.05), transparent 40%),
            radial-gradient(circle at 88% 92%, rgba(139,127,232,0.05), transparent 40%);
        }
        .pc-root * { box-sizing: border-box; }
        .display { font-family: 'Space Grotesk', sans-serif; }

        .topbar {
          display: flex; align-items: center; justify-content: space-between;
          padding: 12px 18px; background: var(--panel); border: 1px solid var(--border);
          border-radius: 10px; margin-bottom: 14px; flex-wrap: wrap; gap: 10px;
        }
        .brand { display: flex; align-items: center; gap: 10px; }
        .brand-title { font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 18px; letter-spacing: 0.5px; }
        .brand-sub { color: var(--dim); font-size: 11px; letter-spacing: 1.5px; text-transform: uppercase; }
        .live-pill {
          display: flex; align-items: center; gap: 6px;
          background: rgba(79,209,197,0.08); border: 1px solid rgba(79,209,197,0.3);
          color: var(--cyan); padding: 5px 10px; border-radius: 20px; font-size: 11px; letter-spacing: 1px;
        }
        .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--cyan); box-shadow: 0 0 8px var(--cyan); animation: pulse 1.6s ease-in-out infinite; }
        @keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:0.35;} }
        .topstats { display: flex; gap: 22px; align-items: center; flex-wrap: wrap; }
        .topstat { display: flex; flex-direction: column; align-items: flex-end; }
        .topstat-label { color: var(--dim); font-size: 10px; letter-spacing: 1px; text-transform: uppercase; }
        .topstat-val { font-size: 15px; font-weight: 600; }
        .warn-val { color: var(--amber); }

        .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
        .panel-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
        .panel-title { font-family: 'Space Grotesk', sans-serif; font-size: 12px; letter-spacing: 1.5px; text-transform: uppercase; color: var(--dim); display: flex; align-items: center; gap: 8px; }
        .subtle { color: var(--dim); font-size: 10.5px; }

        /* Pipeline strip */
        .pipeline { display: flex; align-items: center; gap: 0; margin-bottom: 14px; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px; }
        .pipe-stage { display: flex; align-items: center; gap: 8px; flex: 1; position: relative; }
        .pipe-icon { width: 30px; height: 30px; border-radius: 8px; display: flex; align-items: center; justify-content: center; background: var(--panel-2); border: 1px solid var(--border); transition: all 0.25s; }
        .pipe-icon.active { border-color: var(--cyan); box-shadow: 0 0 12px rgba(79,209,197,0.35); background: rgba(79,209,197,0.08); }
        .pipe-label { font-size: 11px; color: var(--dim); }
        .pipe-label.active { color: var(--text); }
        .pipe-line { flex: 1; height: 1px; background: var(--border); margin: 0 6px; position: relative; overflow: hidden; }
        .pipe-line.active::after { content: ''; position: absolute; top: 0; left: -30%; width: 30%; height: 100%; background: var(--cyan); animation: slide 0.9s linear infinite; }
        @keyframes slide { from { left: -30%; } to { left: 100%; } }

        .grid-main { display: grid; grid-template-columns: 1.2fr 1fr; gap: 14px; margin-bottom: 14px; }
        @media (max-width: 900px) { .grid-main { grid-template-columns: 1fr; } }

        .stream-list { display: flex; flex-direction: column; gap: 6px; max-height: 360px; overflow-y: auto; padding-right: 4px; }
        .stream-list::-webkit-scrollbar { width: 6px; }
        .stream-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        .stream-item {
          display: grid; grid-template-columns: 60px 1fr auto; gap: 10px; align-items: center;
          padding: 8px 10px; background: var(--panel-2); border: 1px solid var(--border);
          border-left: 3px solid var(--sev-color); border-radius: 6px; font-size: 11.5px; cursor: pointer;
          animation: slidein 0.25s ease-out; transition: border-color 0.15s;
        }
        .stream-item:hover { border-color: var(--dimmer); }
        .stream-item.selected { outline: 1px solid var(--cyan); }
        @keyframes slidein { from { opacity: 0; transform: translateY(-4px);} to { opacity:1; transform: translateY(0);} }
        .stream-time { color: var(--dim); font-size: 10.5px; }
        .stream-flow { color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .stream-flow span { color: var(--dim); }
        .verdict-badge { font-weight: 600; font-size: 10px; letter-spacing: 0.5px; color: var(--sev-color); white-space: nowrap; }

        /* Inspector */
        .insp-verdict { display: flex; align-items: center; gap: 10px; padding: 12px; border-radius: 8px; background: var(--panel-2); border: 1px solid var(--border); margin-bottom: 14px; }
        .insp-verdict-label { font-family: 'Space Grotesk', sans-serif; font-size: 16px; font-weight: 700; }
        .field-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 16px; margin-bottom: 16px; font-size: 11.5px; }
        .field { display: flex; justify-content: space-between; border-bottom: 1px dashed var(--border); padding-bottom: 4px; }
        .field-k { color: var(--dim); }
        .field-v { color: var(--text); }
        .conf-row { margin-bottom: 8px; }
        .conf-head { display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 3px; }
        .conf-bar-bg { height: 6px; border-radius: 3px; background: var(--panel-2); border: 1px solid var(--border); overflow: hidden; }
        .conf-bar-fg { height: 100%; border-radius: 3px; }

        .stat-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 14px; }
        @media (max-width: 720px) { .stat-row { grid-template-columns: repeat(2, 1fr); } }
        .stat-card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
        .stat-icon-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
        .stat-label { color: var(--dim); font-size: 10.5px; letter-spacing: 1px; text-transform: uppercase; }
        .stat-value { font-family: 'Space Grotesk', sans-serif; font-size: 26px; font-weight: 700; }

        .grid-lower { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 14px; }
        @media (max-width: 900px) { .grid-lower { grid-template-columns: 1fr; } }
        .chart-wrap { height: 90px; }
        .breakdown-row { display: flex; align-items: center; gap: 10px; margin-bottom: 9px; font-size: 11px; }
        .breakdown-label { width: 92px; color: var(--dim); flex-shrink: 0; }
        .breakdown-bar-bg { flex: 1; height: 8px; border-radius: 4px; background: var(--panel-2); border: 1px solid var(--border); overflow: hidden; }
        .breakdown-bar-fg { height: 100%; border-radius: 4px; }
        .breakdown-count { width: 24px; text-align: right; color: var(--text); }

        .conn-table { width: 100%; border-collapse: collapse; font-size: 11.5px; }
        .conn-table th { text-align: left; color: var(--dim); font-weight: 500; text-transform: uppercase; font-size: 10px; letter-spacing: 1px; padding: 6px 10px; border-bottom: 1px solid var(--border); }
        .conn-table td { padding: 8px 10px; border-bottom: 1px solid var(--border); }
        .conn-table tr:last-child td { border-bottom: none; }
        .sev-badge { display: inline-flex; align-items: center; gap: 5px; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; letter-spacing: 0.5px; background: var(--sev-bg); color: var(--sev-color); }
        .ip-text { color: var(--text); }
        .arrow { color: var(--dimmer); margin: 0 4px; }
      `}</style>

      {/* Top bar */}
      <div className="topbar">
        <div className="brand">
          <Shield size={22} color="var(--cyan)" strokeWidth={1.8} />
          <div>
            <div className="brand-title">PACKETSENTRY</div>
            <div className="brand-sub">Real-Time Packet Classification</div>
          </div>
          <div className="live-pill"><span className="dot" /> LIVE</div>
        </div>
        <div className="topstats">
          <div className="topstat">
            <span className="topstat-label">Analyzed</span>
            <span className="topstat-val">{totalAnalyzed.toLocaleString()}</span>
          </div>
          <div className="topstat">
            <span className="topstat-label">Threats Found</span>
            <span className="topstat-val warn-val">{threatsFound}</span>
          </div>
          <div className="topstat">
            <span className="topstat-label">Benign Rate</span>
            <span className="topstat-val">{benignRate}%</span>
          </div>
        </div>
      </div>

      {/* Pipeline strip */}
      <div className="pipeline">
        {stages.map((s, i) => {
          const Icon = s.icon;
          const active = i === stageActive;
          return (
            <React.Fragment key={s.key}>
              <div className="pipe-stage">
                <div className={`pipe-icon ${active ? "active" : ""}`}>
                  <Icon size={15} color={active ? "var(--cyan)" : "var(--dim)"} />
                </div>
                <span className={`pipe-label ${active ? "active" : ""}`}>{s.label}</span>
              </div>
              {i < stages.length - 1 && <div className={`pipe-line ${i === stageActive ? "active" : ""}`} />}
            </React.Fragment>
          );
        })}
      </div>

      {/* Stream + Inspector */}
      <div className="grid-main">
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title"><Activity size={13} /> Live Packet Stream</span>
            <span className="subtle">click a packet to inspect</span>
          </div>
          <div className="stream-list">
            {packets.map((p) => (
              <div
                key={p.id}
                className={`stream-item ${selected && p.id === selected.id ? "selected" : ""}`}
                style={{ "--sev-color": LABEL_COLOR[p.verdict] }}
                onClick={() => setSelectedId(p.id)}
              >
                <span className="stream-time">{timeStr(p.time)}</span>
                <span className="stream-flow">
                  {p.src}<span>:{p.sport}</span> → {p.dst}<span>:{p.dport}</span>
                  <span> · {p.proto} · {p.length}B</span>
                </span>
                <span className="verdict-badge">{p.verdict}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">
            <span className="panel-title"><Cpu size={13} /> Classification Inspector</span>
          </div>
          {selected && (
            <>
              <div className="insp-verdict">
                {selected.verdict === "Benign" ? (
                  <CheckCircle2 size={22} color="var(--cyan)" />
                ) : (
                  <AlertTriangle size={22} color={LABEL_COLOR[selected.verdict]} />
                )}
                <div>
                  <div className="insp-verdict-label" style={{ color: LABEL_COLOR[selected.verdict] }}>
                    {selected.verdict}
                  </div>
                  <div className="subtle">confidence {(selected.scores[selected.verdict] * 100).toFixed(1)}% · {selected.latencyMs}ms inference</div>
                </div>
              </div>

              <div className="field-grid">
                <div className="field"><span className="field-k">Source</span><span className="field-v">{selected.src}:{selected.sport}</span></div>
                <div className="field"><span className="field-k">Destination</span><span className="field-v">{selected.dst}:{selected.dport}</span></div>
                <div className="field"><span className="field-k">Protocol</span><span className="field-v">{selected.proto}</span></div>
                <div className="field"><span className="field-k">Flags</span><span className="field-v">{selected.flags}</span></div>
                <div className="field"><span className="field-k">Length</span><span className="field-v">{selected.length} B</span></div>
                <div className="field"><span className="field-k">TTL</span><span className="field-v">{selected.ttl}</span></div>
                <div className="field"><span className="field-k">Payload Entropy</span><span className="field-v">{selected.entropy}</span></div>
                <div className="field"><span className="field-k">Inference Time</span><span className="field-v">{selected.latencyMs} ms</span></div>
              </div>

              <div className="panel-title" style={{ marginBottom: 10 }}>Class Probabilities</div>
              {LABELS.slice().sort((a, b) => selected.scores[b] - selected.scores[a]).map((label) => (
                <div className="conf-row" key={label}>
                  <div className="conf-head">
                    <span>{label}</span>
                    <span>{(selected.scores[label] * 100).toFixed(1)}%</span>
                  </div>
                  <div className="conf-bar-bg">
                    <div
                      className="conf-bar-fg"
                      style={{ width: `${selected.scores[label] * 100}%`, background: LABEL_COLOR[label] }}
                    />
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      </div>

      {/* Stat cards */}
      <div className="stat-row">
        <div className="stat-card">
          <div className="stat-icon-row"><span className="stat-label">Packets Analyzed</span><Activity size={15} color="var(--cyan)" /></div>
          <div className="stat-value">{totalAnalyzed.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon-row"><span className="stat-label">Threats Detected</span><Ban size={15} color="var(--red)" /></div>
          <div className="stat-value">{threatsFound}</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon-row"><span className="stat-label">Benign Rate</span><CheckCircle2 size={15} color="var(--cyan)" /></div>
          <div className="stat-value">{benignRate}%</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon-row"><span className="stat-label">Avg Inference</span><Cpu size={15} color="var(--violet)" /></div>
          <div className="stat-value">{(packets.reduce((a, p) => a + parseFloat(p.latencyMs), 0) / packets.length).toFixed(2)}<span style={{ fontSize: 14, color: "var(--dim)" }}> ms</span></div>
        </div>
      </div>

      {/* Chart + Breakdown */}
      <div className="grid-lower">
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title"><Activity size={13} /> Traffic Throughput</span>
            <span className="subtle">last {history.length}s</span>
          </div>
          <div className="chart-wrap">
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ width: "100%", height: "100%" }}>
              <polyline points={points} fill="none" stroke="var(--cyan)" strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
              <polyline points={`0,100 ${points} 100,100`} fill="rgba(79,209,197,0.08)" stroke="none" />
            </svg>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">
            <span className="panel-title"><Radar size={13} /> Classification Breakdown</span>
            <span className="subtle">current buffer</span>
          </div>
          {breakdown.map((b) => (
            <div className="breakdown-row" key={b.label}>
              <span className="breakdown-label">{b.label}</span>
              <div className="breakdown-bar-bg">
                <div className="breakdown-bar-fg" style={{ width: `${(b.count / maxCount) * 100}%`, background: LABEL_COLOR[b.label] }} />
              </div>
              <span className="breakdown-count">{b.count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Flagged table */}
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title"><AlertTriangle size={13} /> Flagged Packets</span>
          <span className="subtle">{flagged.length} non-benign in buffer</span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="conn-table">
            <thead>
              <tr>
                <th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Verdict</th><th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {flagged.length === 0 ? (
                <tr><td colSpan={6} className="subtle" style={{ padding: "14px 10px" }}>No threats in the current buffer.</td></tr>
              ) : flagged.map((p) => (
                <tr key={p.id}>
                  <td className="stream-time">{timeStr(p.time)}</td>
                  <td className="ip-text">{p.src}</td>
                  <td className="ip-text">{p.dst}<span className="arrow">:</span>{p.dport}</td>
                  <td>{p.proto}</td>
                  <td><span className="sev-badge" style={{ "--sev-color": LABEL_COLOR[p.verdict], "--sev-bg": `${LABEL_COLOR[p.verdict]}22` }}>{p.verdict}</span></td>
                  <td>{(p.scores[p.verdict] * 100).toFixed(1)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
