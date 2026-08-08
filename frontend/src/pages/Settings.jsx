import React from "react";

export default function Settings({ modelInfo }) {
  return (
    <div className="tab-page active" id="admin">
      <div className="page-head"><div><div className="eyebrow">SYSTEM / ADMIN</div><div className="page-title">Admin</div></div></div>
      <div className="panel">
        <div className="kv-row"><span className="kv-row-label">Active dataset</span><span className="kv-row-value">IDS2025.csv · 91,703 flows</span></div>
        <div className="kv-row"><span className="kv-row-label">Model version</span><span className="kv-row-value">xgb_nids_engine v1</span></div>
        <div className="kv-row"><span className="kv-row-label">Sniffer status</span><span className="kv-row-value ok">running</span></div>
        <div className="kv-row"><span className="kv-row-label">Alert database</span><span className="kv-row-value">nids.db</span></div>
      </div>
    </div>
  );
}
