"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import type { IncidentLite } from "@/lib/api";

function SevBadge({ sev }: { sev: IncidentLite["severity"] }) {
  const base = "sevBadge";
  const cls =
    sev === "CRITICAL"
      ? "sevCritical"
      : sev === "HIGH"
      ? "sevHigh"
      : sev === "MEDIUM"
      ? "sevMedium"
      : sev === "LOW"
      ? "sevLow"
      : "sevUnknown";

  return <span className={`${base} ${cls}`}>{sev}</span>;
}

export default function IncidentQueueClient({ incidents }: { incidents: IncidentLite[] }) {
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<IncidentLite["severity"] | "ALL">("ALL");

  // ✅ Local state so we can delete rows instantly
  const [items, setItems] = useState<IncidentLite[]>(incidents);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string>("");

  const rows = useMemo(() => {
    const term = q.trim().toLowerCase();
    let filtered = items;

    // Filter by severity dropdown
    if (sev !== "ALL") {
      filtered = filtered.filter((x) => x.severity === sev);
    }

    // Search behavior:
    // - If numeric: exact match ID OR exact match riskScore
    // - If text: partial match sender/subject/verdict
    if (term) {
      const numericTerm = Number(term);
      const isNumeric = !Number.isNaN(numericTerm);

      filtered = filtered.filter((x) => {
        const idStr = String(x.id);

        if (isNumeric) {
          // ✅ ID is string in your types, so compare as string
          const idMatch = idStr === term;

          // ✅ riskScore might be number|null|string depending on type
          const scoreNum = Number(x.riskScore);
          const scoreMatch = !Number.isNaN(scoreNum) && scoreNum === numericTerm;

          return idMatch || scoreMatch;
        }

        const sender = (x.sender ?? "").toLowerCase();
        const subject = (x.summary ?? "").toLowerCase();
        const verdict = (x.verdict ?? "").toLowerCase();

        return sender.includes(term) || subject.includes(term) || verdict.includes(term);
      });
    }

    // Sort by severity + risk
    const sevRank: Record<string, number> = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
      UNKNOWN: 0,
    };

    return [...filtered].sort((a, b) => {
      const sa = sevRank[a.severity] ?? 0;
      const sb = sevRank[b.severity] ?? 0;
      if (sb !== sa) return sb - sa;

      const ra = Number(a.riskScore) || 0;
      const rb = Number(b.riskScore) || 0;
      return rb - ra;
    });
  }, [items, q, sev]);

  async function handleDelete(id: IncidentLite["id"]) {
    const idStr = String(id);
    setErrorMsg("");

    const ok = window.confirm(`Delete incident report ID ${idStr}? This cannot be undone.`);
    if (!ok) return;

    setDeletingId(idStr);

    // ✅ Optimistic update: remove row instantly
    const prev = items;
    setItems((curr) => curr.filter((x) => String(x.id) !== idStr));

    try {
      const res = await fetch(`http://localhost:8000/reports/${encodeURIComponent(idStr)}`, {
        method: "DELETE",
      });

      if (!res.ok) {
        // rollback
        setItems(prev);
        const text = await res.text().catch(() => "");
        setErrorMsg(`Delete failed (HTTP ${res.status}). ${text}`);
      }
    } catch {
      // rollback
      setItems(prev);
      setErrorMsg("Delete failed. Backend not reachable on :8000");
    } finally {
      setDeletingId(null);
    }
  }

  if (!items.length) {
    return (
      <div className="notice">
        No incidents yet. Run backend once (POST <code>/analyze</code>) to create reports, then refresh.
      </div>
    );
  }

  return (
    <div className="queueWrap">
      <div
        className="queueHeader"
        style={{
          display: "flex",
          flexDirection: "column",
          gap: "14px",
          marginBottom: "18px",
        }}
      >
        <div>
          <div className="hTitle">Threat Incident Queue</div>
          <div className="hSub">Severity-Based Prioritization & Risk-Driven SOC Triage</div>
        </div>

        <div
          className="filters"
          style={{
            display: "flex",
            gap: "16px",
            alignItems: "center",
          }}
        >
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by ID, sender, risk, subject..."
            style={{
              flex: 1,
              height: "48px",
              padding: "0 18px",
              borderRadius: "12px",
              border: "1px solid rgba(255,255,255,0.15)",
              background: "rgba(255,255,255,0.05)",
              color: "white",
              fontSize: "15px",
              outline: "none",
            }}
          />

          <select
            value={sev}
            onChange={(e) => setSev(e.target.value as any)}
            style={{
              height: "48px",
              padding: "0 14px",
              borderRadius: "12px",
              border: "1px solid rgba(255,255,255,0.15)",
              background: "rgba(0,0,0,0.35)",
              color: "white",
              fontSize: "14px",
              minWidth: "180px",
              cursor: "pointer",
            }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="UNKNOWN">UNKNOWN</option>
          </select>
        </div>

        {errorMsg && (
          <div className="notice" style={{ marginTop: 6 }}>
            {errorMsg}
          </div>
        )}
      </div>

      <div className="tableWrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>SEVERITY</th>
              <th>RISK</th>
              <th>CREATED</th>
              <th>SENDER</th>
              <th>SUBJECT</th>
              <th style={{ textAlign: "right" }}>ACTION</th>
            </tr>
          </thead>

          <tbody>
            {rows.map((x) => {
              const idStr = String(x.id);
              return (
                <tr key={idStr}>
                  <td style={{ fontWeight: 700, opacity: 0.9 }}>{idStr}</td>

                  <td>
                    <SevBadge sev={x.severity} />
                  </td>

                  <td style={{ fontWeight: 700 }}>{x.riskScore}</td>

                  <td style={{ opacity: 0.85 }}>
                    {x.createdAt ? new Date(x.createdAt).toLocaleString() : "-"}
                  </td>

                  <td style={{ opacity: 0.9 }}>{x.sender ?? "-"}</td>

                  <td style={{ opacity: 0.9 }}>{x.summary ?? "-"}</td>

                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    <Link className="pillLink" href={`/incidents/${idStr}`}>
                      View
                    </Link>

                    <button
                      onClick={() => handleDelete(x.id)}
                      disabled={deletingId === idStr}
                      style={{
                        marginLeft: "10px",
                        padding: "9px 12px",
                        borderRadius: "999px",
                        border: "1px solid rgba(239,68,68,0.45)",
                        background: "rgba(239,68,68,0.10)",
                        color: "rgba(255,255,255,0.92)",
                        cursor: deletingId === idStr ? "not-allowed" : "pointer",
                        fontSize: "13px",
                        fontWeight: 700,
                        opacity: deletingId === idStr ? 0.6 : 1,
                      }}
                      title="Delete this incident"
                    >
                      {deletingId === idStr ? "Deleting..." : "Delete"}
                    </button>
                  </td>
                </tr>
              );
            })}

            {!rows.length && (
              <tr>
                <td colSpan={7} style={{ padding: 18, opacity: 0.7 }}>
                  No results match your filter/search.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="small" style={{ marginTop: 10, opacity: 0.75 }}>
        Showing {rows.length} of {items.length} incidents
      </div>
    </div>
  );
}