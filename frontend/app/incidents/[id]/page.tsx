import Link from "next/link";
import { getIncidentById } from "@/lib/api";
import SlaTimer from "./sla-timer";

export default async function IncidentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  // ✅ unwrap params (Next.js 16 requirement)
  const { id } = await params;

  let data: any = null;
  let error: string | null = null;

  try {
    data = await getIncidentById(id);
  } catch (e: any) {
    error = e?.message ?? "Failed to load incident";
  }

  return (
    <div className="page">
      <div className="shell">
        <div className="topbar">
          <div>
            <strong>Incident Detail</strong>
            <div className="small">ID: {id}</div>
          </div>

          <Link className="pillLink" href="/incidents">
            ← Back to Queue
          </Link>
        </div>

        <div className="card" style={{ marginTop: 20 }}>
          <div className="cardPad">
            {error ? (
              <div className="notice">{error}</div>
            ) : data ? (
              <>
                <div className="grid2">
                  <div className="kpi">
                    <div className="kpiLabel">Severity</div>
                    <div className="kpiValue">{data.severity}</div>
                  </div>

                  <div className="kpi">
                    <div className="kpiLabel">Risk Score</div>
                    <div className="kpiValue">{data.riskScore}</div>
                  </div>

                  <div className="kpi">
                    <div className="kpiLabel">Verdict</div>
                    <div className="kpiValue">{data.verdict}</div>
                  </div>

                  <div className="kpi">
                    <div className="kpiLabel">Created</div>
                    <div className="kpiValue">
                      {data.createdAt ? new Date(data.createdAt).toLocaleString() : "-"}
                    </div>
                  </div>
                </div>

                {/* ✅ SLA TIMER */}
                <SlaTimer createdAt={data.createdAt} severity={data.severity} />

                {/* ✅ Explanation */}
                <div className="sectionTitle">Explanation</div>
                <div className="card" style={{ marginTop: 10 }}>
                  <div className="cardPad">
                    {data.manager_summary || data.summary || "No explanation available."}
                  </div>
                </div>

                {/* ✅ Evidence */}
                <div className="sectionTitle">Evidence</div>
                <pre>{JSON.stringify(data.evidence || data.email_metadata || {}, null, 2)}</pre>

                {/* ✅ Week 2 actions (UI now, real integration later) */}
                <div style={{ marginTop: 20, display: "flex", gap: 12 }}>
                  <button className="btnPrimary">Mark Safe</button>
                  <button className="btnGhost">Escalate</button>
                </div>
              </>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}