export const BACKEND_URL =
  process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";

// ✅ Added for Week 2 (Pod A metrics + workflow integration later)
export const POD_A_BASE_URL =
  process.env.NEXT_PUBLIC_POD_A_BASE_URL || "http://localhost:8001";

/**
 * Backend /reports/history example returns:
 * [
 *  { id, sender, subject, risk_score, verdict, created_at, pdf_location }
 * ]
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export type IncidentLite = {
  id: string;
  sender?: string | null;
  summary?: string | null;
  riskScore: number;
  createdAt?: string | null;
  verdict?: string | null;
  pdfLocation?: string | null;
  severity: Severity;
};

export type IncidentDetail = IncidentLite & {
  // these may be absent in Week 1 backend; kept for future C2
  manager_summary?: string | null;
  triggered_signals?: any[];
  evidence?: any;
  email_metadata?: any;
  confidence_level?: string | null;
};

function severityFromRisk(risk: number): Severity {
  // Simple enterprise triage mapping (adjust if your PDF says different thresholds)
  if (risk >= 90) return "CRITICAL";
  if (risk >= 70) return "HIGH";
  if (risk >= 40) return "MEDIUM";
  if (risk > 0) return "LOW";
  return "UNKNOWN";
}

// ✅ Added: safe fetch timeout (keeps UI responsive)
async function httpGet<T>(path: string, base: string = BACKEND_URL): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000); // 8s timeout

  try {
    const res = await fetch(`${base}${path}`, {
      cache: "no-store",
      signal: controller.signal,
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      throw new Error(`Backend error ${res.status}: ${txt || res.statusText}`);
    }

    return res.json() as Promise<T>;
  } catch (err: any) {
    if (err?.name === "AbortError") {
      throw new Error("Request timed out. Check backend is running.");
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

export async function getIncidents(): Promise<IncidentLite[]> {
  const raw = await httpGet<any[]>(`/reports/history`);

  return raw.map((r) => {
    const risk = Number(r.risk_score ?? 0);
    return {
      id: String(r.id),
      sender: r.sender ?? null,
      summary: r.subject ?? null,
      riskScore: risk,
      createdAt: r.created_at ?? null,
      verdict: r.verdict ?? null,
      pdfLocation: r.pdf_location ?? null,
      severity: severityFromRisk(risk),
    };
  });
}

export async function getIncidentById(id: string): Promise<IncidentDetail> {
  const r = await httpGet<any>(`/reports/${encodeURIComponent(id)}`);
  const risk = Number(r.risk_score ?? 0);

  return {
    id: String(r.id ?? id),
    sender: r.sender ?? null,
    summary: r.subject ?? null,
    riskScore: risk,
    createdAt: r.created_at ?? null,
    verdict: r.verdict ?? null,
    pdfLocation: r.pdf_location ?? null,
    severity: severityFromRisk(risk),

    // optional future fields (won't break if undefined)
    manager_summary: r.manager_summary ?? null,
    triggered_signals: r.triggered_signals ?? [],
    evidence: r.evidence ?? null,
    email_metadata: r.email_metadata ?? null,
    confidence_level: r.confidence_level ?? null,
  };
}

/**
 * Week 2 (Pod A) — placeholder helpers (safe to keep even if not used yet)
 * When Pod A is ready, you will call:
 *  - /metrics/summary
 *  - /metrics/sla
 * from POD_A_BASE_URL
 */
export async function getMetricsSummary(): Promise<any> {
  return httpGet<any>(`/metrics/summary`, POD_A_BASE_URL);
}

export async function getMetricsSLA(): Promise<any> {
  return httpGet<any>(`/metrics/sla`, POD_A_BASE_URL);
}