import Link from "next/link";

export default function Home() {
  return (
    <div className="page">
      <div className="shell">
        <header className="topbar">
          <div className="brand">
            <div className="logo" />
            <div className="brandTitle">
              <strong>CyberGuard</strong>
              <span>vSOC Dashboard • Pod C</span>
            </div>
          </div>

          <nav className="navlinks">
            <a className="pillLink" href="http://localhost:8000/docs" target="_blank" rel="noreferrer">
              Backend Swagger
            </a>
            <Link className="pillLink" href="/incidents">
              Incident Queue
            </Link>
          </nav>
        </header>

        <section className="hero">
          <div className="card">
            <div className="cardPad">
              <h1 className="h1">Incident Queue for Email Threat Intelligence</h1>
              <p className="sub">
                Week 1 (C1) provides a clean analyst queue powered by your backend <b>/reports/history</b>.
                It includes severity classification, filtering, and sorting for triage.
              </p>

              <div className="actions">
                <Link className="btnPrimary" href="/incidents">
                  Open Incident Queue →
                </Link>
                <a className="btnGhost" href="http://localhost:8000/docs" target="_blank" rel="noreferrer">
                  Open Backend Swagger →
                </a>
              </div>

              <div className="kpis">
                <div className="kpi">
                  <div className="kpiLabel">Week 1</div>
                  <div className="kpiValue">C1</div>
                  <div className="small">Queue + Filter + Severity Sort</div>
                </div>
                <div className="kpi">
                  <div className="kpiLabel">Data Source</div>
                  <div className="kpiValue">Backend</div>
                  <div className="small">/reports/history</div>
                </div>
                <div className="kpi">
                  <div className="kpiLabel">Severity</div>
                  <div className="kpiValue">Derived</div>
                  <div className="small">From risk_score (enterprise triage)</div>
                </div>
              </div>
            </div>
          </div>

          <div className="card">
            <div className="cardPad">
              <div className="sectionTitle">What C1 includes</div>
              <p className="sub">
                Severity is computed from <b>risk_score</b> and shown as CRITICAL/HIGH/MEDIUM/LOW to support triage.
                The queue supports search + severity filtering + sorting.
              </p>

              <div className="grid2">
                <div className="kpi">
                  <div className="kpiLabel">Filtering</div>
                  <div className="kpiValue">Severity + Search</div>
                  <div className="small">Find incidents fast</div>
                </div>
                <div className="kpi">
                  <div className="kpiLabel">Sorting</div>
                  <div className="kpiValue">Severity → Risk</div>
                  <div className="small">Critical shows first</div>
                </div>
              </div>

              <p className="small" style={{ marginTop: 14 }}>
                Next: Week 1 (C2) integrates Pod A endpoints + richer incident detail data.
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}