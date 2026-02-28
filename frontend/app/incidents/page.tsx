import Link from "next/link";
import { getIncidents, type IncidentLite } from "@/lib/api";
import IncidentQueueClient from "./queue-client";

export default async function IncidentsPage() {
  let incidents: IncidentLite[] = [];
  let error: string | null = null;

  try {
    incidents = await getIncidents();
  } catch (e: any) {
    error = e?.message ?? "Failed to load incidents";
  }

  return (
    <div className="page">
      <div className="shell">
        <header className="topbar">
          <div className="brand">
            <div className="logo" />
            <div className="brandTitle">
              <strong>THREAT INCIDENT QUEUE</strong>
            </div>
          </div>
          <nav className="navlinks">
            <Link className="pillLink" href="/">
              Home
            </Link>
            <a className="pillLink" href="http://localhost:8000/docs" target="_blank" rel="noreferrer">
              Swagger
            </a>
          </nav>
        </header>

        <div className="card" style={{ marginTop: 18 }}>
          <div className="cardPad">
            {error ? (
              <div className="notice">{error}</div>
            ) : (
              <IncidentQueueClient incidents={incidents} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}