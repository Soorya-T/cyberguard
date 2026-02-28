"use client";

import { useEffect, useState } from "react";

interface Props {
  createdAt: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
}

function getSlaMinutes(severity: Props["severity"]) {
  switch (severity) {
    case "CRITICAL":
      return 15;
    case "HIGH":
      return 30;
    case "MEDIUM":
      return 60;
    case "LOW":
      return 240;
    default:
      return 120;
  }
}

export default function SlaTimer({ createdAt, severity }: Props) {
  const [remaining, setRemaining] = useState<number>(0);

  useEffect(() => {
    const slaMinutes = getSlaMinutes(severity);
    const created = new Date(createdAt).getTime();
    const deadline = created + slaMinutes * 60 * 1000;

    const interval = setInterval(() => {
      const now = Date.now();
      const diff = deadline - now;
      setRemaining(diff);
    }, 1000);

    return () => clearInterval(interval);
  }, [createdAt, severity]);

  if (!createdAt) return null;

  const minutes = Math.floor(Math.abs(remaining) / 60000);
  const seconds = Math.floor((Math.abs(remaining) % 60000) / 1000);

  const breached = remaining < 0;

  return (
    <div style={{
      padding: "12px",
      borderRadius: "12px",
      marginTop: "16px",
      background: breached ? "rgba(239,68,68,0.15)" : "rgba(34,197,94,0.15)",
      border: breached ? "1px solid rgba(239,68,68,0.4)" : "1px solid rgba(34,197,94,0.4)"
    }}>
      <strong>SLA Status:</strong>{" "}
      {breached ? "BREACHED" : "Active"} <br />
      <span style={{ fontSize: "14px" }}>
        {minutes}m {seconds}s {breached ? "overdue" : "remaining"}
      </span>
    </div>
  );
}