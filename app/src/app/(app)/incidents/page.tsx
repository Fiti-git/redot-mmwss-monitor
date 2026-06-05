import Link from "next/link";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

const sevColor: Record<string, string> = {
  critical: "bg-brand-50 text-brand-700",
  warning: "bg-amber-50 text-amber-700",
  info: "bg-blue-50 text-blue-700",
};

export default async function IncidentsPage() {
  const incidents = await prisma.incident.findMany({
    orderBy: { startedAt: "desc" },
    take: 100,
    include: { zone: { select: { id: true, name: true } } },
  });

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Incidents</h1>
        <p className="text-sm text-ink-muted mt-1">Auto-detected from uptime probes and snapshots.</p>
      </div>
      <div className="bg-white border border-border rounded-lg shadow-tremor-card overflow-hidden">
        <table className="w-full">
          <thead className="bg-surface-alt">
            <tr>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Severity</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Site</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Type</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Summary</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Started</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Status</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((i) => (
              <tr key={String(i.id)} className="border-t border-border">
                <td className="px-5 py-3 text-xs">
                  <span className={`px-2 py-0.5 rounded font-medium uppercase tracking-wide ${sevColor[i.severity] || "bg-surface-alt text-ink-muted"}`}>
                    {i.severity}
                  </span>
                </td>
                <td className="px-5 py-3 text-sm">
                  <Link href={`/zones/${i.zoneId}`} className="text-ink font-medium hover:text-brand">{i.zone.name}</Link>
                </td>
                <td className="px-5 py-3 text-sm text-ink-muted font-mono text-xs">{i.type}</td>
                <td className="px-5 py-3 text-sm text-ink">{i.summary}</td>
                <td className="px-5 py-3 text-sm text-ink-muted">{new Date(i.startedAt).toLocaleString()}</td>
                <td className="px-5 py-3 text-sm">
                  {i.endedAt ? (
                    <span className="text-emerald-600">resolved</span>
                  ) : (
                    <span className="text-brand">open</span>
                  )}
                </td>
              </tr>
            ))}
            {incidents.length === 0 && (
              <tr><td colSpan={6} className="px-5 py-12 text-center text-ink-muted">No incidents yet — all sites running smoothly.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
