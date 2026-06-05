import { prisma } from "@/lib/db";
import Link from "next/link";

export const dynamic = "force-dynamic";

export default async function UptimePage() {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const zones = await prisma.zone.findMany({ where: { status: "active" }, orderBy: { name: "asc" } });
  const summaries = await Promise.all(
    zones.map(async (z) => {
      const [total, ok, latest, avgLatency] = await Promise.all([
        prisma.uptimeCheck.count({ where: { zoneId: z.id, checkedAt: { gte: since } } }),
        prisma.uptimeCheck.count({ where: { zoneId: z.id, checkedAt: { gte: since }, ok: true } }),
        prisma.uptimeCheck.findFirst({ where: { zoneId: z.id }, orderBy: { checkedAt: "desc" } }),
        prisma.uptimeCheck.aggregate({
          where: { zoneId: z.id, checkedAt: { gte: since }, ok: true },
          _avg: { latencyMs: true },
        }),
      ]);
      const pct = total > 0 ? (ok / total) * 100 : null;
      return { zone: z, total, ok, latest, pct, avgLatency: avgLatency._avg.latencyMs };
    })
  );

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Uptime</h1>
        <p className="text-sm text-ink-muted mt-1">Last 24h — probes every 60 seconds.</p>
      </div>
      <div className="bg-white border border-border rounded-lg shadow-tremor-card overflow-hidden">
        <table className="w-full">
          <thead className="bg-surface-alt">
            <tr>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Site</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Current</th>
              <th className="text-right text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Uptime %</th>
              <th className="text-right text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Avg latency</th>
              <th className="text-right text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Probes</th>
            </tr>
          </thead>
          <tbody>
            {summaries.map(({ zone, pct, ok, total, latest, avgLatency }) => (
              <tr key={String(zone.id)} className="border-t border-border hover:bg-surface-alt">
                <td className="px-5 py-3"><Link href={`/zones/${zone.id}`} className="text-ink font-medium hover:text-brand">{zone.name}</Link></td>
                <td className="px-5 py-3 text-sm">
                  {latest ? (
                    <span className={`inline-flex items-center gap-1.5 ${latest.ok ? "text-emerald-600" : "text-brand"}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${latest.ok ? "bg-emerald-500" : "bg-brand"}`} />
                      {latest.ok ? `${latest.statusCode}` : "DOWN"}
                    </span>
                  ) : <span className="text-ink-subtle">no data</span>}
                </td>
                <td className="px-5 py-3 text-sm text-right tabular-nums">
                  {pct !== null ? `${pct.toFixed(2)}%` : "—"}
                </td>
                <td className="px-5 py-3 text-sm text-right tabular-nums text-ink-muted">
                  {avgLatency ? `${Math.round(avgLatency)} ms` : "—"}
                </td>
                <td className="px-5 py-3 text-sm text-right tabular-nums text-ink-muted">
                  {ok} / {total}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
