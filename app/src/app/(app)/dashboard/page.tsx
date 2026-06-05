import { prisma } from "@/lib/db";
import { formatNumber, humanBytes } from "@/lib/utils";
import { Activity, AlertTriangle, Globe, Shield } from "lucide-react";
import Link from "next/link";

export const dynamic = "force-dynamic";
export const revalidate = 0;

async function getOverview() {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [zones, openIncidents, lastUptimePerZone, analytics24h] = await Promise.all([
    prisma.zone.findMany({
      where: { status: "active" },
      orderBy: { name: "asc" },
      include: {
        snapshots: { orderBy: { capturedAt: "desc" }, take: 1 },
      },
    }),
    prisma.incident.count({ where: { endedAt: null } }),
    prisma.$queryRaw<{ zone_id: bigint; ok: boolean; latency_ms: number | null; checked_at: Date }[]>`
      SELECT DISTINCT ON (zone_id) zone_id, ok, latency_ms, checked_at
      FROM mmwss.uptime_checks ORDER BY zone_id, checked_at DESC`,
    prisma.analyticsHourly.groupBy({
      by: ["zoneId"],
      where: { hour: { gte: since } },
      _sum: { requests: true, cachedRequests: true, bytes: true, threats: true },
    }),
  ]);

  const upMap = new Map(lastUptimePerZone.map((r) => [String(r.zone_id), r]));
  const analyticsMap = new Map(analytics24h.map((a) => [String(a.zoneId), a._sum]));

  const totalReq = analytics24h.reduce((acc, a) => acc + Number(a._sum.requests ?? 0), 0);
  const totalCached = analytics24h.reduce((acc, a) => acc + Number(a._sum.cachedRequests ?? 0), 0);
  const totalBytes = analytics24h.reduce((acc, a) => acc + Number(a._sum.bytes ?? 0), 0);
  const totalThreats = analytics24h.reduce((acc, a) => acc + Number(a._sum.threats ?? 0), 0);
  const hitRatio = totalReq > 0 ? (totalCached / totalReq) * 100 : 0;

  return { zones, openIncidents, upMap, analyticsMap, totalReq, totalBytes, totalThreats, hitRatio };
}

export default async function DashboardPage() {
  const data = await getOverview();

  const kpis = [
    { label: "Zones", value: formatNumber(data.zones.length), icon: Globe, color: "text-ink" },
    { label: "Requests (24h)", value: formatNumber(data.totalReq), icon: Activity, color: "text-ink" },
    { label: "Threats blocked (24h)", value: formatNumber(data.totalThreats), icon: Shield, color: "text-brand" },
    { label: "Open incidents", value: formatNumber(data.openIncidents), icon: AlertTriangle, color: data.openIncidents > 0 ? "text-brand" : "text-ink" },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Overview</h1>
        <p className="text-sm text-ink-muted mt-1">All sites at a glance — last 24 hours.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpis.map((k) => {
          const Icon = k.icon;
          return (
            <div key={k.label} className="bg-white border border-border rounded-lg p-5 shadow-tremor-card">
              <div className="flex items-center justify-between">
                <div className="text-xs uppercase tracking-wide text-ink-muted">{k.label}</div>
                <Icon size={16} className={k.color} />
              </div>
              <div className={`text-3xl font-semibold mt-2 ${k.color}`}>{k.value}</div>
            </div>
          );
        })}
      </div>

      <div className="bg-white border border-border rounded-lg shadow-tremor-card overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex items-center justify-between">
          <h2 className="text-base font-semibold text-ink">Sites</h2>
          <div className="text-xs text-ink-muted">{humanBytes(data.totalBytes)} served · {data.hitRatio.toFixed(0)}% cache hit</div>
        </div>
        <table className="w-full">
          <thead className="bg-surface-alt">
            <tr>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Site</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Plan</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Uptime</th>
              <th className="text-right text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Req (24h)</th>
              <th className="text-right text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Threats</th>
              <th className="text-right text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">SSL expires</th>
            </tr>
          </thead>
          <tbody>
            {data.zones.map((z) => {
              const last = data.upMap.get(String(z.id));
              const a = data.analyticsMap.get(String(z.id));
              const snap = z.snapshots[0];
              return (
                <tr key={String(z.id)} className="border-t border-border hover:bg-surface-alt">
                  <td className="px-5 py-3">
                    <Link href={`/zones/${z.id}`} className="text-ink font-medium hover:text-brand">{z.name}</Link>
                  </td>
                  <td className="px-5 py-3 text-sm text-ink-muted">{z.plan || "—"}</td>
                  <td className="px-5 py-3 text-sm">
                    {last ? (
                      <span className={`inline-flex items-center gap-1.5 ${last.ok ? "text-emerald-600" : "text-brand"}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${last.ok ? "bg-emerald-500" : "bg-brand"}`} />
                        {last.ok ? `${last.latency_ms ?? "?"}ms` : "DOWN"}
                      </span>
                    ) : <span className="text-ink-subtle">no data</span>}
                  </td>
                  <td className="px-5 py-3 text-sm text-ink text-right tabular-nums">{formatNumber(a?.requests ?? 0)}</td>
                  <td className="px-5 py-3 text-sm text-right tabular-nums">
                    <span className={Number(a?.threats ?? 0) > 0 ? "text-brand" : "text-ink-muted"}>
                      {formatNumber(a?.threats ?? 0)}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-sm text-ink-muted text-right">
                    {snap?.sslExpiry ? new Date(snap.sslExpiry).toLocaleDateString() : "—"}
                  </td>
                </tr>
              );
            })}
            {data.zones.length === 0 && (
              <tr><td colSpan={6} className="px-5 py-12 text-center text-ink-muted">No zones yet. The collector will populate this list shortly.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
