import { notFound } from "next/navigation";
import { prisma } from "@/lib/db";
import { formatNumber, humanBytes } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function ZoneDetailPage({ params }: { params: { id: string } }) {
  const id = BigInt(params.id);
  const zone = await prisma.zone.findUnique({
    where: { id },
    include: { snapshots: { orderBy: { capturedAt: "desc" }, take: 1 } },
  });
  if (!zone) notFound();

  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const [analytics, uptimeLatest, incidents, snapshot, dnsRecords] = await Promise.all([
    prisma.analyticsHourly.findMany({
      where: { zoneId: zone.id, hour: { gte: since } },
      orderBy: { hour: "asc" },
    }),
    prisma.uptimeCheck.findMany({
      where: { zoneId: zone.id },
      orderBy: { checkedAt: "desc" },
      take: 20,
    }),
    prisma.incident.findMany({
      where: { zoneId: zone.id },
      orderBy: { startedAt: "desc" },
      take: 10,
    }),
    zone.snapshots[0],
    zone.snapshots[0]
      ? prisma.$queryRaw<{ type: string; name: string; content: string; proxied: boolean; ttl: number | null }[]>`
        SELECT type, name, content, proxied, ttl FROM mmwss.dns_records_snapshot
        WHERE zone_snapshot_id = ${zone.snapshots[0].id} ORDER BY type, name`
      : Promise.resolve([]),
  ]);

  const totals = analytics.reduce(
    (acc, a) => {
      acc.req += Number(a.requests);
      acc.cached += Number(a.cachedRequests);
      acc.bytes += Number(a.bytes);
      acc.threats += Number(a.threats);
      return acc;
    },
    { req: 0, cached: 0, bytes: 0, threats: 0 }
  );
  const hitRatio = totals.req > 0 ? (totals.cached / totals.req) * 100 : 0;
  const settings = (snapshot?.settingsJson as any) || {};

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-ink">{zone.name}</h1>
        <p className="text-sm text-ink-muted mt-1">{zone.plan} · {zone.status}</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Kpi label="Requests (24h)" value={formatNumber(totals.req)} />
        <Kpi label="Cache hit" value={`${hitRatio.toFixed(1)}%`} />
        <Kpi label="Bandwidth (24h)" value={humanBytes(totals.bytes)} />
        <Kpi label="Threats blocked" value={formatNumber(totals.threats)} accent={totals.threats > 0} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Configuration">
          <Row k="SSL mode" v={settings.ssl} />
          <Row k="Always HTTPS" v={settings.always_use_https} />
          <Row k="Min TLS" v={settings.min_tls_version} />
          <Row k="Security level" v={settings.security_level} />
          <Row k="Brotli" v={settings.brotli} />
          <Row k="Cache level" v={settings.cache_level} />
          <Row k="Dev mode" v={settings.development_mode} />
          <Row k="Firewall rules" v={`${snapshot?.fwRulesEnabled ?? 0} enabled / ${snapshot?.fwRulesTotal ?? 0}`} />
        </Card>

        <Card title="SSL & DNS">
          <Row k="SSL expiry" v={snapshot?.sslExpiry ? new Date(snapshot.sslExpiry).toLocaleDateString() : "—"} />
          <Row k="Active cert packs" v={snapshot?.sslPacksActive ?? 0} />
          <Row k="DNS records" v={snapshot?.dnsCount ?? 0} />
          <Row k="Proxied" v={snapshot?.dnsProxiedCount ?? 0} />
        </Card>
      </div>

      <Card title="Recent uptime probes (last 20)">
        <div className="overflow-x-auto -mx-5 -my-2">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs uppercase tracking-wide text-ink-muted">
                <th className="text-left px-5 py-2">When</th>
                <th className="text-left px-5 py-2">Status</th>
                <th className="text-right px-5 py-2">Latency</th>
                <th className="text-left px-5 py-2">Error</th>
              </tr>
            </thead>
            <tbody>
              {uptimeLatest.map((u) => (
                <tr key={String(u.id)} className="border-t border-border">
                  <td className="px-5 py-2 text-ink-muted">{new Date(u.checkedAt).toLocaleTimeString()}</td>
                  <td className="px-5 py-2">
                    <span className={u.ok ? "text-emerald-600" : "text-brand"}>
                      {u.statusCode ?? (u.ok ? "OK" : "ERR")}
                    </span>
                  </td>
                  <td className="px-5 py-2 text-right tabular-nums text-ink-muted">{u.latencyMs ?? "—"} ms</td>
                  <td className="px-5 py-2 text-xs text-ink-muted truncate max-w-xs">{u.errorMessage || ""}</td>
                </tr>
              ))}
              {uptimeLatest.length === 0 && (
                <tr><td colSpan={4} className="px-5 py-6 text-center text-ink-muted">No probes yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title={`DNS records (${dnsRecords.length})`}>
        <div className="overflow-x-auto -mx-5 -my-2">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs uppercase tracking-wide text-ink-muted">
                <th className="text-left px-5 py-2">Type</th>
                <th className="text-left px-5 py-2">Name</th>
                <th className="text-left px-5 py-2">Content</th>
                <th className="text-left px-5 py-2">Proxied</th>
              </tr>
            </thead>
            <tbody>
              {dnsRecords.slice(0, 50).map((r, i) => (
                <tr key={i} className="border-t border-border">
                  <td className="px-5 py-2 text-ink font-mono text-xs">{r.type}</td>
                  <td className="px-5 py-2 text-ink-muted">{r.name}</td>
                  <td className="px-5 py-2 text-ink-muted font-mono text-xs truncate max-w-md">{r.content}</td>
                  <td className="px-5 py-2 text-xs">
                    {r.proxied ? <span className="text-brand">orange</span> : <span className="text-ink-subtle">direct</span>}
                  </td>
                </tr>
              ))}
              {dnsRecords.length === 0 && (
                <tr><td colSpan={4} className="px-5 py-6 text-center text-ink-muted">No snapshot yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function Kpi({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="bg-white border border-border rounded-lg p-4 shadow-tremor-card">
      <div className="text-xs uppercase tracking-wide text-ink-muted">{label}</div>
      <div className={`text-2xl font-semibold mt-1 ${accent ? "text-brand" : "text-ink"}`}>{value}</div>
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white border border-border rounded-lg shadow-tremor-card">
      <div className="px-5 py-3 border-b border-border"><h2 className="text-sm font-semibold text-ink">{title}</h2></div>
      <div className="px-5 py-4 space-y-2">{children}</div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: any }) {
  return (
    <div className="flex justify-between text-sm">
      <span className="text-ink-muted">{k}</span>
      <span className="text-ink font-medium">{String(v ?? "—")}</span>
    </div>
  );
}
