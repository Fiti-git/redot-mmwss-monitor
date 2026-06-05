import Link from "next/link";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export default async function ZonesPage() {
  const zones = await prisma.zone.findMany({
    where: { status: "active" },
    orderBy: { name: "asc" },
    include: { snapshots: { orderBy: { capturedAt: "desc" }, take: 1 } },
  });

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold text-ink">Zones</h1>
      <div className="bg-white border border-border rounded-lg shadow-tremor-card overflow-hidden">
        <table className="w-full">
          <thead className="bg-surface-alt">
            <tr>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Name</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Plan</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Status</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">SSL mode</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Last snapshot</th>
            </tr>
          </thead>
          <tbody>
            {zones.map((z) => {
              const s = (z.snapshots[0]?.settingsJson as any) || {};
              return (
                <tr key={String(z.id)} className="border-t border-border hover:bg-surface-alt">
                  <td className="px-5 py-3"><Link href={`/zones/${z.id}`} className="text-ink font-medium hover:text-brand">{z.name}</Link></td>
                  <td className="px-5 py-3 text-sm text-ink-muted">{z.plan || "—"}</td>
                  <td className="px-5 py-3 text-sm">
                    <span className="inline-flex items-center gap-1.5 text-emerald-600">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                      {z.status}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-sm text-ink-muted">{s.ssl || "—"}</td>
                  <td className="px-5 py-3 text-sm text-ink-muted">
                    {z.snapshots[0]?.capturedAt ? new Date(z.snapshots[0].capturedAt).toLocaleString() : "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
