import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import { redirect } from "next/navigation";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export default async function SettingsPage() {
  const session = await getServerSession(authOptions);
  if (!session?.user || (session.user as any).role !== "admin") {
    redirect("/dashboard");
  }
  const [users, tokens] = await Promise.all([
    prisma.user.findMany({ orderBy: { email: "asc" } }),
    prisma.cfToken.findMany({ orderBy: { label: "asc" } }),
  ]);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-ink">Settings</h1>

      <div className="bg-white border border-border rounded-lg shadow-tremor-card">
        <div className="px-5 py-3 border-b border-border"><h2 className="text-sm font-semibold text-ink">Users</h2></div>
        <table className="w-full">
          <thead className="bg-surface-alt">
            <tr>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Email</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Name</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Role</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Active</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Last login</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={String(u.id)} className="border-t border-border">
                <td className="px-5 py-3 text-sm text-ink">{u.email}</td>
                <td className="px-5 py-3 text-sm text-ink-muted">{u.name}</td>
                <td className="px-5 py-3 text-sm">
                  <span className="text-[10px] uppercase tracking-wide bg-surface-alt text-ink-muted px-1.5 py-0.5 rounded">
                    {u.role}
                  </span>
                </td>
                <td className="px-5 py-3 text-sm">{u.isActive ? "yes" : "no"}</td>
                <td className="px-5 py-3 text-sm text-ink-muted">{u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="bg-white border border-border rounded-lg shadow-tremor-card">
        <div className="px-5 py-3 border-b border-border"><h2 className="text-sm font-semibold text-ink">Cloudflare tokens</h2></div>
        <table className="w-full">
          <thead className="bg-surface-alt">
            <tr>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Label</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Last 4</th>
              <th className="text-left text-xs uppercase tracking-wide text-ink-muted font-medium px-5 py-3">Added</th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={String(t.id)} className="border-t border-border">
                <td className="px-5 py-3 text-sm text-ink font-medium">{t.label}</td>
                <td className="px-5 py-3 text-sm text-ink-muted font-mono">···{t.last4}</td>
                <td className="px-5 py-3 text-sm text-ink-muted">{new Date(t.createdAt).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="text-xs text-ink-subtle">User invite and token rotation UI lands in the next slice. For now use the seed script on the VPS.</p>
    </div>
  );
}
