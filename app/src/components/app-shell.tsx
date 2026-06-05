"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import { Activity, AlertTriangle, BarChart3, FileText, Globe, LogOut, Settings, ShieldCheck } from "lucide-react";

import { cn } from "@/lib/utils";

const nav = [
  { href: "/dashboard", label: "Overview", icon: BarChart3 },
  { href: "/zones", label: "Zones", icon: Globe },
  { href: "/incidents", label: "Incidents", icon: AlertTriangle },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/uptime", label: "Uptime", icon: Activity },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname() || "";
  const { data: session } = useSession();
  const user = session?.user as any;

  return (
    <div className="min-h-screen flex bg-surface-alt">
      {/* Sidebar */}
      <aside className="w-64 bg-white border-r border-border flex flex-col">
        <div className="px-5 py-5 border-b border-border flex items-center gap-3">
          <div className="w-9 h-9 rounded-md bg-brand flex items-center justify-center text-white font-bold">R</div>
          <div>
            <div className="text-base font-semibold text-ink leading-none">MMWSS</div>
            <div className="text-xs text-ink-muted mt-0.5">Redot Global</div>
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-0.5">
          {nav.map((item) => {
            const active = pathname.startsWith(`/mmwss${item.href}`) || pathname === item.href;
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition",
                  active
                    ? "bg-brand-50 text-brand-700 font-medium"
                    : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                )}
              >
                <Icon size={16} />
                {item.label}
              </Link>
            );
          })}
        </nav>
        {user?.role === "admin" && (
          <div className="px-3 pb-2">
            <Link
              href="/settings"
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition",
                pathname.startsWith("/mmwss/settings")
                  ? "bg-brand-50 text-brand-700 font-medium"
                  : "text-ink-muted hover:bg-surface-alt hover:text-ink"
              )}
            >
              <Settings size={16} /> Settings
            </Link>
          </div>
        )}
        <div className="px-4 py-3 border-t border-border">
          <div className="text-xs text-ink-subtle">Signed in as</div>
          <div className="text-sm text-ink truncate" title={user?.email}>{user?.email || "—"}</div>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[10px] uppercase tracking-wide bg-surface-alt text-ink-muted px-1.5 py-0.5 rounded">
              {user?.role || "viewer"}
            </span>
            <button
              onClick={() => signOut({ callbackUrl: "/mmwss/login" })}
              className="ml-auto text-ink-muted hover:text-brand text-xs flex items-center gap-1"
            >
              <LogOut size={12} /> Sign out
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col">
        <header className="h-14 bg-white border-b border-border px-6 flex items-center">
          <div className="flex items-center gap-2 text-sm text-ink-muted">
            <ShieldCheck size={16} className="text-brand" />
            Security & uptime monitor
          </div>
        </header>
        <div className="flex-1 p-6 overflow-auto">{children}</div>
      </main>
    </div>
  );
}
