"use client";

import { Suspense, useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-surface-alt" />}>
      <LoginForm />
    </Suspense>
  );
}

function LoginForm() {
  const router = useRouter();
  const search = useSearchParams();
  const callbackUrl = search?.get("callbackUrl") || "/mmwss/dashboard";
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const res = await signIn("credentials", {
      email: email.trim().toLowerCase(),
      password,
      redirect: false,
    });
    setLoading(false);
    if (res?.error) {
      setError("Invalid email or password");
      return;
    }
    router.push(callbackUrl);
    router.refresh();
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-surface-alt px-4">
      <div className="w-full max-w-md">
        <div className="flex items-center justify-center mb-6 gap-3">
          <div className="w-12 h-12 rounded-lg bg-brand flex items-center justify-center text-white font-bold text-2xl">
            R
          </div>
          <div>
            <div className="text-2xl font-bold text-ink leading-none">MMWSS</div>
            <div className="text-xs text-ink-muted">by Redot Global</div>
          </div>
        </div>
        <div className="bg-white border border-border rounded-lg p-6 shadow-tremor-card">
          <h1 className="text-xl font-semibold text-ink mb-1">Sign in</h1>
          <p className="text-sm text-ink-muted mb-6">Internal access only.</p>
          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Email</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3 py-2 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-brand focus:border-transparent text-ink"
                autoComplete="email"
                autoFocus
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-ink mb-1">Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-brand focus:border-transparent text-ink"
                autoComplete="current-password"
              />
            </div>
            {error && (
              <div className="text-sm text-brand bg-brand-50 border border-brand-200 rounded-md px-3 py-2">{error}</div>
            )}
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-brand hover:bg-brand-600 text-white font-medium py-2.5 rounded-md transition disabled:opacity-60"
            >
              {loading ? "Signing in..." : "Sign in"}
            </button>
          </form>
        </div>
        <p className="text-center text-xs text-ink-subtle mt-6">
          MMWSS — Security & uptime monitoring · {new Date().getFullYear()}
        </p>
      </div>
    </div>
  );
}
