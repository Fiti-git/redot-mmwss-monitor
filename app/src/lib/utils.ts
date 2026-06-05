import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function humanBytes(n: number | bigint | null | undefined): string {
  if (n === null || n === undefined) return "n/a";
  let num = typeof n === "bigint" ? Number(n) : n;
  for (const unit of ["B", "KB", "MB", "GB", "TB"]) {
    if (num < 1024) return `${num.toFixed(1)} ${unit}`;
    num /= 1024;
  }
  return `${num.toFixed(1)} PB`;
}

export function formatNumber(n: number | bigint | null | undefined): string {
  if (n === null || n === undefined) return "—";
  return new Intl.NumberFormat("en-US").format(typeof n === "bigint" ? Number(n) : n);
}
