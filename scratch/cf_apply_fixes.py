import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN")
if not TOKEN:
    sys.exit("Missing CLOUDFLARE_API_TOKEN")

BASE = "https://api.cloudflare.com/client/v4"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

FIXES = {
    "wakaf.sg": [
        ("ssl", "strict", "Enforce strict origin cert validation"),
        ("always_use_https", "on", "Force all HTTP requests to HTTPS"),
        ("brotli", "on", "Enable Brotli compression"),
    ],
    "ourmasjid.sg": [
        ("security_level", "medium", "Raise security level from essentially_off"),
    ],
    "ourwakaf.sg": [
        ("min_tls_version", "1.2", "Disallow TLS 1.0/1.1 connections"),
    ],
    "sharedservices.sg": [
        ("min_tls_version", "1.2", "Disallow TLS 1.1 connections"),
    ],
    "learnislam.sg": [
        ("brotli", "on", "Enable Brotli compression"),
    ],
    "ourmadrasah.sg": [
        ("brotli", "on", "Enable Brotli compression"),
    ],
}


def cf_get(path):
    return requests.get(f"{BASE}{path}", headers=HEADERS, timeout=30).json()


def cf_patch(path, body):
    return requests.patch(f"{BASE}{path}", headers=HEADERS, json=body, timeout=30).json()


def list_zones_by_name():
    r = cf_get("/zones?per_page=50")
    if not r.get("success"):
        sys.exit(f"Failed to list zones: {r}")
    return {z["name"]: z["id"] for z in r["result"]}


def main():
    apply = "--apply" in sys.argv
    mode = "APPLY" if apply else "DRY-RUN"
    print(f"=== {mode} ===\n")

    zones = list_zones_by_name()
    total = sum(len(v) for v in FIXES.values())
    print(f"Planned changes: {total} across {len(FIXES)} zones\n")

    success = 0
    skipped = 0
    failed = 0

    for zone_name, changes in FIXES.items():
        zid = zones.get(zone_name)
        if not zid:
            print(f"[skip] {zone_name}: zone not found in account")
            skipped += len(changes)
            continue
        print(f"--- {zone_name} ({zid}) ---")
        for setting_id, new_value, reason in changes:
            current = cf_get(f"/zones/{zid}/settings/{setting_id}")
            cur_val = current.get("result", {}).get("value") if current.get("success") else "?"
            if cur_val == new_value:
                print(f"  [ok]     {setting_id:<22} already = {new_value!r}")
                skipped += 1
                continue
            arrow = "->"
            print(f"  [change] {setting_id:<22} {cur_val!r} {arrow} {new_value!r}  ({reason})")
            if not apply:
                continue
            res = cf_patch(f"/zones/{zid}/settings/{setting_id}", {"value": new_value})
            if res.get("success"):
                print(f"  [done]   {setting_id:<22} applied")
                success += 1
            else:
                errs = res.get("errors", [])
                msg = errs[0].get("message") if errs else "?"
                print(f"  [FAIL]   {setting_id:<22} {msg}")
                failed += 1
        print()

    print("=" * 40)
    if apply:
        print(f"Applied: {success} | Skipped: {skipped} | Failed: {failed}")
    else:
        print(f"DRY-RUN complete. Would change: {total - skipped} | Already correct: {skipped}")
        print("Re-run with --apply to actually make these changes.")


if __name__ == "__main__":
    main()
