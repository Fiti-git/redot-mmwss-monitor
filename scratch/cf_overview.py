import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN")
if not TOKEN:
    sys.exit("Missing CLOUDFLARE_API_TOKEN")

BASE = "https://api.cloudflare.com/client/v4"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
}


def cf(path, params=None):
    r = requests.get(f"{BASE}{path}", headers=HEADERS, params=params, timeout=30)
    try:
        data = r.json()
    except ValueError:
        return {"_status": r.status_code, "_text": r.text[:200]}
    return data


GRAPHQL_24H = """
query ($zoneTag: String!, $from: Time!, $to: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      httpRequests1hGroups(
        limit: 24,
        filter: {datetime_geq: $from, datetime_leq: $to}
      ) {
        sum {
          requests
          cachedRequests
          bytes
          cachedBytes
          threats
        }
      }
    }
  }
}
"""


def cf_graphql(query, variables):
    r = requests.post(
        "https://api.cloudflare.com/client/v4/graphql",
        headers=HEADERS,
        json={"query": query, "variables": variables},
        timeout=30,
    )
    try:
        return r.json()
    except ValueError:
        return {"errors": [{"message": f"non-json response {r.status_code}"}]}


def fetch_24h_analytics(zone_id):
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    frm = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    to = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    res = cf_graphql(GRAPHQL_24H, {"zoneTag": zone_id, "from": frm, "to": to})
    if res.get("errors"):
        return None, res["errors"][0].get("message", "unknown")
    try:
        groups = res["data"]["viewer"]["zones"][0]["httpRequests1hGroups"]
    except (KeyError, IndexError, TypeError):
        return None, "no data"
    totals = {"requests": 0, "cachedRequests": 0, "bytes": 0, "cachedBytes": 0, "threats": 0}
    for g in groups:
        s = g.get("sum", {})
        for k in totals:
            totals[k] += s.get(k, 0) or 0
    return totals, None


def human_bytes(n):
    if n is None:
        return "n/a"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def fmt(label, value):
    return f"    {label:<22} {value}"


def zone_snapshot(zone, collected):
    zid = zone["id"]
    name = zone["name"]
    entry = {"zone": name, "id": zid, "status": zone.get("status"), "plan": zone.get("plan", {}).get("name")}
    print(f"\n=== {name} ===")
    print(fmt("Zone ID", zid))
    print(fmt("Status", zone.get("status")))
    print(fmt("Plan", zone.get("plan", {}).get("name")))
    print(fmt("Name servers", ", ".join(zone.get("name_servers", []) or [])))

    dns = cf(f"/zones/{zid}/dns_records", params={"per_page": 200})
    if dns.get("success"):
        records = dns.get("result", [])
        by_type = Counter(r["type"] for r in records)
        print(fmt("DNS records", f"{len(records)} total | " + ", ".join(f"{t}:{c}" for t, c in by_type.most_common())))
        proxied = sum(1 for r in records if r.get("proxied"))
        print(fmt("Proxied (orange)", f"{proxied} / {len(records)}"))
        a_records = [r for r in records if r["type"] in ("A", "AAAA", "CNAME") and r.get("name") in (name, f"www.{name}")]
        for r in a_records[:4]:
            arrow = "P" if r.get("proxied") else "."
            print(fmt(f"  {r['type']} {r['name']}", f"-> {r['content']} [{arrow}]"))
        entry["dns"] = {"total": len(records), "by_type": dict(by_type), "proxied": proxied}
    else:
        print(fmt("DNS records", f"ERROR {dns.get('errors')}"))

    ssl = cf(f"/zones/{zid}/ssl/certificate_packs", params={"status": "all"})
    if ssl.get("success"):
        packs = ssl.get("result", [])
        active = [p for p in packs if p.get("status") == "active"]
        soonest = None
        if active:
            for p in active:
                for c in p.get("certificates", []) or []:
                    exp = c.get("expires_on")
                    if exp and (soonest is None or exp < soonest):
                        soonest = exp
            print(fmt("SSL packs active", f"{len(active)} | next expiry: {soonest or 'unknown'}"))
        else:
            print(fmt("SSL packs active", "none"))
        entry["ssl"] = {"active_packs": len(active), "next_expiry": soonest}
    else:
        print(fmt("SSL packs", f"ERROR {ssl.get('errors')}"))

    settings = cf(f"/zones/{zid}/settings")
    if settings.get("success"):
        s = {item["id"]: item.get("value") for item in settings.get("result", [])}
        wanted = ["ssl", "always_use_https", "security_level", "development_mode",
                  "cache_level", "browser_cache_ttl", "min_tls_version", "brotli"]
        labels = {"ssl": "SSL mode", "always_use_https": "Always use HTTPS",
                  "security_level": "Security level", "development_mode": "Dev mode",
                  "cache_level": "Cache level", "browser_cache_ttl": "Browser cache TTL",
                  "min_tls_version": "Min TLS version", "brotli": "Brotli"}
        for k in wanted:
            print(fmt(labels[k], s.get(k)))
        entry["settings"] = {k: s.get(k) for k in wanted}
    else:
        print(fmt("Settings", f"ERROR {settings.get('errors')}"))

    totals, err = fetch_24h_analytics(zid)
    if totals:
        req = totals["requests"]
        cached = totals["cachedRequests"]
        hit_ratio = (cached / req * 100) if req else 0
        print(fmt("[24h] Requests", f"{req:,} (cached {cached:,}, hit {hit_ratio:.1f}%)"))
        print(fmt("[24h] Bandwidth", f"{human_bytes(totals['bytes'])} (cached {human_bytes(totals['cachedBytes'])})"))
        print(fmt("[24h] Threats", f"{totals['threats']:,}"))
        entry["analytics_24h"] = totals
    else:
        print(fmt("[24h] Analytics", f"unavailable ({err})"))
        entry["analytics_24h"] = None

    fw = cf(f"/zones/{zid}/firewall/rules")
    if fw.get("success"):
        rules = fw.get("result", [])
        enabled = sum(1 for r in rules if not r.get("paused"))
        print(fmt("Firewall rules", f"{enabled} enabled / {len(rules)} total"))
        entry["firewall"] = {"total": len(rules), "enabled": enabled}

    collected.append(entry)


def main():
    zones = cf("/zones", params={"per_page": 50})
    if not zones.get("success"):
        sys.exit(f"Failed to list zones: {zones}")
    results = zones.get("result", [])
    print(f"Found {len(results)} zones. Pulling snapshot for each...")
    collected = []
    for z in results:
        zone_snapshot(z, collected)

    out_path = "cf_overview.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "zones": collected}, f, indent=2)
    print(f"\nExported snapshot to {out_path}")
    print("Done.")


if __name__ == "__main__":
    main()
