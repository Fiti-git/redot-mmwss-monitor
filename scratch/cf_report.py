import html
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
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

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


def cf(path, params=None):
    r = requests.get(f"{BASE}{path}", headers=HEADERS, params=params, timeout=30)
    try:
        return r.json()
    except ValueError:
        return {"success": False, "errors": [{"message": f"non-json {r.status_code}"}]}


def cf_graphql(query, variables):
    r = requests.post(f"{BASE}/graphql", headers=HEADERS, json={"query": query, "variables": variables}, timeout=30)
    try:
        return r.json()
    except ValueError:
        return {"errors": [{"message": f"non-json {r.status_code}"}]}


def human_bytes(n):
    if n is None:
        return "n/a"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def fetch_24h(zone_id):
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    frm = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    to = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    res = cf_graphql(GRAPHQL_24H, {"zoneTag": zone_id, "from": frm, "to": to})
    if res.get("errors"):
        return None
    try:
        groups = res["data"]["viewer"]["zones"][0]["httpRequests1hGroups"]
    except (KeyError, IndexError, TypeError):
        return None
    totals = {"requests": 0, "cachedRequests": 0, "bytes": 0, "cachedBytes": 0, "threats": 0}
    for g in groups:
        for k, v in (g.get("sum", {}) or {}).items():
            if k in totals:
                totals[k] += v or 0
    return totals


def collect_zone(zone):
    zid = zone["id"]
    name = zone["name"]
    data = {
        "name": name,
        "id": zid,
        "status": zone.get("status"),
        "plan": zone.get("plan", {}).get("name"),
        "name_servers": zone.get("name_servers", []),
        "issues": [],
    }

    dns = cf(f"/zones/{zid}/dns_records", params={"per_page": 200})
    if dns.get("success"):
        recs = dns["result"]
        data["dns"] = {
            "total": len(recs),
            "by_type": dict(Counter(r["type"] for r in recs)),
            "proxied": sum(1 for r in recs if r.get("proxied")),
            "apex": [
                {"type": r["type"], "name": r["name"], "content": r["content"], "proxied": r.get("proxied", False)}
                for r in recs
                if r["type"] in ("A", "AAAA", "CNAME") and r.get("name") in (name, f"www.{name}")
            ],
            "records": [
                {"type": r["type"], "name": r["name"], "content": r["content"], "proxied": r.get("proxied", False), "ttl": r.get("ttl")}
                for r in recs
            ],
        }

    ssl = cf(f"/zones/{zid}/ssl/certificate_packs", params={"status": "all"})
    next_expiry = None
    if ssl.get("success"):
        for p in ssl["result"]:
            if p.get("status") != "active":
                continue
            for c in p.get("certificates", []) or []:
                exp = c.get("expires_on")
                if exp and (next_expiry is None or exp < next_expiry):
                    next_expiry = exp
    data["ssl_next_expiry"] = next_expiry

    settings = cf(f"/zones/{zid}/settings")
    if settings.get("success"):
        data["settings"] = {i["id"]: i.get("value") for i in settings["result"]}
    else:
        data["settings"] = {}

    data["analytics_24h"] = fetch_24h(zid)

    fw = cf(f"/zones/{zid}/firewall/rules")
    if fw.get("success"):
        rules = fw["result"]
        data["firewall"] = {"total": len(rules), "enabled": sum(1 for r in rules if not r.get("paused"))}
    else:
        data["firewall"] = {"total": 0, "enabled": 0}

    s = data["settings"]
    if s.get("ssl") and s.get("ssl") not in ("strict", "full"):
        data["issues"].append(("warn", f"SSL mode is '{s.get('ssl')}' — consider strict"))
    if s.get("ssl") == "full":
        data["issues"].append(("warn", "SSL mode is 'full' — origin cert not validated"))
    if s.get("always_use_https") == "off":
        data["issues"].append(("crit", "Always Use HTTPS is OFF — plaintext requests reach origin"))
    if s.get("security_level") == "essentially_off":
        data["issues"].append(("crit", "Security level is essentially_off — WAF disabled"))
    if s.get("min_tls_version") in ("1.0", "1.1"):
        data["issues"].append(("warn", f"Minimum TLS is {s.get('min_tls_version')} — below 1.2 baseline"))
    if s.get("brotli") == "off":
        data["issues"].append(("info", "Brotli compression disabled — bandwidth left on the table"))
    if data["firewall"]["enabled"] == 0:
        data["issues"].append(("info", "No custom firewall rules — relying on defaults only"))
    if next_expiry:
        try:
            exp_dt = datetime.strptime(next_expiry[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            days = (exp_dt - datetime.now(timezone.utc)).days
            data["ssl_days_to_expiry"] = days
            if days < 30:
                data["issues"].append(("warn", f"SSL cert expires in {days} days"))
        except Exception:
            data["ssl_days_to_expiry"] = None
    else:
        data["ssl_days_to_expiry"] = None
    if data.get("analytics_24h"):
        a = data["analytics_24h"]
        if a["requests"] > 1000 and a["requests"] and (a["cachedRequests"] / a["requests"]) < 0.20:
            ratio = (a["cachedRequests"] / a["requests"]) * 100
            data["issues"].append(("info", f"Low cache hit ratio ({ratio:.0f}%) — origin doing most of the work"))

    return data


SEVERITY_LABEL = {"crit": "Critical", "warn": "Warning", "info": "Info"}


def render_html(zones, generated_at):
    total_req = sum((z.get("analytics_24h") or {}).get("requests", 0) for z in zones)
    total_threats = sum((z.get("analytics_24h") or {}).get("threats", 0) for z in zones)
    total_bw = sum((z.get("analytics_24h") or {}).get("bytes", 0) for z in zones)
    total_issues = sum(len(z["issues"]) for z in zones)
    crit_count = sum(1 for z in zones for s, _ in z["issues"] if s == "crit")

    parts = []
    parts.append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<title>Cloudflare Zones Report</title>")
    parts.append("""<style>
:root{--bg:#0f1419;--card:#1a1f2e;--border:#2a3142;--text:#e4e7ed;--muted:#8a93a3;--accent:#f6821f;--ok:#26a653;--warn:#f7b500;--crit:#e34c4c;--info:#3b8eea}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.5;font-size:14px}
.container{max-width:1200px;margin:0 auto;padding:32px 24px}
h1{margin:0 0 8px;font-size:28px}
h2{font-size:20px;margin:32px 0 16px;border-bottom:1px solid var(--border);padding-bottom:8px}
h3{font-size:16px;margin:0 0 8px}
.gen{color:var(--muted);font-size:13px;margin-bottom:24px}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:32px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px}
.stat .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px}
.stat .value{font-size:24px;font-weight:600}
.stat.crit .value{color:var(--crit)}
.stat.warn .value{color:var(--warn)}
.zone{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}
.zone-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px}
.zone-name{font-size:18px;font-weight:600}
.zone-name a{color:var(--accent);text-decoration:none}
.tags{display:flex;gap:6px;flex-wrap:wrap}
.tag{background:#2a3142;color:var(--text);padding:3px 8px;border-radius:4px;font-size:12px}
.tag.plan{background:#3a2a1a;color:var(--accent)}
.tag.active{background:#1d3826;color:var(--ok)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:12px}
@media(max-width:720px){.grid{grid-template-columns:1fr}}
.section-title{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:0.5px;margin:0 0 6px}
.kv{display:grid;grid-template-columns:140px 1fr;gap:4px 12px;font-size:13px}
.kv dt{color:var(--muted)}
.kv dd{margin:0}
.metric{font-variant-numeric:tabular-nums}
.issue{display:flex;align-items:flex-start;gap:8px;padding:6px 0;font-size:13px;border-top:1px solid var(--border)}
.issue:first-child{border-top:0}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;flex-shrink:0}
.badge.crit{background:rgba(227,76,76,0.18);color:var(--crit)}
.badge.warn{background:rgba(247,181,0,0.18);color:var(--warn)}
.badge.info{background:rgba(59,142,234,0.18);color:var(--info)}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:500;padding:6px 8px;border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase;letter-spacing:0.5px}
td{padding:6px 8px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:0}
.proxied{color:var(--accent)}
.notproxied{color:var(--muted)}
details{margin-top:12px}
summary{cursor:pointer;color:var(--muted);font-size:13px;padding:4px 0}
summary:hover{color:var(--text)}
.bar{display:inline-block;height:6px;background:var(--border);border-radius:3px;width:100px;vertical-align:middle;margin-left:8px;overflow:hidden}
.bar > div{height:100%;background:var(--ok)}
</style></head><body><div class='container'>""")

    parts.append(f"<h1>Cloudflare Zones Report</h1>")
    parts.append(f"<div class='gen'>Generated {html.escape(generated_at)} &middot; {len(zones)} zones</div>")

    parts.append("<div class='summary'>")
    parts.append(f"<div class='stat'><div class='label'>Zones</div><div class='value'>{len(zones)}</div></div>")
    parts.append(f"<div class='stat'><div class='label'>Requests (24h)</div><div class='value'>{total_req:,}</div></div>")
    parts.append(f"<div class='stat'><div class='label'>Bandwidth (24h)</div><div class='value'>{human_bytes(total_bw)}</div></div>")
    parts.append(f"<div class='stat'><div class='label'>Threats blocked (24h)</div><div class='value'>{total_threats:,}</div></div>")
    cls = "crit" if crit_count else ("warn" if total_issues else "")
    parts.append(f"<div class='stat {cls}'><div class='label'>Issues found</div><div class='value'>{total_issues}</div></div>")
    parts.append("</div>")

    parts.append("<h2>SSL Expiry Timeline</h2>")
    parts.append("<table><thead><tr><th>Zone</th><th>Next expiry</th><th>Days</th></tr></thead><tbody>")
    sorted_by_exp = sorted([z for z in zones if z.get("ssl_next_expiry")], key=lambda z: z["ssl_next_expiry"])
    for z in sorted_by_exp:
        days = z.get("ssl_days_to_expiry")
        cls = "crit" if days is not None and days < 30 else ""
        exp = z["ssl_next_expiry"][:10]
        parts.append(f"<tr><td>{html.escape(z['name'])}</td><td>{html.escape(exp)}</td><td class='{cls}'>{days if days is not None else '?'}</td></tr>")
    parts.append("</tbody></table>")

    parts.append("<h2>Zones</h2>")
    zones_sorted = sorted(zones, key=lambda z: -(z.get("analytics_24h") or {}).get("requests", 0))
    for z in zones_sorted:
        a = z.get("analytics_24h") or {}
        s = z.get("settings", {}) or {}
        d = z.get("dns", {}) or {}
        parts.append("<div class='zone'>")
        parts.append("<div class='zone-head'>")
        parts.append(f"<div class='zone-name'><a href='https://{html.escape(z['name'])}' target='_blank'>{html.escape(z['name'])}</a></div>")
        parts.append("<div class='tags'>")
        parts.append(f"<span class='tag plan'>{html.escape(z.get('plan') or 'n/a')}</span>")
        if z.get("status") == "active":
            parts.append("<span class='tag active'>active</span>")
        else:
            parts.append(f"<span class='tag'>{html.escape(z.get('status') or 'unknown')}</span>")
        parts.append("</div></div>")

        parts.append("<div class='grid'>")

        parts.append("<div><div class='section-title'>Traffic (last 24h)</div><dl class='kv'>")
        if a:
            req = a["requests"]
            cached = a["cachedRequests"]
            hit_ratio = (cached / req * 100) if req else 0
            parts.append(f"<dt>Requests</dt><dd class='metric'>{req:,}</dd>")
            parts.append(f"<dt>Cached</dt><dd class='metric'>{cached:,} ({hit_ratio:.1f}%)<span class='bar'><div style='width:{min(hit_ratio,100):.0f}%'></div></span></dd>")
            parts.append(f"<dt>Bandwidth</dt><dd class='metric'>{human_bytes(a['bytes'])}</dd>")
            parts.append(f"<dt>Threats blocked</dt><dd class='metric'>{a['threats']:,}</dd>")
        else:
            parts.append("<dt colspan='2'>Analytics unavailable</dt>")
        parts.append("</dl></div>")

        parts.append("<div><div class='section-title'>Configuration</div><dl class='kv'>")
        parts.append(f"<dt>SSL mode</dt><dd>{html.escape(str(s.get('ssl','?')))}</dd>")
        parts.append(f"<dt>Always HTTPS</dt><dd>{html.escape(str(s.get('always_use_https','?')))}</dd>")
        parts.append(f"<dt>Min TLS</dt><dd>{html.escape(str(s.get('min_tls_version','?')))}</dd>")
        parts.append(f"<dt>Security level</dt><dd>{html.escape(str(s.get('security_level','?')))}</dd>")
        parts.append(f"<dt>Brotli</dt><dd>{html.escape(str(s.get('brotli','?')))}</dd>")
        parts.append(f"<dt>Cache level</dt><dd>{html.escape(str(s.get('cache_level','?')))}</dd>")
        parts.append(f"<dt>Dev mode</dt><dd>{html.escape(str(s.get('development_mode','?')))}</dd>")
        parts.append(f"<dt>FW rules</dt><dd>{z['firewall']['enabled']} enabled / {z['firewall']['total']} total</dd>")
        parts.append("</dl></div>")

        parts.append("</div>")

        parts.append("<div><div class='section-title'>DNS & Apex</div><dl class='kv'>")
        if d:
            parts.append(f"<dt>Records</dt><dd>{d['total']} total ({', '.join(f'{t}:{c}' for t,c in sorted(d['by_type'].items(), key=lambda x:-x[1]))})</dd>")
            parts.append(f"<dt>Proxied</dt><dd>{d['proxied']} / {d['total']}</dd>")
            for r in d.get("apex", [])[:4]:
                arrow = "<span class='proxied'>proxied</span>" if r["proxied"] else "<span class='notproxied'>direct</span>"
                parts.append(f"<dt>{html.escape(r['type'])} {html.escape(r['name'])}</dt><dd>{html.escape(r['content'])} {arrow}</dd>")
        parts.append("</dl></div>")

        if z["issues"]:
            parts.append("<div style='margin-top:12px'><div class='section-title'>Issues</div>")
            for sev, msg in z["issues"]:
                parts.append(f"<div class='issue'><span class='badge {sev}'>{html.escape(SEVERITY_LABEL[sev])}</span><span>{html.escape(msg)}</span></div>")
            parts.append("</div>")

        if d.get("records"):
            parts.append("<details><summary>All DNS records (" + str(d["total"]) + ")</summary>")
            parts.append("<table><thead><tr><th>Type</th><th>Name</th><th>Content</th><th>Proxied</th><th>TTL</th></tr></thead><tbody>")
            for r in sorted(d["records"], key=lambda r: (r["type"], r["name"])):
                px = "<span class='proxied'>yes</span>" if r["proxied"] else "<span class='notproxied'>no</span>"
                parts.append(f"<tr><td>{html.escape(r['type'])}</td><td>{html.escape(r['name'])}</td><td>{html.escape(str(r['content'])[:80])}</td><td>{px}</td><td>{r.get('ttl','?')}</td></tr>")
            parts.append("</tbody></table></details>")

        parts.append("</div>")

    parts.append("</div></body></html>")
    return "".join(parts)


def main():
    print("Fetching zones...")
    zlist = cf("/zones", params={"per_page": 50})
    if not zlist.get("success"):
        sys.exit(f"Failed: {zlist}")
    zones_raw = zlist["result"]
    print(f"Collecting data for {len(zones_raw)} zones...")
    zones = []
    for z in zones_raw:
        print(f"  - {z['name']}")
        zones.append(collect_zone(z))

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html_path = "cf_report.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(render_html(zones, generated_at))

    json_path = "cf_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": generated_at, "zones": zones}, f, indent=2, default=str)

    abs_html = os.path.abspath(html_path)
    print(f"\nReport written:")
    print(f"  HTML: {abs_html}")
    print(f"  JSON: {os.path.abspath(json_path)}")
    print(f"\nOpen the HTML in a browser: start \"\" \"{abs_html}\"")


if __name__ == "__main__":
    main()
