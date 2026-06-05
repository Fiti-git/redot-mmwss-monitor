import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

WPMUDEV_API_KEY = os.environ.get("WPMUDEV_API_KEY")
CLOUDFLARE_API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN")

missing = [k for k, v in {
    "WPMUDEV_API_KEY": WPMUDEV_API_KEY,
    "CLOUDFLARE_API_TOKEN": CLOUDFLARE_API_TOKEN,
}.items() if not v]
if missing:
    sys.exit(f"Missing required env vars: {', '.join(missing)}")

print("--- Testing WPMUDEV ---")
r = requests.get(
    "https://wpmudev.com/api/hub/v1/sites",
    headers={
        "Authorization": WPMUDEV_API_KEY,
        "User-Agent": "MssApiClient/1.0",
    }
)
if r.status_code == 200:
    data = r.json()
    sites = data if isinstance(data, list) else data.get("results", [])
    print(f"SUCCESS - Found {len(sites)} sites:")
    for s in sites:
        print(f"  - {s.get('domain') or s.get('name')}")
else:
    print(f"FAILED - Status: {r.status_code} - {r.text}")

print("")
print("--- Testing Cloudflare ---")
r2 = requests.get(
    "https://api.cloudflare.com/client/v4/zones",
    headers={"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}"}
)
if r2.status_code == 200:
    zones = r2.json().get("result", [])
    print(f"SUCCESS - Found {len(zones)} domains:")
    for z in zones:
        print(f"  - {z.get('name')} ({z.get('status')})")
else:
    print(f"FAILED - Status: {r2.status_code} - {r2.text}")
