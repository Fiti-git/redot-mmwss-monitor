"""JSON endpoints.

The /api/fix one-click Cloudflare apply endpoint was removed.
Fixes are now applied MANUALLY outside the platform and recorded in the
change log so engineers retain full control over what runs against MMWSS
production. The platform detects, recommends and audits — it does not
mutate client infrastructure.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
