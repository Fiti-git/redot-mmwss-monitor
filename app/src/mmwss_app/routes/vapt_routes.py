"""VAPT report + finding routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth, queries, vapt

router = APIRouter()
templates: Jinja2Templates = None  # type: ignore


def _client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


@router.get("/vapt", response_class=HTMLResponse)
def vapt_home(request: Request, user: dict = Depends(auth.require_user)):
    reports = vapt.list_reports()
    findings = vapt.list_findings()  # all, for the top-level open list
    counters = vapt.counters()
    return templates.TemplateResponse(
        "vapt_home.html",
        {"request": request, "user": user, "active": "vapt",
         "reports": reports, "findings": findings, "counters": counters,
         "sev_label": vapt.SEVERITY_LABEL, "status_label": vapt.STATUS_LABEL},
    )


@router.get("/vapt/reports/new", response_class=HTMLResponse)
def vapt_report_new(request: Request, user: dict = Depends(auth.require_admin)):
    return templates.TemplateResponse(
        "vapt_report_new.html",
        {"request": request, "user": user, "active": "vapt"},
    )


@router.post("/vapt/reports/new")
def vapt_report_create(
    request: Request,
    title: str = Form(...),
    vendor: str = Form(""),
    report_date: str = Form(""),
    notes: str = Form(""),
    user: dict = Depends(auth.require_admin),
):
    rid = vapt.create_report(
        title=title, vendor=vendor or None, report_date=report_date or None,
        notes=notes or None, uploaded_by_user_id=int(user["id"]),
    )
    auth.record_audit(int(user["id"]), user["email"], "vapt_report.create",
                      ip=_client_ip(request), target_type="vapt_report", target_id=str(rid),
                      details={"title": title, "vendor": vendor})
    return RedirectResponse(f"/mmwss/vapt/reports/{rid}", status_code=303)


@router.get("/vapt/reports/{report_id}", response_class=HTMLResponse)
def vapt_report_detail(report_id: int, request: Request, user: dict = Depends(auth.require_user)):
    rep = vapt.get_report(report_id)
    if not rep:
        raise HTTPException(404, "Report not found")
    findings = vapt.list_findings(report_id=report_id)
    return templates.TemplateResponse(
        "vapt_report_detail.html",
        {"request": request, "user": user, "active": "vapt",
         "report": rep, "findings": findings,
         "sev_label": vapt.SEVERITY_LABEL, "status_label": vapt.STATUS_LABEL},
    )


@router.get("/vapt/reports/{report_id}/findings/new", response_class=HTMLResponse)
def vapt_finding_new(report_id: int, request: Request, user: dict = Depends(auth.require_admin)):
    rep = vapt.get_report(report_id)
    if not rep:
        raise HTTPException(404, "Report not found")
    zones = queries.zones_with_status()
    return templates.TemplateResponse(
        "vapt_finding_new.html",
        {"request": request, "user": user, "active": "vapt",
         "report": rep, "zones": zones,
         "sev_label": vapt.SEVERITY_LABEL,
         "sla_by_sev": vapt.SLA_BY_SEVERITY},
    )


@router.post("/vapt/reports/{report_id}/findings/new")
def vapt_finding_create(
    report_id: int, request: Request,
    title: str = Form(...),
    severity: str = Form(...),
    description: str = Form(""),
    vendor_finding_id: str = Form(""),
    cve_reference: str = Form(""),
    cvss_score: str = Form(""),
    owasp_category: str = Form(""),
    affected_url: str = Form(""),
    proof_text: str = Form(""),
    zone_id: str = Form(""),
    auto_create_ticket: str = Form(""),  # "on" if checked
    user: dict = Depends(auth.require_admin),
):
    rep = vapt.get_report(report_id)
    if not rep:
        raise HTTPException(404, "Report not found")
    zid = int(zone_id) if zone_id.strip().isdigit() else None
    cvss = float(cvss_score) if cvss_score.strip() else None
    fid, tid = vapt.create_finding(
        report_id=report_id, title=title, severity=severity,
        description=description, vendor_finding_id=vendor_finding_id,
        cve_reference=cve_reference, cvss_score=cvss,
        owasp_category=owasp_category, affected_url=affected_url,
        proof_text=proof_text, zone_id=zid,
        auto_create_ticket=(auto_create_ticket == "on"),
        opened_by_user_id=int(user["id"]),
    )
    auth.record_audit(int(user["id"]), user["email"], "vapt_finding.create",
                      ip=_client_ip(request), target_type="vapt_finding", target_id=str(fid),
                      details={"severity": severity, "report_id": report_id,
                               "auto_ticket_id": tid})
    return RedirectResponse(f"/mmwss/vapt/findings/{fid}", status_code=303)


@router.get("/vapt/findings/{finding_id}", response_class=HTMLResponse)
def vapt_finding_detail(finding_id: int, request: Request, user: dict = Depends(auth.require_user)):
    f = vapt.get_finding(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return templates.TemplateResponse(
        "vapt_finding_detail.html",
        {"request": request, "user": user, "active": "vapt", "f": f,
         "sev_label": vapt.SEVERITY_LABEL, "status_label": vapt.STATUS_LABEL,
         "sla_by_sev": vapt.SLA_BY_SEVERITY},
    )


@router.post("/vapt/findings/{finding_id}/update")
def vapt_finding_update(
    finding_id: int, request: Request,
    status: str = Form(...),
    remediation_plan: str = Form(""),
    remediation_evidence: str = Form(""),
    user: dict = Depends(auth.require_admin),
):
    vapt.update_finding_status(
        finding_id, status,
        remediation_plan=remediation_plan,
        remediation_evidence=remediation_evidence,
        engineer_user_id=int(user["id"]),
    )
    auth.record_audit(int(user["id"]), user["email"], "vapt_finding.update",
                      ip=_client_ip(request), target_type="vapt_finding", target_id=str(finding_id),
                      details={"status": status, "has_plan": bool(remediation_plan),
                               "has_evidence": bool(remediation_evidence)})
    return RedirectResponse(f"/mmwss/vapt/findings/{finding_id}", status_code=303)
