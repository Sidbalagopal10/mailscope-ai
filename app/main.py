import json
from collections import defaultdict

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session

from app.config import settings
from app.api.ml_routes import router as ml_router
from app.database.database import Base, engine, get_database
from app.gmail.scanner import scan_recent_emails
from app.models.scan_result import ScanResult
from app.services.risk_engine import analyze_url
from app.services.scan_service import save_scan_result
from app.api.hybrid_routes import router as hybrid_router
from app.api.feedback_routes import router as feedback_router
from app.api.email_content_routes import router as email_content_router
from app.api.gmail_risk_routes import router as gmail_risk_router
from app.api.monitor_routes import router as monitor_router
from app.api.continuous_learning_routes import router as continuous_learning_router
from app.api.header_analysis_routes import router as header_analysis_router
from app.api.daily_report_routes import router as daily_report_router
from app.api.gmail_account_routes import router as gmail_account_router
from app.api.deep_inspection_routes import router as deep_inspection_router
from app.api.domain_trust_routes import router as domain_trust_router
from app.api.organization_intelligence_routes import router as organization_intelligence_router
from app.api.domain_intelligence_routes import router as domain_intelligence_router
from app.api.certificate_transparency_routes import router as certificate_transparency_router
from app.api.dns_intelligence_routes import router as dns_intelligence_router
from app.api.unified_domain_profile_routes import router as unified_domain_profile_router
from app.api.global_brand_intelligence_routes import router as global_brand_intelligence_router
from app.api.ip_asn_intelligence_routes import router as ip_asn_intelligence_router
from app.api.threatfox_routes import router as threatfox_router
from app.api.email_authentication_routes import router as email_authentication_router
from app.api.email_context_routes import router as email_context_router
from app.api.gmail_observation_routes import router as gmail_observation_router
from app.api.gmail_label_plan_routes import router as gmail_label_plan_router
from app.api.gmail_label_execution_routes import router as gmail_label_execution_router
from app.api.gmail_feedback_routes import router as gmail_feedback_router
from app.api.model_governance_routes import router as model_governance_router
from app.api.virustotal_routes import router as virustotal_router
from app.api.unified_email_pipeline_routes import router as unified_email_pipeline_router
from app.api.evaluation_routes import router as evaluation_router
from app.api.attachment_security_routes import router as attachment_security_router
from app.api.campaign_routes import router as campaign_router
from app.api.threat_hunting_routes import router as threat_hunting_router
from app.api.case_graph_routes import router as case_graph_router
from app.api.soc_copilot_routes import router as soc_copilot_router


Base.metadata.create_all(bind=engine)


from app.api.identity_routes import router as identity_router

from app.api.analyst_routes import router as analyst_router

app = FastAPI(
    title=settings.app_name,
    description=(
        "A Gmail phishing-detection platform with "
        "explainable severity scoring."
    ),
    version="0.6.0",
)

app.include_router(identity_router)
app.include_router(analyst_router)
app.include_router(ml_router)
app.include_router(hybrid_router)
app.include_router(feedback_router)
app.include_router(campaign_router)
app.include_router(threat_hunting_router)
app.include_router(case_graph_router)
app.include_router(soc_copilot_router)


def deserialize_reasons(value):
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []


def severity_to_risk_level(severity):
    if severity >= 8:
        return "CRITICAL"

    if severity >= 6:
        return "HIGH"

    if severity >= 4:
        return "MODERATE"

    if severity >= 2:
        return "GUARDED"

    return "LOW"


@app.get("/")
def root():
    return {
        "project": settings.app_name,
        "version": "0.6.0",
        "status": "running",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "environment": settings.app_env,
    }


@app.get("/analyze-url")
def analyze_url_endpoint(
    url: str = Query(
        ...,
        description="URL to analyze",
    ),
    database: Session = Depends(get_database),
):
    result = analyze_url(url)

    record = save_scan_result(
        database=database,
        result=result,
        source="manual",
    )

    return {
        "scan_id": record.id,
        "url": result.url,
        "severity": result.severity,
        "risk_level": result.risk_level,
        "is_suspicious": result.is_suspicious,
        "reasons": result.reasons,
        "source": record.source,
        "scanned_at": record.scanned_at,
    }


@app.post("/scan-gmail")
def scan_gmail_endpoint(
    limit: int = Query(
        5,
        ge=1,
        le=50,
        description="Number of recent Gmail messages to scan",
    ),
):
    try:
        summary = scan_recent_emails(
            max_messages=limit
        )

        return {
            "status": "completed",
            "message": "Gmail scan completed successfully.",
            "summary": summary,
        }

    except FileNotFoundError as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Gmail credentials were not found. "
                "Check credentials.json and token.json."
            ),
        ) from error

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Gmail scan failed: {str(error)}",
        ) from error


@app.get("/scan-history")
def get_scan_history(
    limit: int = Query(
        200,
        ge=1,
        le=1000,
    ),
    database: Session = Depends(get_database),
):
    records = (
        database.query(ScanResult)
        .order_by(ScanResult.scanned_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": record.id,
            "url": record.url,
            "domain": record.domain,
            "severity": record.severity,
            "risk_level": record.risk_level,
            "is_suspicious": record.is_suspicious,
            "reasons": deserialize_reasons(
                record.reasons
            ),
            "source": record.source,
            "gmail_message_id": record.gmail_message_id,
            "email_subject": record.email_subject,
            "email_sender": record.email_sender,
            "scanned_at": record.scanned_at,
        }
        for record in records
    ]


@app.get("/email-summary")
def get_email_summary(
    limit: int = Query(
        100,
        ge=1,
        le=500,
    ),
    database: Session = Depends(get_database),
):
    records = (
        database.query(ScanResult)
        .filter(
            ScanResult.source == "gmail",
            ScanResult.gmail_message_id.isnot(None),
        )
        .order_by(ScanResult.scanned_at.desc())
        .all()
    )

    grouped_records = defaultdict(list)

    for record in records:
        grouped_records[
            record.gmail_message_id
        ].append(record)

    email_summaries = []

    for gmail_message_id, message_records in grouped_records.items():
        newest_record = max(
            message_records,
            key=lambda record: record.scanned_at,
        )

        total_links = len(message_records)

        suspicious_links = sum(
            1
            for record in message_records
            if record.is_suspicious
        )

        highest_severity = max(
            record.severity
            for record in message_records
        )

        suspicious_domains = sorted(
            {
                record.domain
                for record in message_records
                if record.is_suspicious
            }
        )

        all_reasons = []

        for record in message_records:
            for reason in deserialize_reasons(
                record.reasons
            ):
                if reason not in all_reasons:
                    all_reasons.append(reason)

        email_summaries.append(
            {
                "gmail_message_id": gmail_message_id,
                "email_subject": newest_record.email_subject,
                "email_sender": newest_record.email_sender,
                "total_links": total_links,
                "suspicious_links": suspicious_links,
                "highest_severity": highest_severity,
                "overall_risk_level": severity_to_risk_level(
                    highest_severity
                ),
                "is_suspicious": suspicious_links > 0,
                "suspicious_domains": suspicious_domains,
                "reasons": all_reasons,
                "scanned_at": newest_record.scanned_at,
            }
        )

    email_summaries.sort(
        key=lambda item: item["scanned_at"],
        reverse=True,
    )

    return email_summaries[:limit]


@app.get("/dashboard-summary")
def get_dashboard_summary(
    database: Session = Depends(get_database),
):
    records = database.query(ScanResult).all()

    if not records:
        return {
            "total_scans": 0,
            "suspicious_scans": 0,
            "average_severity": 0,
            "highest_severity": 0,
            "gmail_emails_scanned": 0,
            "suspicious_emails": 0,
            "risk_distribution": {},
        }

    total_scans = len(records)

    suspicious_scans = sum(
        1
        for record in records
        if record.is_suspicious
    )

    average_severity = round(
        sum(
            record.severity
            for record in records
        ) / total_scans,
        2,
    )

    highest_severity = max(
        record.severity
        for record in records
    )

    risk_distribution = {}

    for record in records:
        risk_distribution[record.risk_level] = (
            risk_distribution.get(
                record.risk_level,
                0,
            )
            + 1
        )

    gmail_records = [
        record
        for record in records
        if (
            record.source == "gmail"
            and record.gmail_message_id
        )
    ]

    gmail_message_ids = {
        record.gmail_message_id
        for record in gmail_records
    }

    suspicious_message_ids = {
        record.gmail_message_id
        for record in gmail_records
        if record.is_suspicious
    }

    return {
        "total_scans": total_scans,
        "suspicious_scans": suspicious_scans,
        "average_severity": average_severity,
        "highest_severity": highest_severity,
        "gmail_emails_scanned": len(
            gmail_message_ids
        ),
        "suspicious_emails": len(
            suspicious_message_ids
        ),
        "risk_distribution": risk_distribution,
    }

app.include_router(email_content_router)

app.include_router(gmail_risk_router)

app.include_router(monitor_router)

app.include_router(continuous_learning_router)

app.include_router(header_analysis_router)

app.include_router(daily_report_router)

app.include_router(gmail_account_router)

app.include_router(deep_inspection_router)

app.include_router(domain_trust_router)

app.include_router(organization_intelligence_router)

app.include_router(domain_intelligence_router)

app.include_router(certificate_transparency_router)

app.include_router(dns_intelligence_router)

app.include_router(unified_domain_profile_router)

app.include_router(global_brand_intelligence_router)

app.include_router(ip_asn_intelligence_router)

app.include_router(threatfox_router)

app.include_router(email_authentication_router)

app.include_router(email_context_router)

app.include_router(gmail_observation_router)

app.include_router(gmail_label_plan_router)

app.include_router(gmail_label_execution_router)

app.include_router(gmail_feedback_router)

app.include_router(model_governance_router)

app.include_router(virustotal_router)

app.include_router(unified_email_pipeline_router)

app.include_router(evaluation_router)

app.include_router(attachment_security_router)
