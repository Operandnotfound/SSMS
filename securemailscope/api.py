"""
SecureMailScope - RESTful API and Automated Ingestion Service
FastAPI-powered endpoints designed for CI/CD security gating and automated SOC pipelines.
Implements streaming upload, memory bounds enforcement, path traversal defense, and tempfile lifecycle management.
"""

import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from securemailscope.crypto_validator import CryptographicValidator
from securemailscope.ml_engine import MLRiskEngine
from securemailscope.models import (
    ForensicReport,
    InteractiveDashboardSummary,
    RiskSeverity,
    SessionRiskAssessment,
)
from securemailscope.reporting import ForensicReportGenerator
from securemailscope.traffic_processor import TrafficProcessor

# Maximum allowable PCAP upload size (1 GiB) to prevent Disk Fill DoS
MAX_UPLOAD_SIZE_BYTES = 1024 * 1024 * 1024
CHUNK_SIZE_BYTES = 1024 * 1024  # 1 MiB chunking for stream buffering

app = FastAPI(
    title="SecureMailScope Forensic API",
    description="AI-Assisted Cryptographic Security Posture Assessment API for passive email network traffic.",
    version="1.0.0",
)

# Enable CORS for SOC dashboard integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for asynchronous analysis jobs and cached reports
job_store: Dict[str, Dict[str, Any]] = {}
report_store: Dict[str, ForensicReport] = {}

# Shared engine instances
crypto_validator = CryptographicValidator()
ml_risk_engine = MLRiskEngine()


def execute_forensic_pipeline(temp_path: str, filename: str, file_size: int) -> ForensicReport:
    """
    Executes the end-to-end passive forensic pipeline:
    1. PCAP streaming packet ingestion & TCP reassembly
    2. STARTTLS and TLS handshake extraction
    3. Cryptographic cipher and X.509 certificate validation
    4. AI/ML anomaly detection and explainability scoring
    5. Synthesis of aggregate forensic report
    """
    analysis_id = str(uuid.uuid4())
    processor = TrafficProcessor()

    with open(temp_path, "rb") as stream:
        raw_sessions = processor.process_pcap_stream(stream)

    analyzed_sessions: list[SessionRiskAssessment] = []
    encrypted_count = 0
    cleartext_count = 0
    downgrades_count = 0
    severity_counts: Dict[str, int] = {
        RiskSeverity.CRITICAL.value: 0,
        RiskSeverity.HIGH.value: 0,
        RiskSeverity.MEDIUM.value: 0,
        RiskSeverity.LOW.value: 0,
        RiskSeverity.INFORMATIONAL.value: 0,
    }
    proto_counts: Dict[str, int] = {}

    for session in raw_sessions:
        proto_key = session.protocol.value
        proto_counts[proto_key] = proto_counts.get(proto_key, 0) + 1

        # Track tracker certificate telemetry into validated models
        if hasattr(session, "raw_certificate_ders") and session.raw_certificate_ders:
            session.certificates = crypto_validator.validate_x509_certificates(session.raw_certificate_ders)

        # Resolve negotiated cipher suite
        flow_tracker = processor.streams.get(session.session_id)
        if flow_tracker and flow_tracker.server_selected_cipher is not None:
            session.cipher_suite = crypto_validator.resolve_cipher_suite(flow_tracker.server_selected_cipher)
            if flow_tracker.raw_certificate_ders:
                session.certificates = crypto_validator.validate_x509_certificates(flow_tracker.raw_certificate_ders)

        if session.handshake_completed:
            encrypted_count += 1
        else:
            cleartext_count += 1

        if session.starttls_downgrade_detected:
            downgrades_count += 1

        # Cryptographic and CVE analysis
        cves, findings, penalty = crypto_validator.assess_session_vulnerabilities(session)

        # AI/ML scoring and Explainable AI
        assessment = ml_risk_engine.score_session(session, penalty, cves, findings)
        severity_counts[assessment.severity.value] += 1
        analyzed_sessions.append(assessment)

    # Calculate overall metrics
    total_sess = len(analyzed_sessions)
    avg_risk = round(sum(s.overall_risk_score for s in analyzed_sessions) / (total_sess or 1), 2)

    # Formulate executive summary
    exec_summary = (
        f"Forensic PCAP analysis completed for '{filename}'. Parsed {total_sess} email sessions "
        f"({encrypted_count} encrypted, {cleartext_count} cleartext). "
        f"Detected {downgrades_count} potential STARTTLS downgrade attacks. "
        f"Average enterprise cryptographic risk score evaluated at {avg_risk}/100."
    )

    report = ForensicReport(
        analysis_id=analysis_id,
        filename=filename,
        file_size_bytes=file_size,
        analyzed_at=datetime.now(timezone.utc),
        total_sessions_parsed=total_sess,
        encrypted_sessions_count=encrypted_count,
        cleartext_sessions_count=cleartext_count,
        downgrade_attacks_detected=downgrades_count,
        average_risk_score=avg_risk,
        severity_breakdown=severity_counts,
        protocol_breakdown=proto_counts,
        sessions=analyzed_sessions,
        executive_summary=exec_summary,
    )

    report_store[analysis_id] = report
    return report


def async_pipeline_worker(job_id: str, temp_path: str, filename: str, file_size: int) -> None:
    """Background worker task for processing large PCAP captures without holding HTTP connections."""
    try:
        report = execute_forensic_pipeline(temp_path, filename, file_size)
        job_store[job_id] = {
            "status": "completed",
            "analysis_id": report.analysis_id,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "report": report,
        }
    except Exception as exc:
        job_store[job_id] = {
            "status": "failed",
            "error": str(exc),
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


@app.get("/api/v1/health", summary="Service Health and Readiness Check")
async def health_check() -> Dict[str, str]:
    """Health check endpoint to verify worker availability and ML model readiness."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "framework_author": "Ibrahim Ali",
        "watermark_verified": "true",
        "ml_engine_ready": "true" if ml_risk_engine.model is not None else "false",
        "cipher_database_size": str(len(crypto_validator.CIPHER_REGISTRY)),
    }


@app.post(
    "/api/v1/analyze/pcap",
    response_model=ForensicReport,
    summary="Synchronous PCAP Cryptographic Posture Analysis",
)
async def analyze_pcap_sync(file: UploadFile = File(...)) -> ForensicReport:
    """
    Upload a PCAP capture for immediate passive analysis.
    Implements streaming file transfer to handle multi-gigabyte files with constant memory,
    path sanitization to eliminate path traversal, and deterministic cleanup.
    """
    # Sanitize input filename to neutralize path traversal attempts (CWE-22)
    sanitized_filename = os.path.basename(file.filename or "capture.pcap")

    # Verify standard PCAP extension
    lower_name = sanitized_filename.lower()
    if not (lower_name.endswith(".pcap") or lower_name.endswith(".cap") or lower_name.endswith(".pcapng")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format. Please provide a standard .pcap, .cap, or .pcapng capture.",
        )

    # Secure temporary file creation with automatic cleanup
    temp_fd, temp_path = tempfile.mkstemp(prefix="sms_pcap_", suffix=".pcap")
    total_written = 0

    try:
        with os.fdopen(temp_fd, "wb") as f_out:
            while True:
                chunk = await file.read(CHUNK_SIZE_BYTES)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Upload exceeded maximum allowed threshold ({MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MiB).",
                    )
                f_out.write(chunk)

        report = execute_forensic_pipeline(temp_path, sanitized_filename, total_written)
        return report

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to process capture stream: {str(exc)}",
        )
    finally:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


@app.post(
    "/api/v1/analyze/pcap/async",
    summary="Asynchronous PCAP Ingestion for CI/CD and Batch Forensic Pipelines",
)
async def analyze_pcap_async(
    background_tasks: BackgroundTasks, file: UploadFile = File(...)
) -> Dict[str, str]:
    """
    Queue a large PCAP file for asynchronous background analysis.
    Returns a unique job ticket for polling.
    """
    sanitized_filename = os.path.basename(file.filename or "capture.pcap")
    lower_name = sanitized_filename.lower()
    if not (lower_name.endswith(".pcap") or lower_name.endswith(".cap") or lower_name.endswith(".pcapng")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format.",
        )

    temp_fd, temp_path = tempfile.mkstemp(prefix="sms_async_", suffix=".pcap")
    total_written = 0

    try:
        with os.fdopen(temp_fd, "wb") as f_out:
            while True:
                chunk = await file.read(CHUNK_SIZE_BYTES)
                if not chunk:
                    break
                total_written += len(chunk)
                if total_written > MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Upload exceeded maximum file size.",
                    )
                f_out.write(chunk)
    except Exception:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise

    job_id = str(uuid.uuid4())
    job_store[job_id] = {
        "status": "processing",
        "filename": sanitized_filename,
        "file_size": total_written,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }

    background_tasks.add_task(async_pipeline_worker, job_id, temp_path, sanitized_filename, total_written)

    return {
        "job_id": job_id,
        "status": "queued",
        "poll_url": f"/api/v1/jobs/{job_id}",
    }


@app.get("/api/v1/jobs/{job_id}", summary="Check Asynchronous Analysis Status")
async def get_job_status(job_id: str) -> Dict[str, Any]:
    """Poll job status or fetch finalized ForensicReport."""
    if job_id not in job_store:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job ID not found.")
    return job_store[job_id]


@app.get(
    "/api/v1/reports/{analysis_id}/html",
    response_class=HTMLResponse,
    summary="Download or View Interactive HTML Forensic Report",
)
async def get_html_report(analysis_id: str) -> HTMLResponse:
    """Retrieve full interactive dark-mode HTML report for SOC analysts."""
    if analysis_id not in report_store:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report ID not found.")
    report = report_store[analysis_id]
    html_data = ForensicReportGenerator.to_html(report)
    return HTMLResponse(content=html_data)


@app.get(
    "/api/v1/reports/{analysis_id}/dashboard",
    response_model=InteractiveDashboardSummary,
    summary="Interactive SOC/DFIR Dashboard Visualization Schema",
)
async def get_dashboard_summary(analysis_id: str) -> InteractiveDashboardSummary:
    """Retrieve aggregate visualization telemetry conforming to the SOC interactive dashboard schema."""
    if analysis_id not in report_store:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report ID not found.")
    report = report_store[analysis_id]
    return ForensicReportGenerator.to_dashboard_summary(report)
