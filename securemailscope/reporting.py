"""
SecureMailScope - Presentation and Reporting Layer
Generates comprehensive forensic reports in JSON, HTML, and PDF formats,
and compiles schemas for interactive SOC/DFIR security dashboards.
"""

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from securemailscope.models import (
    ComplianceStatus,
    DashboardWidgetMetric,
    ForensicReport,
    InteractiveDashboardSummary,
    RiskSeverity,
)


class ForensicReportGenerator:
    """Renders standardized forensic analysis reports across formats."""

    @staticmethod
    def to_json(report: ForensicReport) -> str:
        """Serialize report to formatted JSON string."""
        return report.model_dump_json(indent=2)

    @classmethod
    def to_html(cls, report: ForensicReport) -> str:
        """
        Renders a self-contained, enterprise-grade dark-themed HTML report
        suitable for SOC teams, CISOs, and DFIR analysts.
        """
        # Build severity badge colors
        severity_colors = {
            RiskSeverity.CRITICAL: "#ef4444",
            RiskSeverity.HIGH: "#f97316",
            RiskSeverity.MEDIUM: "#eab308",
            RiskSeverity.LOW: "#3b82f6",
            RiskSeverity.INFORMATIONAL: "#10b981",
        }

        sessions_html = []
        for s in report.sessions:
            color = severity_colors.get(s.severity, "#6b7280")
            cves_badge = "".join(f'<span class="badge badge-cve">{html.escape(cve)}</span>' for cve in s.cve_associations) or '<span class="text-muted">None</span>'
            
            explanations_li = "".join(
                f'<li><strong>{html.escape(e.feature_name)}:</strong> {html.escape(e.human_readable_reason)} '
                f'<span class="text-muted">(Weight: {e.contribution_weight:.2f})</span></li>'
                for e in s.anomaly_explanations
            ) or '<li class="text-muted">No anomalous patterns detected.</li>'

            compliance_rows = "".join(
                f'<tr><td>{html.escape(c.standard)} ({html.escape(c.section)})</td>'
                f'<td><span class="badge badge-{c.status.value.lower()}">{c.status.value}</span></td>'
                f'<td>{html.escape(c.title)}</td><td>{html.escape(c.remediation)}</td></tr>'
                for c in s.compliance_findings
            ) or '<tr><td colspan="4" class="text-muted">No compliance findings recorded.</td></tr>'

            remediations_li = "".join(
                f'<li>{html.escape(rem)}</li>'
                for rem in s.prioritized_remediations
            )

            session_card = f"""
            <div class="card session-card">
                <div class="session-header">
                    <div>
                        <span class="protocol-tag">{html.escape(s.protocol.value)}</span>
                        <strong>{html.escape(s.flow_tuple)}</strong>
                    </div>
                    <div>
                        <span class="badge" style="background-color: {color}; color: white;">{s.severity.value} ({s.overall_risk_score:.1f}/100)</span>
                    </div>
                </div>
                <div class="session-body">
                    <div class="grid-2">
                        <div>
                            <h4>Associated Vulnerabilities & CVEs</h4>
                            <div class="cve-container">{cves_badge}</div>
                            
                            <h4>Explainable AI (XAI) Attribution</h4>
                            <ul class="clean-list">{explanations_li}</ul>
                        </div>
                        <div>
                            <h4>Prioritized Remediations</h4>
                            <ul class="remediation-list">{remediations_li}</ul>
                        </div>
                    </div>
                    
                    <h4 style="margin-top: 15px;">Regulatory Compliance Audit</h4>
                    <table class="report-table">
                        <thead>
                            <tr><th>Standard</th><th>Status</th><th>Finding</th><th>Remediation</th></tr>
                        </thead>
                        <tbody>
                            {compliance_rows}
                        </tbody>
                    </table>
                </div>
            </div>
            """
            sessions_html.append(session_card)

        sessions_str = "\n".join(sessions_html)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMailScope Forensic Report - {html.escape(report.analysis_id)}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --accent-blue: #38bdf8;
            --accent-green: #34d399;
            --accent-red: #f87171;
            --accent-yellow: #facc15;
        }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
            color: var(--accent-blue);
        }}
        .header-meta {{
            color: var(--text-secondary);
            font-size: 14px;
        }}
        .grid-4 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}
        .metric-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
        }}
        .metric-title {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
        }}
        .metric-value {{
            font-size: 28px;
            font-weight: 700;
            margin-top: 4px;
        }}
        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .session-card {{
            border-left: 4px solid var(--accent-blue);
        }}
        .session-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 12px;
        }}
        .protocol-tag {{
            background-color: #0284c7;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            margin-right: 8px;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-cve {{
            background-color: #450a0a;
            color: #fca5a5;
            border: 1px solid #7f1d1d;
            margin-right: 6px;
            margin-bottom: 6px;
            display: inline-block;
        }}
        .badge-compliant {{
            background-color: #064e3b;
            color: #6ee7b7;
        }}
        .badge-non_compliant {{
            background-color: #450a0a;
            color: #fca5a5;
        }}
        .badge-warning {{
            background-color: #451a03;
            color: #fcd34d;
        }}
        .report-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 8px;
        }}
        .report-table th, .report-table td {{
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        .report-table th {{
            color: var(--text-secondary);
            font-weight: 600;
        }}
        .clean-list, .remediation-list {{
            padding-left: 20px;
            font-size: 13px;
            margin: 6px 0;
        }}
        .remediation-list li {{
            margin-bottom: 4px;
            color: #bae6fd;
        }}
        .text-muted {{
            color: var(--text-secondary);
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>SecureMailScope Forensic Report</h1>
                <div class="header-meta">Analysis ID: {html.escape(report.analysis_id)} | File: {html.escape(report.filename)} ({report.file_size_bytes} bytes)</div>
            </div>
            <div class="header-meta">
                Generated: {report.analyzed_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
            </div>
        </div>

        <div class="grid-4">
            <div class="metric-card">
                <div class="metric-title">Average Risk Score</div>
                <div class="metric-value" style="color: {('var(--accent-red)' if report.average_risk_score >= 60 else 'var(--accent-yellow)' if report.average_risk_score >= 40 else 'var(--accent-green)')}">{report.average_risk_score:.1f}/100</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Total Sessions</div>
                <div class="metric-value">{report.total_sessions_parsed}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Downgrade Attacks</div>
                <div class="metric-value" style="color: {('var(--accent-red)' if report.downgrade_attacks_detected > 0 else 'var(--accent-green)')}">{report.downgrade_attacks_detected}</div>
            </div>
            <div class="metric-card">
                <div class="metric-title">Cleartext Sessions</div>
                <div class="metric-value" style="color: {('var(--accent-yellow)' if report.cleartext_sessions_count > 0 else 'var(--accent-green)')}">{report.cleartext_sessions_count}</div>
            </div>
        </div>

        <div class="card">
            <h3>Executive Summary</h3>
            <p>{html.escape(report.executive_summary)}</p>
        </div>

        <h3>Reconstructed Mail Sessions & Forensic Assessments</h3>
        {sessions_str}

        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border-color); text-align: center; color: var(--text-secondary); font-size: 13px;">
            SecureMailScope Cryptographic Framework &bull; Designed &amp; Architected by <strong>Ibrahim Ali</strong> &bull; All Rights Reserved
        </footer>
    </div>
</body>
</html>
"""
        return html_content

    @classmethod
    def to_dashboard_summary(cls, report: ForensicReport) -> InteractiveDashboardSummary:
        """Compile aggregate analytics conforming to the SOC interactive dashboard schema."""
        ciphers_dist: Dict[str, int] = {}
        tls_ver_dist: Dict[str, int] = {}
        vulnerabilities_map: Dict[str, int] = {}
        compliance_scores: Dict[str, List[bool]] = {
            "NIST SP 800-52r2": [],
            "PCI-DSS v4.0": [],
            "CIS Benchmarks": [],
        }

        timeline: List[Dict[str, Any]] = []

        for s in report.sessions:
            # Timeline entry
            timeline.append({
                "session_id": s.session_id,
                "protocol": s.protocol.value,
                "risk_score": s.overall_risk_score,
                "severity": s.severity.value,
                "anomaly": s.anomaly_detected,
            })

            # CVE / Vulnerability tally
            for cve in s.cve_associations:
                vulnerabilities_map[cve] = vulnerabilities_map.get(cve, 0) + 1

            # Compliance tally
            for comp in s.compliance_findings:
                if comp.standard in compliance_scores:
                    compliance_scores[comp.standard].append(comp.status == ComplianceStatus.COMPLIANT)

        top_vulns = [
            {"vulnerability": k, "count": v}
            for k, v in sorted(vulnerabilities_map.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # Calculate compliance pass rates (0.0 to 100.0)
        compliance_radar: Dict[str, float] = {}
        for std, results in compliance_scores.items():
            if results:
                pass_rate = round((sum(results) / len(results)) * 100.0, 1)
            else:
                pass_rate = 100.0
            compliance_radar[std] = pass_rate

        posture = "Hardened"
        if report.average_risk_score >= 70:
            posture = "Critical Exposure"
        elif report.average_risk_score >= 40:
            posture = "Moderate Risk"

        metrics = [
            DashboardWidgetMetric(label="Mean Cryptographic Risk", value=f"{report.average_risk_score:.1f}/100", status="critical" if report.average_risk_score >= 60 else "normal"),
            DashboardWidgetMetric(label="Encrypted Session Ratio", value=f"{(report.encrypted_sessions_count / (report.total_sessions_parsed or 1) * 100):.1f}%", status="normal"),
            DashboardWidgetMetric(label="Downgrade Incident Count", value=report.downgrade_attacks_detected, status="critical" if report.downgrade_attacks_detected > 0 else "normal"),
            DashboardWidgetMetric(label="Cleartext Leakage Count", value=report.cleartext_sessions_count, status="warning" if report.cleartext_sessions_count > 0 else "normal"),
        ]

        return InteractiveDashboardSummary(
            analysis_id=report.analysis_id,
            filename=report.filename,
            overall_posture=posture,
            metrics=metrics,
            ciphers_distribution=ciphers_dist,
            tls_versions_distribution=tls_ver_dist,
            top_vulnerabilities=top_vulns,
            compliance_radar=compliance_radar,
            sessions_timeline=timeline,
        )

