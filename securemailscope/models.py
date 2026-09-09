"""
SecureMailScope - Core Pydantic Schemas and Domain Models
Defines immutable data contracts for network sessions, TLS handshakes,
X.509 certificate chains, compliance standards, and risk scoring.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class EmailProtocol(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    SMTPS = "SMTPS"
    IMAPS = "IMAPS"
    POP3S = "POP3S"
    UNKNOWN = "UNKNOWN"


class TLSVersion(str, Enum):
    SSLv2 = "SSLv2"
    SSLv3 = "SSLv3"
    TLSv1_0 = "TLSv1.0"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"
    UNKNOWN = "UNKNOWN"


class RiskSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ComplianceStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class X509CertificateDetails(BaseModel):
    """Forensic breakdown of an extracted X.509 leaf or intermediate certificate."""
    model_config = ConfigDict(extra="ignore")

    subject_dn: str = Field(..., description="Full Subject Distinguished Name")
    issuer_dn: str = Field(..., description="Full Issuer Distinguished Name")
    serial_number: str = Field(..., description="Hex encoded serial number")
    not_before: datetime = Field(..., description="Validity start timestamp")
    not_after: datetime = Field(..., description="Validity expiration timestamp")
    is_expired: bool = Field(..., description="True if current time exceeds not_after")
    days_until_expiration: int = Field(..., description="Remaining valid days (negative if expired)")
    public_key_algorithm: str = Field(..., description="RSA, EC, Ed25519, etc.")
    key_size_bits: int = Field(..., description="Public key length in bits")
    signature_algorithm: str = Field(..., description="e.g., sha256WithRSAEncryption, md5WithRSA")
    is_weak_signature: bool = Field(..., description="True if MD5, SHA1 or other weak digest is used")
    san_list: List[str] = Field(default_factory=list, description="Subject Alternative Names")
    is_self_signed: bool = Field(..., description="True if subject matches issuer")
    fingerprint_sha256: str = Field(..., description="Hex SHA-256 fingerprint")
    chain_verified: Optional[bool] = Field(default=None, description="Trust store chain verification status")


class CipherSuiteDetails(BaseModel):
    """Detailed cryptographic attribute mapping for a negotiated cipher suite."""
    model_config = ConfigDict(extra="ignore")

    iana_id: int = Field(..., description="Decimal IANA identifier (e.g. 0xC02F -> 49200)")
    iana_hex: str = Field(..., description="Hexadecimal representation (e.g. 0xC02F)")
    iana_name: str = Field(..., description="Standard IANA cipher name")
    openssl_name: Optional[str] = Field(None, description="OpenSSL alias")
    key_exchange: str = Field(..., description="ECDHE, DHE, RSA, PSK, etc.")
    authentication: str = Field(..., description="RSA, ECDSA, etc.")
    encryption: str = Field(..., description="AES_128_GCM, CHACHA20_POLY1305, 3DES_EDE_CBC, etc.")
    mac: str = Field(..., description="AEAD, SHA256, SHA1, MD5")
    key_size: int = Field(..., description="Symmetric key bit size (e.g. 128, 256, 112 for 3DES)")
    provides_forward_secrecy: bool = Field(..., description="True if ECDHE or DHE key exchange")
    is_aead: bool = Field(..., description="Authenticated Encryption with Associated Data")
    is_deprecated: bool = Field(..., description="Flagged as deprecated by NIST/RFC")
    known_vulnerabilities: List[str] = Field(default_factory=list, description="SWEET32, POODLE, LOGJAM, etc.")


class TLSSessionDetails(BaseModel):
    """Normalized communication session capturing transport, STARTTLS and TLS state."""
    model_config = ConfigDict(extra="ignore")

    session_id: str = Field(..., description="Unique flow identifier (5-tuple hash)")
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: EmailProtocol
    starttls_command_seen: bool = Field(default=False, description="Whether STARTTLS/STLS was sent")
    starttls_negotiated: bool = Field(default=False, description="Whether server acknowledged STARTTLS")
    starttls_downgrade_detected: bool = Field(
        default=False, 
        description="Whether STARTTLS was offered but stripped/failed, forcing cleartext"
    )
    tls_record_version: Optional[str] = None
    negotiated_tls_version: TLSVersion = TLSVersion.UNKNOWN
    cipher_suite: Optional[CipherSuiteDetails] = None
    client_hello_ciphers: List[int] = Field(default_factory=list)
    sni_hostname: Optional[str] = None
    alpn_protocols: List[str] = Field(default_factory=list)
    certificates: List[X509CertificateDetails] = Field(default_factory=list)
    handshake_completed: bool = Field(default=False)
    total_bytes_transferred: int = 0
    packet_count: int = 0
    timestamp_start: float = 0.0
    timestamp_end: float = 0.0


class ComplianceFinding(BaseModel):
    """Mapping of a specific cryptographic metric to an industry standard."""
    standard: str = Field(..., description="NIST SP 800-52r2, PCI-DSS v4.0, CIS")
    section: str = Field(..., description="Requirement or Section ID")
    status: ComplianceStatus
    title: str
    description: str
    remediation: str


class AnomalyExplanation(BaseModel):
    """Human-readable explainability attribution generated by the AI/ML engine."""
    feature_name: str
    observed_value: Any
    baseline_reference: str
    contribution_weight: float = Field(..., description="Normalized contribution to anomaly index")
    human_readable_reason: str


class SessionRiskAssessment(BaseModel):
    """Comprehensive risk evaluation for an individual reconstructed session."""
    session_id: str
    flow_tuple: str
    protocol: EmailProtocol
    overall_risk_score: float = Field(..., ge=0.0, le=100.0, description="0=Hardened, 100=Critical Risk")
    severity: RiskSeverity
    deterministic_penalty: float = Field(..., description="Rule-based vulnerability score component")
    ml_anomaly_score: float = Field(..., description="Unsupervised anomaly metric (0.0 to 1.0)")
    anomaly_detected: bool
    anomaly_explanations: List[AnomalyExplanation] = Field(default_factory=list)
    compliance_findings: List[ComplianceFinding] = Field(default_factory=list)
    cve_associations: List[str] = Field(default_factory=list)
    prioritized_remediations: List[str] = Field(default_factory=list)


class ForensicReport(BaseModel):
    """Aggregate forensic security report across all sessions in an ingested PCAP."""
    analysis_id: str
    filename: str
    file_size_bytes: int
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_sessions_parsed: int
    encrypted_sessions_count: int
    cleartext_sessions_count: int
    downgrade_attacks_detected: int
    average_risk_score: float
    severity_breakdown: Dict[str, int]
    protocol_breakdown: Dict[str, int]
    sessions: List[SessionRiskAssessment]
    executive_summary: str


class DashboardWidgetMetric(BaseModel):
    """Metric item for SOC dashboard widgets."""
    label: str
    value: Any
    status: str = "normal"  # normal, warning, critical


class InteractiveDashboardSummary(BaseModel):
    """Schema for SOC/DFIR interactive visualization dashboard."""
    analysis_id: str
    filename: str
    overall_posture: str
    metrics: List[DashboardWidgetMetric]
    ciphers_distribution: Dict[str, int]
    tls_versions_distribution: Dict[str, int]
    top_vulnerabilities: List[Dict[str, Any]]
    compliance_radar: Dict[str, float]
    sessions_timeline: List[Dict[str, Any]]
