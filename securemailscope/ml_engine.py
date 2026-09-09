"""
SecureMailScope - AI/ML Risk and Anomaly Detection Engine
Transforms cryptographic sessions into normalized feature vectors, applies
Isolation Forest anomaly detection, delivers Explainable AI (XAI) attributions,
and calculates quantitative risk scores with prioritized remediation.
"""

from typing import Dict, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

from securemailscope.models import (
    AnomalyExplanation,
    ComplianceFinding,
    EmailProtocol,
    RiskSeverity,
    SessionRiskAssessment,
    TLSSessionDetails,
    TLSVersion,
)


class FeatureExtractor:
    """Extracts normalized numerical feature vectors from TLSSessionDetails models."""

    FEATURE_NAMES: List[str] = [
        "tls_version_ordinal",
        "symmetric_key_bits_norm",
        "has_forward_secrecy",
        "is_aead",
        "is_deprecated_cipher",
        "cert_is_expired",
        "cert_is_self_signed",
        "cert_has_weak_signature",
        "cert_key_size_norm",
        "downgrade_detected",
        "is_cleartext",
    ]

    VERSION_MAP: Dict[TLSVersion, float] = {
        TLSVersion.SSLv2: 0.0,
        TLSVersion.SSLv3: 1.0,
        TLSVersion.TLSv1_0: 2.0,
        TLSVersion.TLSv1_1: 3.0,
        TLSVersion.TLSv1_2: 4.0,
        TLSVersion.TLSv1_3: 5.0,
        TLSVersion.UNKNOWN: -1.0,
    }

    @classmethod
    def extract_vector(cls, session: TLSSessionDetails) -> np.ndarray:
        """Convert a session into an 11-dimensional normalized float array."""
        ver_ord = cls.VERSION_MAP.get(session.negotiated_tls_version, -1.0)
        
        # Cipher metrics
        key_bits = 0.0
        pfs = 0.0
        aead = 0.0
        deprecated = 0.0
        if session.cipher_suite:
            key_bits = float(session.cipher_suite.key_size) / 256.0
            pfs = 1.0 if session.cipher_suite.provides_forward_secrecy else 0.0
            aead = 1.0 if session.cipher_suite.is_aead else 0.0
            deprecated = 1.0 if session.cipher_suite.is_deprecated else 0.0

        # Certificate metrics
        cert_expired = 0.0
        cert_self_signed = 0.0
        cert_weak_sig = 0.0
        cert_key_size = 0.0
        if session.certificates:
            leaf = session.certificates[0]
            cert_expired = 1.0 if leaf.is_expired else 0.0
            cert_self_signed = 1.0 if leaf.is_self_signed else 0.0
            cert_weak_sig = 1.0 if leaf.is_weak_signature else 0.0
            cert_key_size = min(1.0, float(leaf.key_size_bits) / 4096.0)

        # Downgrade and transport
        downgrade = 1.0 if session.starttls_downgrade_detected else 0.0
        cleartext = 1.0 if (not session.handshake_completed and session.negotiated_tls_version == TLSVersion.UNKNOWN) else 0.0

        return np.array([
            ver_ord,
            key_bits,
            pfs,
            aead,
            deprecated,
            cert_expired,
            cert_self_signed,
            cert_weak_sig,
            cert_key_size,
            downgrade,
            cleartext,
        ], dtype=np.float32)


class MLRiskEngine:
    """
    Foundational ML engine for anomaly detection, Explainable AI (XAI)
    feature attribution, and quantitative risk scoring.
    """

    def __init__(self):
        self.feature_names = FeatureExtractor.FEATURE_NAMES
        self.model: Optional[IsolationForest] = None
        self.baseline_mean: np.ndarray = np.array([
            4.5,   # TLS 1.2 - 1.3
            0.75,  # 128 - 256 bits
            1.0,   # PFS enabled
            1.0,   # AEAD enabled
            0.0,   # Not deprecated
            0.0,   # Not expired
            0.0,   # CA signed
            0.0,   # Strong SHA-256+ signature
            0.5,   # 2048+ bit RSA / 256+ bit ECC
            0.0,   # No downgrade
            0.0,   # Encrypted
        ], dtype=np.float32)
        
        self.feature_weights: np.ndarray = np.array([
            0.20,  # Version
            0.10,  # Key bits
            0.15,  # PFS
            0.10,  # AEAD
            0.15,  # Deprecated cipher
            0.10,  # Cert expiry
            0.05,  # Self-signed
            0.05,  # Weak signature
            0.05,  # Key size
            0.25,  # Downgrade
            0.20,  # Cleartext
        ], dtype=np.float32)

        self._initialize_baseline_model()

    def _initialize_baseline_model(self) -> None:
        """
        Initializes and fits an Isolation Forest model using a calibrated distribution
        of hardened enterprise mail configurations to establish a normal baseline.
        """
        rng = np.random.RandomState(42)
        # Generate 300 normative secure baseline samples
        n_samples = 300
        normal_samples = []
        for _ in range(n_samples):
            ver = rng.choice([4.0, 5.0], p=[0.4, 0.6]) # TLS 1.2 or 1.3
            key = rng.choice([0.5, 1.0], p=[0.3, 0.7]) # 128 or 256 bit
            pfs = 1.0
            aead = rng.choice([0.0, 1.0], p=[0.05, 0.95])
            dep = 0.0
            expired = 0.0
            self_signed = 0.0
            weak_sig = 0.0
            cert_key = rng.choice([0.5, 1.0], p=[0.7, 0.3])
            downgrade = 0.0
            cleartext = 0.0
            normal_samples.append([ver, key, pfs, aead, dep, expired, self_signed, weak_sig, cert_key, downgrade, cleartext])

        # Add a small fraction (5%) of anomalies for boundary calibration
        n_anomalies = 15
        for _ in range(n_anomalies):
            ver = rng.choice([0.0, 1.0, 2.0, 3.0])
            normal_samples.append([ver, 0.5, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0])

        X_train = np.array(normal_samples, dtype=np.float32)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.08,
            random_state=42,
        )
        self.model.fit(X_train)

    def score_session(
        self,
        session: TLSSessionDetails,
        deterministic_penalty: float,
        cves: List[str],
        compliance_findings: List[ComplianceFinding],
    ) -> SessionRiskAssessment:
        """
        Computes the complete risk assessment for a session by combining
        unsupervised ML anomaly detection, XAI feature attribution, and deterministic rules.
        """
        vec = FeatureExtractor.extract_vector(session)
        
        # ML Anomaly calculation
        raw_score = self.model.score_samples([vec])[0]
        # score_samples yields values roughly [-0.8, -0.2]. Map to [0.0, 1.0] anomaly metric:
        ml_anomaly_score = float(np.clip(1.0 - (raw_score + 0.8) / 0.6, 0.0, 1.0))
        is_anomaly = bool(ml_anomaly_score > 0.45 or self.model.predict([vec])[0] == -1)

        # XAI: Explainable AI Attribution
        explanations = self._generate_explanations(session, vec)

        # Composite Quantitative Risk Score (0 - 100)
        # Weighted combination of rule-based penalty (65%) and ML anomaly index (35%)
        composite_score = (0.65 * deterministic_penalty) + (0.35 * (ml_anomaly_score * 100.0))
        
        # Critical override: if downgrade attack or broken crypto detected, floor at 75
        if session.starttls_downgrade_detected:
            composite_score = max(composite_score, 85.0)
        elif session.negotiated_tls_version in (TLSVersion.SSLv2, TLSVersion.SSLv3):
            composite_score = max(composite_score, 80.0)

        final_risk_score = round(float(np.clip(composite_score, 0.0, 100.0)), 2)

        # Severity categorization
        if final_risk_score >= 80.0:
            severity = RiskSeverity.CRITICAL
        elif final_risk_score >= 60.0:
            severity = RiskSeverity.HIGH
        elif final_risk_score >= 40.0:
            severity = RiskSeverity.MEDIUM
        elif final_risk_score >= 20.0:
            severity = RiskSeverity.LOW
        else:
            severity = RiskSeverity.INFORMATIONAL

        # Prioritize Remediations
        remediations = self._prioritize_remediations(session, cves, compliance_findings)

        return SessionRiskAssessment(
            session_id=session.session_id,
            flow_tuple=f"{session.client_ip}:{session.client_port} -> {session.server_ip}:{session.server_port}",
            protocol=session.protocol,
            overall_risk_score=final_risk_score,
            severity=severity,
            deterministic_penalty=deterministic_penalty,
            ml_anomaly_score=round(ml_anomaly_score, 3),
            anomaly_detected=is_anomaly,
            anomaly_explanations=explanations,
            compliance_findings=compliance_findings,
            cve_associations=cves,
            prioritized_remediations=remediations,
        )

    def _generate_explanations(
        self, session: TLSSessionDetails, vec: np.ndarray
    ) -> List[AnomalyExplanation]:
        """
        Explainable AI (XAI) Attribution Engine:
        Computes feature deviations from normative baseline to generate human-readable explanations.
        """
        explanations: List[AnomalyExplanation] = []
        deviations = np.abs(vec - self.baseline_mean) * self.feature_weights
        total_dev = float(np.sum(deviations))

        for idx, feat_name in enumerate(self.feature_names):
            dev = deviations[idx]
            if dev <= 0.02:
                continue

            weight = round(float(dev / (total_dev if total_dev > 0 else 1.0)), 3)
            val = float(vec[idx])

            reason = ""
            observed = None
            baseline = ""

            if feat_name == "tls_version_ordinal":
                observed = session.negotiated_tls_version.value
                baseline = "TLS 1.2 or TLS 1.3"
                reason = f"Negotiated protocol {observed} deviates from enterprise standard {baseline}."
            elif feat_name == "downgrade_detected" and val > 0.5:
                observed = "Downgrade Detected"
                baseline = "No Downgrade"
                reason = "STARTTLS negotiation was offered but bypassed/stripped, exposing credentials in cleartext."
            elif feat_name == "has_forward_secrecy" and val < 0.5:
                observed = "Static Key Exchange"
                baseline = "Ephemeral ECDHE/DHE"
                reason = "Cipher suite does not provide Perfect Forward Secrecy (PFS), risking retroactive decryption."
            elif feat_name == "is_deprecated_cipher" and val > 0.5:
                observed = session.cipher_suite.iana_name if session.cipher_suite else "Deprecated Cipher"
                baseline = "Modern AEAD Ciphers"
                reason = f"Cipher {observed} is deprecated due to structural weaknesses (e.g. 3DES, RC4, CBC mode)."
            elif feat_name == "cert_is_expired" and val > 0.5:
                observed = "Expired"
                baseline = "Valid Active Certificate"
                reason = "X.509 certificate has passed its expiration date, exposing clients to interception."
            elif feat_name == "cert_is_self_signed" and val > 0.5:
                observed = "Self-Signed"
                baseline = "CA Signed"
                reason = "Certificate is self-signed and lacks trust validation from recognized root authorities."
            elif feat_name == "is_cleartext" and val > 0.5:
                observed = "Cleartext Session"
                baseline = "TLS Encrypted"
                reason = "Application mail commands were exchanged without TLS encapsulation."

            if reason:
                explanations.append(
                    AnomalyExplanation(
                        feature_name=feat_name,
                        observed_value=observed if observed is not None else val,
                        baseline_reference=baseline,
                        contribution_weight=weight,
                        human_readable_reason=reason,
                    )
                )

        # Sort explanations by contribution weight descending
        explanations.sort(key=lambda x: x.contribution_weight, reverse=True)
        return explanations

    def _prioritize_remediations(
        self, session: TLSSessionDetails, cves: List[str], compliance_findings: List[ComplianceFinding]
    ) -> List[str]:
        """Rank and prioritize actionable remediation steps based on impact and exploitability."""
        remediations: List[str] = []

        # Tier 1 (Urgent: Active Downgrade / Cleartext Exposure)
        if session.starttls_downgrade_detected:
            remediations.append(
                "[P1 - URGENT] Enforce MTA-STS and DANE (TLSA) to prevent STARTTLS stripping attacks."
            )
            remediations.append(
                "[P1 - URGENT] Reject plaintext authentication (AUTH) until TLS handshake is complete."
            )

        # Tier 2 (Critical: Expired Cert / SSL 2/3 / Deprecated TLS)
        for cert in session.certificates:
            if cert.is_expired:
                remediations.append(
                    f"[P1 - URGENT] Immediately replace expired certificate for {cert.subject_dn}."
                )

        if session.negotiated_tls_version in (TLSVersion.SSLv2, TLSVersion.SSLv3):
            remediations.append(
                "[P1 - CRITICAL] Immediately disable SSLv2 and SSLv3 daemons to mitigate POODLE and DROWN."
            )
        elif session.negotiated_tls_version in (TLSVersion.TLSv1_0, TLSVersion.TLSv1_1):
            remediations.append(
                "[P2 - HIGH] Decommission TLS 1.0 and TLS 1.1; enforce TLS 1.2 minimum per NIST SP 800-52r2."
            )

        # Tier 3 (High: Cipher Weaknesses / Forward Secrecy)
        if session.cipher_suite:
            if not session.cipher_suite.provides_forward_secrecy:
                remediations.append(
                    "[P2 - HIGH] Prioritize ECDHE and DHE cipher suites to guarantee Perfect Forward Secrecy."
                )
            if session.cipher_suite.is_deprecated:
                remediations.append(
                    f"[P2 - HIGH] Disable deprecated cipher {session.cipher_suite.iana_name} on mail gateways."
                )

        # Tier 4 (Medium: CA Trust and Certificates)
        for cert in session.certificates:
            if cert.is_self_signed:
                remediations.append(
                    "[P3 - MEDIUM] Replace self-signed certificates with validated certificates from a trusted CA."
                )
            if cert.is_weak_signature:
                remediations.append(
                    "[P3 - MEDIUM] Re-issue certificate using SHA-256 or SHA-384 signature digests."
                )

        if not remediations:
            remediations.append("[P4 - INFO] System cryptographic posture aligns with recommended baselines.")

        return remediations
