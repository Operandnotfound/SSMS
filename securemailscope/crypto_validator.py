"""
SecureMailScope - Cryptographic Validation and Posture Analysis Engine
Evaluates TLS cipher strength, Forward Secrecy, deprecated protocol configurations,
X.509 certificate chains, CVE associations, and compliance against NIST SP 800-52, PCI-DSS, and CIS.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa, x448, x25519

from securemailscope.models import (
    CipherSuiteDetails,
    ComplianceFinding,
    ComplianceStatus,
    EmailProtocol,
    TLSSessionDetails,
    TLSVersion,
    X509CertificateDetails,
)


class CryptographicValidator:
    """
    Expert cryptographic validator for passive email TLS sessions.
    Validates cipher strength, forward secrecy, certificates, and maps findings
    to CVEs and modern regulatory compliance frameworks.
    """

    # Comprehensive IANA Cipher Suite Database
    CIPHER_REGISTRY: Dict[int, Dict[str, Any]] = {
        # TLS 1.3 Modern AEAD Ciphers (RFC 8446)
        0x1301: {
            "name": "TLS_AES_128_GCM_SHA256",
            "openssl": "TLS_AES_128_GCM_SHA256",
            "kex": "ECDHE/DHE",
            "auth": "AEAD",
            "enc": "AES_128_GCM",
            "mac": "AEAD",
            "key_size": 128,
            "pfs": True,
            "aead": True,
            "deprecated": False,
            "cves": [],
        },
        0x1302: {
            "name": "TLS_AES_256_GCM_SHA384",
            "openssl": "TLS_AES_256_GCM_SHA384",
            "kex": "ECDHE/DHE",
            "auth": "AEAD",
            "enc": "AES_256_GCM",
            "mac": "AEAD",
            "key_size": 256,
            "pfs": True,
            "aead": True,
            "deprecated": False,
            "cves": [],
        },
        0x1303: {
            "name": "TLS_CHACHA20_POLY1305_SHA256",
            "openssl": "TLS_CHACHA20_POLY1305_SHA256",
            "kex": "ECDHE/DHE",
            "auth": "AEAD",
            "enc": "CHACHA20_POLY1305",
            "mac": "AEAD",
            "key_size": 256,
            "pfs": True,
            "aead": True,
            "deprecated": False,
            "cves": [],
        },
        # TLS 1.2 Recommended Ciphers (ECDHE + GCM)
        0xC02F: {
            "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "openssl": "ECDHE-RSA-AES128-GCM-SHA256",
            "kex": "ECDHE",
            "auth": "RSA",
            "enc": "AES_128_GCM",
            "mac": "AEAD",
            "key_size": 128,
            "pfs": True,
            "aead": True,
            "deprecated": False,
            "cves": [],
        },
        0xC030: {
            "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "openssl": "ECDHE-RSA-AES256-GCM-SHA384",
            "kex": "ECDHE",
            "auth": "RSA",
            "enc": "AES_256_GCM",
            "mac": "AEAD",
            "key_size": 256,
            "pfs": True,
            "aead": True,
            "deprecated": False,
            "cves": [],
        },
        0xC02B: {
            "name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "openssl": "ECDHE-ECDSA-AES128-GCM-SHA256",
            "kex": "ECDHE",
            "auth": "ECDSA",
            "enc": "AES_128_GCM",
            "mac": "AEAD",
            "key_size": 128,
            "pfs": True,
            "aead": True,
            "deprecated": False,
            "cves": [],
        },
        0xC02C: {
            "name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "openssl": "ECDHE-ECDSA-AES256-GCM-SHA384",
            "kex": "ECDHE",
            "auth": "ECDSA",
            "enc": "AES_256_GCM",
            "mac": "AEAD",
            "key_size": 256,
            "pfs": True,
            "aead": True,
            "deprecated": False,
            "cves": [],
        },
        0xCCA8: {
            "name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "openssl": "ECDHE-RSA-CHACHA20-POLY1305",
            "kex": "ECDHE",
            "auth": "RSA",
            "enc": "CHACHA20_POLY1305",
            "mac": "AEAD",
            "key_size": 256,
            "pfs": True,
            "aead": True,
            "deprecated": False,
            "cves": [],
        },
        # TLS 1.2 DHE Ciphers
        0x009E: {
            "name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            "openssl": "DHE-RSA-AES128-GCM-SHA256",
            "kex": "DHE",
            "auth": "RSA",
            "enc": "AES_128_GCM",
            "mac": "AEAD",
            "key_size": 128,
            "pfs": True,
            "aead": True,
            "deprecated": False,
            "cves": [],
        },
        0x009F: {
            "name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "openssl": "DHE-RSA-AES256-GCM-SHA384",
            "kex": "DHE",
            "auth": "RSA",
            "enc": "AES_256_GCM",
            "mac": "AEAD",
            "key_size": 256,
            "pfs": True,
            "aead": True,
            "deprecated": False,
            "cves": [],
        },
        # CBC Mode Ciphers (LUCKY13 Risk, Deprecated in NIST SP 800-52r2)
        0xC013: {
            "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "openssl": "ECDHE-RSA-AES128-SHA",
            "kex": "ECDHE",
            "auth": "RSA",
            "enc": "AES_128_CBC",
            "mac": "SHA1",
            "key_size": 128,
            "pfs": True,
            "aead": False,
            "deprecated": True,
            "cves": ["CVE-2013-0169 (LUCKY13)", "Weak MAC: SHA-1"],
        },
        0xC014: {
            "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "openssl": "ECDHE-RSA-AES256-SHA",
            "kex": "ECDHE",
            "auth": "RSA",
            "enc": "AES_256_CBC",
            "mac": "SHA1",
            "key_size": 256,
            "pfs": True,
            "aead": False,
            "deprecated": True,
            "cves": ["CVE-2013-0169 (LUCKY13)", "Weak MAC: SHA-1"],
        },
        0x002F: {
            "name": "TLS_RSA_WITH_AES_128_CBC_SHA",
            "openssl": "AES128-SHA",
            "kex": "RSA",
            "auth": "RSA",
            "enc": "AES_128_CBC",
            "mac": "SHA1",
            "key_size": 128,
            "pfs": False,
            "aead": False,
            "deprecated": True,
            "cves": ["CVE-2017-13099 (ROBOT)", "CVE-2013-0169 (LUCKY13)", "No Forward Secrecy"],
        },
        0x0035: {
            "name": "TLS_RSA_WITH_AES_256_CBC_SHA",
            "openssl": "AES256-SHA",
            "kex": "RSA",
            "auth": "RSA",
            "enc": "AES_256_CBC",
            "mac": "SHA1",
            "key_size": 256,
            "pfs": False,
            "aead": False,
            "deprecated": True,
            "cves": ["CVE-2017-13099 (ROBOT)", "CVE-2013-0169 (LUCKY13)", "No Forward Secrecy"],
        },
        0x009C: {
            "name": "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "openssl": "AES128-GCM-SHA256",
            "kex": "RSA",
            "auth": "RSA",
            "enc": "AES_128_GCM",
            "mac": "AEAD",
            "key_size": 128,
            "pfs": False,
            "aead": True,
            "deprecated": True,
            "cves": ["CVE-2017-13099 (ROBOT)", "No Forward Secrecy"],
        },
        # Severely Weak / Broken Ciphers (3DES, RC4, DES, EXPORT)
        0x000A: {
            "name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "openssl": "DES-CBC3-SHA",
            "kex": "RSA",
            "auth": "RSA",
            "enc": "3DES_EDE_CBC",
            "mac": "SHA1",
            "key_size": 112,
            "pfs": False,
            "aead": False,
            "deprecated": True,
            "cves": ["CVE-2016-2183 (SWEET32)", "CVE-2017-13099 (ROBOT)", "No Forward Secrecy"],
        },
        0xC012: {
            "name": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "openssl": "ECDHE-RSA-DES-CBC3-SHA",
            "kex": "ECDHE",
            "auth": "RSA",
            "enc": "3DES_EDE_CBC",
            "mac": "SHA1",
            "key_size": 112,
            "pfs": True,
            "aead": False,
            "deprecated": True,
            "cves": ["CVE-2016-2183 (SWEET32)"],
        },
        0x0005: {
            "name": "TLS_RSA_WITH_RC4_128_SHA",
            "openssl": "RC4-SHA",
            "kex": "RSA",
            "auth": "RSA",
            "enc": "RC4_128",
            "mac": "SHA1",
            "key_size": 128,
            "pfs": False,
            "aead": False,
            "deprecated": True,
            "cves": ["CVE-2015-2808 (Bar Mitzvah / RC4)", "CVE-2013-2566 (RC4 Biases)", "No Forward Secrecy"],
        },
        0x0004: {
            "name": "TLS_RSA_WITH_RC4_128_MD5",
            "openssl": "RC4-MD5",
            "kex": "RSA",
            "auth": "RSA",
            "enc": "RC4_128",
            "mac": "MD5",
            "key_size": 128,
            "pfs": False,
            "aead": False,
            "deprecated": True,
            "cves": ["CVE-2015-2808 (Bar Mitzvah / RC4)", "Weak MD5 MAC", "No Forward Secrecy"],
        },
        0x0009: {
            "name": "TLS_RSA_WITH_DES_CBC_SHA",
            "openssl": "DES-CBC-SHA",
            "kex": "RSA",
            "auth": "RSA",
            "enc": "DES_CBC",
            "mac": "SHA1",
            "key_size": 56,
            "pfs": False,
            "aead": False,
            "deprecated": True,
            "cves": ["Broken 56-bit DES", "No Forward Secrecy"],
        },
    }

    def __init__(self):
        """Initializes validator and cryptographically enforces framework integrity."""
        from securemailscope import verify_framework_integrity
        verify_framework_integrity()

    def resolve_cipher_suite(self, cipher_id: int) -> CipherSuiteDetails:
        """Resolve a 16-bit cipher suite identifier into structural cryptographic details."""
        hex_repr = f"0x{cipher_id:04X}"
        if cipher_id in self.CIPHER_REGISTRY:
            meta = self.CIPHER_REGISTRY[cipher_id]
            return CipherSuiteDetails(
                iana_id=cipher_id,
                iana_hex=hex_repr,
                iana_name=meta["name"],
                openssl_name=meta["openssl"],
                key_exchange=meta["kex"],
                authentication=meta["auth"],
                encryption=meta["enc"],
                mac=meta["mac"],
                key_size=meta["key_size"],
                provides_forward_secrecy=meta["pfs"],
                is_aead=meta["aead"],
                is_deprecated=meta["deprecated"],
                known_vulnerabilities=meta["cves"],
            )

        # Dynamic fallback for unmapped cipher suites
        pfs = False
        aead = False
        deprecated = True
        cves = []
        name = f"TLS_UNKNOWN_CIPHER_{hex_repr}"
        return CipherSuiteDetails(
            iana_id=cipher_id,
            iana_hex=hex_repr,
            iana_name=name,
            openssl_name=None,
            key_exchange="UNKNOWN",
            authentication="UNKNOWN",
            encryption="UNKNOWN",
            mac="UNKNOWN",
            key_size=0,
            provides_forward_secrecy=pfs,
            is_aead=aead,
            is_deprecated=deprecated,
            known_vulnerabilities=["Unrecognized or unverified cipher suite."],
        )

    def validate_x509_certificates(self, cert_ders: List[bytes]) -> List[X509CertificateDetails]:
        """
        Forensically decodes ASN.1 DER certificates, validates validity periods,
        key strengths, digital signature algorithms, and detects self-signed chains.
        """
        results: List[X509CertificateDetails] = []
        now = datetime.now(timezone.utc)

        for der_bytes in cert_ders:
            try:
                cert = x509.load_der_x509_certificate(der_bytes)
                
                # Extract Subject and Issuer
                subject_dn = cert.subject.rfc4514_string()
                issuer_dn = cert.issuer.rfc4514_string()
                serial_hex = f"{cert.serial_number:X}"

                # Expiration calculation
                if hasattr(cert, "not_valid_before_utc"):
                    not_before = cert.not_valid_before_utc
                else:
                    not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

                if hasattr(cert, "not_valid_after_utc"):
                    not_after = cert.not_valid_after_utc
                else:
                    not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                is_expired = now > not_after
                days_left = (not_after - now).days

                # Public Key Analysis
                pub_key = cert.public_key()
                pub_key_alg = "UNKNOWN"
                key_size = 0

                if isinstance(pub_key, rsa.RSAPublicKey):
                    pub_key_alg = "RSA"
                    key_size = pub_key.key_size
                elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                    pub_key_alg = f"EC ({pub_key.curve.name})"
                    key_size = pub_key.key_size
                elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                    pub_key_alg = "Ed25519"
                    key_size = 256
                elif isinstance(pub_key, ed448.Ed448PublicKey):
                    pub_key_alg = "Ed448"
                    key_size = 448

                # Signature Algorithm Analysis
                sig_alg_name = cert.signature_algorithm_oid._name
                weak_signature = any(
                    weak in sig_alg_name.lower()
                    for weak in ["md5", "sha1", "sha-1", "md2"]
                )

                # SAN (Subject Alternative Names) extraction
                sans: List[str] = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = [str(x.value) for x in san_ext.value]
                except Exception:
                    pass

                # Self-signed assessment
                is_self_signed = (subject_dn == issuer_dn)

                # SHA-256 Fingerprint
                fp = hashlib.sha256(der_bytes).hexdigest().upper()
                formatted_fp = ":".join(fp[i : i + 2] for i in range(0, len(fp), 2))

                results.append(
                    X509CertificateDetails(
                        subject_dn=subject_dn,
                        issuer_dn=issuer_dn,
                        serial_number=serial_hex,
                        not_before=not_before,
                        not_after=not_after,
                        is_expired=is_expired,
                        days_until_expiration=days_left,
                        public_key_algorithm=pub_key_alg,
                        key_size_bits=key_size,
                        signature_algorithm=sig_alg_name,
                        is_weak_signature=weak_signature,
                        san_list=sans,
                        is_self_signed=is_self_signed,
                        fingerprint_sha256=formatted_fp,
                        chain_verified=not is_self_signed and not is_expired,
                    )
                )
            except Exception:
                continue

        return results

    def evaluate_compliance(self, session: TLSSessionDetails) -> List[ComplianceFinding]:
        """
        Maps cryptographic telemetry against industry security standards:
        - NIST SP 800-52 Rev. 2 (Guidelines for TLS in Federal Environments)
        - PCI-DSS v4.0 (Requirement 4.2.1 - Strong Cryptography)
        - CIS Benchmarks (Mail Transfer Hardening)
        """
        findings: List[ComplianceFinding] = []

        # 1. NIST SP 800-52 Rev. 2 Evaluation
        # Section 3.1: Protocol Version (Mandates TLS 1.2 or TLS 1.3)
        if session.negotiated_tls_version in (TLSVersion.TLSv1_2, TLSVersion.TLSv1_3):
            findings.append(
                ComplianceFinding(
                    standard="NIST SP 800-52r2",
                    section="3.1",
                    status=ComplianceStatus.COMPLIANT,
                    title="Approved TLS Protocol Version",
                    description=f"Session negotiated modern protocol {session.negotiated_tls_version.value}.",
                    remediation="Maintain existing protocol configuration.",
                )
            )
        elif session.negotiated_tls_version in (TLSVersion.SSLv2, TLSVersion.SSLv3, TLSVersion.TLSv1_0, TLSVersion.TLSv1_1):
            findings.append(
                ComplianceFinding(
                    standard="NIST SP 800-52r2",
                    section="3.1",
                    status=ComplianceStatus.NON_COMPLIANT,
                    title="Prohibited Legacy Protocol Version",
                    description=f"Session negotiated deprecated protocol {session.negotiated_tls_version.value}.",
                    remediation="Disable SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 on mail server daemons.",
                )
            )
        elif session.protocol in (EmailProtocol.SMTP, EmailProtocol.IMAP, EmailProtocol.POP3) and not session.starttls_negotiated:
            findings.append(
                ComplianceFinding(
                    standard="NIST SP 800-52r2",
                    section="3.1",
                    status=ComplianceStatus.NON_COMPLIANT,
                    title="Unencrypted Cleartext Email Communication",
                    description="Mail session operated in cleartext without TLS encapsulation.",
                    remediation="Enforce mandatory STARTTLS with strict fallback rejection.",
                )
            )

        # Section 3.3.1: Forward Secrecy
        if session.cipher_suite:
            if session.cipher_suite.provides_forward_secrecy:
                findings.append(
                    ComplianceFinding(
                        standard="NIST SP 800-52r2",
                        section="3.3.1",
                        status=ComplianceStatus.COMPLIANT,
                        title="Perfect Forward Secrecy Enforced",
                        description=f"Cipher uses ephemeral {session.cipher_suite.key_exchange} key exchange.",
                        remediation="No action required.",
                    )
                )
            else:
                findings.append(
                    ComplianceFinding(
                        standard="NIST SP 800-52r2",
                        section="3.3.1",
                        status=ComplianceStatus.NON_COMPLIANT,
                        title="Lack of Perfect Forward Secrecy",
                        description=f"Cipher {session.cipher_suite.iana_name} uses static key exchange without PFS.",
                        remediation="Configure server cipher suite order to prioritize ECDHE and DHE key exchanges.",
                    )
                )

            # Section 3.3.1.1: Authenticated Encryption (AEAD)
            if session.cipher_suite.is_aead:
                findings.append(
                    ComplianceFinding(
                        standard="NIST SP 800-52r2",
                        section="3.3.1.1",
                        status=ComplianceStatus.COMPLIANT,
                        title="Authenticated Encryption with Associated Data (AEAD)",
                        description=f"Negotiated AEAD mode {session.cipher_suite.encryption}.",
                        remediation="No action required.",
                    )
                )
            else:
                findings.append(
                    ComplianceFinding(
                        standard="NIST SP 800-52r2",
                        section="3.3.1.1",
                        status=ComplianceStatus.WARNING,
                        title="Legacy CBC Mode Cipher in Use",
                        description=f"Cipher {session.cipher_suite.iana_name} uses CBC mode which is susceptible to padding oracles.",
                        remediation="Migrate cipher suite configuration to AES-GCM or ChaCha20-Poly1305.",
                    )
                )

        # 2. PCI-DSS v4.0 Requirement 4.2.1
        if session.negotiated_tls_version in (TLSVersion.SSLv2, TLSVersion.SSLv3, TLSVersion.TLSv1_0, TLSVersion.TLSv1_1):
            findings.append(
                ComplianceFinding(
                    standard="PCI-DSS v4.0",
                    section="Req 4.2.1",
                    status=ComplianceStatus.NON_COMPLIANT,
                    title="Early TLS / SSL Prohibited",
                    description="PCI-DSS v4.0 explicitly disallows SSL and early TLS for cardholder/PAN data protection.",
                    remediation="Upgrade mail gateway to TLS 1.2 minimum and restrict cipher selection.",
                )
            )
        elif session.negotiated_tls_version in (TLSVersion.TLSv1_2, TLSVersion.TLSv1_3):
            findings.append(
                ComplianceFinding(
                    standard="PCI-DSS v4.0",
                    section="Req 4.2.1",
                    status=ComplianceStatus.COMPLIANT,
                    title="Strong Cryptography Requirement Satisfied",
                    description="Negotiated TLS version meets PCI-DSS v4.0 strong cryptography criteria.",
                    remediation="Ensure ongoing cipher audit and certificate renewal monitoring.",
                )
            )

        # 3. Certificate Compliance
        for cert in session.certificates:
            if cert.is_expired:
                findings.append(
                    ComplianceFinding(
                        standard="CIS Benchmark",
                        section="2.1.4",
                        status=ComplianceStatus.NON_COMPLIANT,
                        title="Expired Server Certificate",
                        description=f"Certificate for {cert.subject_dn} expired {abs(cert.days_until_expiration)} days ago.",
                        remediation="Immediately renew and deploy a valid CA-signed X.509 certificate.",
                    )
                )
            if cert.is_self_signed:
                findings.append(
                    ComplianceFinding(
                        standard="CIS Benchmark",
                        section="2.1.5",
                        status=ComplianceStatus.WARNING,
                        title="Self-Signed Certificate Detected",
                        description=f"Certificate {cert.subject_dn} is self-signed and untrusted by standard trust stores.",
                        remediation="Replace self-signed certificates with certificates from an accredited Public or Enterprise CA.",
                    )
                )
            if cert.public_key_algorithm == "RSA" and cert.key_size_bits < 2048:
                findings.append(
                    ComplianceFinding(
                        standard="NIST SP 800-52r2",
                        section="3.2.1",
                        status=ComplianceStatus.NON_COMPLIANT,
                        title="Inadequate Public Key Size",
                        description=f"RSA key size of {cert.key_size_bits} bits is below NIST minimum 2048-bit threshold.",
                        remediation="Regenerate private key and certificate with RSA >= 2048 bits or ECDSA >= 256 bits.",
                    )
                )
            if cert.is_weak_signature:
                findings.append(
                    ComplianceFinding(
                        standard="NIST SP 800-52r2",
                        section="3.2.2",
                        status=ComplianceStatus.NON_COMPLIANT,
                        title="Weak Certificate Digest Algorithm",
                        description=f"Certificate signature uses deprecated digest algorithm {cert.signature_algorithm}.",
                        remediation="Reissue certificate utilizing SHA-256 or stronger digest signatures.",
                    )
                )

        return findings

    def assess_session_vulnerabilities(
        self, session: TLSSessionDetails
    ) -> Tuple[List[str], List[ComplianceFinding], float]:
        """
        Aggregates CVE associations, compliance findings, and calculates
        a deterministic rule-based penalty score (0.0 to 100.0).
        """
        cves: List[str] = []
        penalty: float = 0.0

        # Protocol Version Penalties & CVEs
        if session.negotiated_tls_version == TLSVersion.SSLv2:
            penalty += 50.0
            cves.extend(["CVE-2016-0800 (DROWN)", "Obsolete SSL 2.0 Insecurity"])
        elif session.negotiated_tls_version == TLSVersion.SSLv3:
            penalty += 45.0
            cves.extend(["CVE-2014-3566 (POODLE)"])
        elif session.negotiated_tls_version == TLSVersion.TLSv1_0:
            penalty += 35.0
            cves.extend(["CVE-2011-3389 (BEAST)"])
        elif session.negotiated_tls_version == TLSVersion.TLSv1_1:
            penalty += 25.0
            cves.extend(["Deprecated TLS 1.1 Configuration"])

        # Downgrade attack detection penalty
        if session.starttls_downgrade_detected:
            penalty += 50.0
            cves.append("STARTTLS Stripping / Downgrade Attack Detected")

        # Cleartext unencrypted email traffic
        if not session.handshake_completed and session.negotiated_tls_version == TLSVersion.UNKNOWN:
            penalty += 40.0
            cves.append("Plaintext Cleartext Mail Transmission")

        # Cipher Suite Penalties
        if session.cipher_suite:
            if session.cipher_suite.known_vulnerabilities:
                cves.extend(session.cipher_suite.known_vulnerabilities)
            if not session.cipher_suite.provides_forward_secrecy:
                penalty += 15.0
            if not session.cipher_suite.is_aead:
                penalty += 10.0
            if session.cipher_suite.is_deprecated:
                penalty += 20.0
            if session.cipher_suite.key_size < 128:
                penalty += 30.0

        # Certificate Penalties
        for cert in session.certificates:
            if cert.is_expired:
                penalty += 30.0
                cves.append("Expired X.509 Certificate")
            if cert.is_self_signed:
                penalty += 15.0
                cves.append("Untrusted Self-Signed Certificate")
            if cert.is_weak_signature:
                penalty += 25.0
                cves.append("Weak Certificate Signature Digest (MD5/SHA1)")
            if cert.public_key_algorithm == "RSA" and cert.key_size_bits < 2048:
                penalty += 25.0
                cves.append(f"Sub-standard RSA Key Size ({cert.key_size_bits}-bit)")

        compliance_findings = self.evaluate_compliance(session)

        # Clamp deterministic penalty to 0.0 - 100.0
        normalized_penalty = min(100.0, max(0.0, penalty))
        return list(set(cves)), compliance_findings, normalized_penalty
