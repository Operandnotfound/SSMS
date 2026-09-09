"""
Comprehensive Pipeline and Vulnerability Verification Tests for SecureMailScope.
Validates PCAP packet ingestion, STARTTLS state tracking, downgrade detection,
cipher and X.509 validation, ML anomaly scoring, XAI attribution, and REST API routes.
"""

import io
import socket
import struct
import unittest
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from securemailscope.api import app
from securemailscope.crypto_validator import CryptographicValidator
from securemailscope.ml_engine import FeatureExtractor, MLRiskEngine
from securemailscope.models import (
    ComplianceStatus,
    EmailProtocol,
    RiskSeverity,
    TLSVersion,
)
from securemailscope.reporting import ForensicReportGenerator
from securemailscope.traffic_processor import TrafficProcessor


def create_mock_certificate_der(common_name: str = "mail.example.com", key_size: int = 2048) -> bytes:
    """Helper to generate a self-contained X.509 certificate in ASN.1 DER format."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def build_raw_packet(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, seq: int, ack: int, payload: bytes
) -> bytes:
    """Synthesizes Ethernet II + IPv4 + TCP frame bytes."""
    # Ethernet Header (14 bytes)
    eth_hdr = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    
    # IPv4 Header (20 bytes)
    ihl_ver = (4 << 4) | 5
    total_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        ihl_ver, 0, total_len, 54321, 0, 64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    )

    # TCP Header (20 bytes)
    offset_flags = (5 << 12) | 0x18  # Data offset 5 (20 bytes), PSH+ACK
    tcp_hdr = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, 65535, 0, 0)

    return eth_hdr + ip_hdr + tcp_hdr + payload


def build_pcap_bytes(packets: list[bytes]) -> bytes:
    """Builds a complete binary PCAP file from a list of raw frames."""
    # Global header (24 bytes)
    magic = 0xA1B2C3D4
    pcap_hdr = struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 65535, 1)  # Link-Layer: Ethernet (1)
    
    buf = bytearray(pcap_hdr)
    ts_sec = 1700000000
    for idx, pkt in enumerate(packets):
        ts_usec = idx * 1000
        pkt_len = len(pkt)
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
        buf.extend(pkt_hdr)
        buf.extend(pkt)
    return bytes(buf)


def build_tls_client_hello(ciphers: list[int]) -> bytes:
    """Constructs a minimal TLS 1.2 ClientHello Record."""
    client_random = b"\xaa" * 32
    session_id_len = 0
    ciphers_bytes = struct.pack(f"!H{len(ciphers)}H", len(ciphers) * 2, *ciphers)
    comp_methods = b"\x01\x00"  # 1 method: null compression
    
    handshake_body = struct.pack("!H", 0x0303) + client_random + struct.pack("!B", session_id_len) + ciphers_bytes + comp_methods
    
    msg_type = 1  # ClientHello
    msg_len = len(handshake_body)
    handshake_hdr = struct.pack("!B", msg_type) + struct.pack("!I", msg_len)[1:]  # 3-byte len
    handshake_msg = handshake_hdr + handshake_body
    
    # Record layer (ContentType 22 = Handshake, Version 0x0303, Length)
    record = struct.pack("!BHH", 22, 0x0303, len(handshake_msg)) + handshake_msg
    return record


def build_tls_server_hello(cipher_id: int) -> bytes:
    """Constructs a minimal TLS 1.2 ServerHello Record."""
    server_random = b"\xbb" * 32
    session_id_len = 0
    selected_cipher = struct.pack("!H", cipher_id)
    comp_method = b"\x00"
    
    handshake_body = struct.pack("!H", 0x0303) + server_random + struct.pack("!B", session_id_len) + selected_cipher + comp_method
    
    msg_type = 2  # ServerHello
    msg_len = len(handshake_body)
    handshake_hdr = struct.pack("!B", msg_type) + struct.pack("!I", msg_len)[1:]
    handshake_msg = handshake_hdr + handshake_body
    
    record = struct.pack("!BHH", 22, 0x0303, len(handshake_msg)) + handshake_msg
    return record


class TestSecureMailScope(unittest.TestCase):
    """End-to-End Test Suite for SecureMailScope."""

    def setUp(self):
        self.client = TestClient(app)
        self.validator = CryptographicValidator()
        self.ml_engine = MLRiskEngine()

    def test_cipher_suite_resolution(self):
        """Test resolving modern AEAD cipher with Perfect Forward Secrecy."""
        details = self.validator.resolve_cipher_suite(0xC02F)
        self.assertEqual(details.iana_name, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        self.assertTrue(details.provides_forward_secrecy)
        self.assertTrue(details.is_aead)
        self.assertFalse(details.is_deprecated)

    def test_weak_cipher_detection(self):
        """Test detection of deprecated 3DES cipher vulnerable to SWEET32."""
        details = self.validator.resolve_cipher_suite(0x000A)
        self.assertEqual(details.iana_name, "TLS_RSA_WITH_3DES_EDE_CBC_SHA")
        self.assertFalse(details.provides_forward_secrecy)
        self.assertTrue(details.is_deprecated)
        self.assertTrue(any("SWEET32" in v for v in details.known_vulnerabilities))

    def test_x509_certificate_validation(self):
        """Test parsing and validating self-signed X.509 certificates."""
        der_data = create_mock_certificate_der("mail.company.com", key_size=2048)
        cert_details_list = self.validator.validate_x509_certificates([der_data])
        self.assertEqual(len(cert_details_list), 1)
        cert = cert_details_list[0]
        self.assertTrue("mail.company.com" in cert.subject_dn)
        self.assertEqual(cert.public_key_algorithm, "RSA")
        self.assertEqual(cert.key_size_bits, 2048)
        self.assertFalse(cert.is_expired)
        self.assertTrue(cert.is_self_signed)

    def test_end_to_end_pcap_pipeline_and_api(self):
        """
        Synthesizes a multi-session PCAP:
        Session 1: SMTP STARTTLS negotiation with TLS 1.2 ECDHE-GCM (Compliant)
        Session 2: SMTP STARTTLS Downgrade Attack (STRIPTLS)
        """
        packets = []

        # --- SESSION 1: Hardened SMTP with STARTTLS ---
        s1_cli_ip, s1_cli_port = "192.168.1.100", 49152
        s1_srv_ip, s1_srv_port = "10.0.0.25", 25

        # 1. Server greeting
        p1 = build_raw_packet(s1_srv_ip, s1_srv_port, s1_cli_ip, s1_cli_port, 1, 1, b"220 mail.corp.internal ESMTP Postfix\r\n")
        # 2. Client EHLO
        p2 = build_raw_packet(s1_cli_ip, s1_cli_port, s1_srv_ip, s1_srv_port, 1, 100, b"EHLO client.internal\r\n")
        # 3. Server 250 STARTTLS
        p3 = build_raw_packet(s1_srv_ip, s1_srv_port, s1_cli_ip, s1_cli_port, 100, 50, b"250-mail.corp.internal\r\n250 STARTTLS\r\n")
        # 4. Client STARTTLS
        p4 = build_raw_packet(s1_cli_ip, s1_cli_port, s1_srv_ip, s1_srv_port, 50, 200, b"STARTTLS\r\n")
        # 5. Server 220 Ready
        p5 = build_raw_packet(s1_srv_ip, s1_srv_port, s1_cli_ip, s1_cli_port, 200, 60, b"220 2.0.0 Ready to start TLS\r\n")
        # 6. TLS ClientHello (offering 0xC02F)
        p6 = build_raw_packet(s1_cli_ip, s1_cli_port, s1_srv_ip, s1_srv_port, 60, 250, build_tls_client_hello([0xC02F]))
        # 7. TLS ServerHello (selecting 0xC02F)
        p7 = build_raw_packet(s1_srv_ip, s1_srv_port, s1_cli_ip, s1_cli_port, 250, 160, build_tls_server_hello(0xC02F))

        packets.extend([p1, p2, p3, p4, p5, p6, p7])

        # --- SESSION 2: STARTTLS Downgrade Attack ---
        s2_cli_ip, s2_cli_port = "192.168.1.101", 49153
        s2_srv_ip, s2_srv_port = "10.0.0.25", 587

        # 1. Server greeting
        p8 = build_raw_packet(s2_srv_ip, s2_srv_port, s2_cli_ip, s2_cli_port, 1, 1, b"220 submission.corp.internal ESMTP\r\n")
        # 2. Client EHLO
        p9 = build_raw_packet(s2_cli_ip, s2_cli_port, s2_srv_ip, s2_srv_port, 1, 50, b"EHLO laptop.internal\r\n")
        # 3. Server advertises STARTTLS
        p10 = build_raw_packet(s2_srv_ip, s2_srv_port, s2_cli_ip, s2_cli_port, 50, 50, b"250-submission.corp.internal\r\n250 STARTTLS\r\n")
        # 4. Insecure client sends cleartext AUTH immediately instead of STARTTLS (downgrade!)
        p11 = build_raw_packet(s2_cli_ip, s2_cli_port, s2_srv_ip, s2_srv_port, 50, 100, b"AUTH PLAIN dXNlcjE6cGFzc3dvcmQxMjM=\r\n")

        packets.extend([p8, p9, p10, p11])

        pcap_data = build_pcap_bytes(packets)

        # 1. Test PCAP Ingestion in TrafficProcessor
        processor = TrafficProcessor()
        sessions = processor.process_pcap_stream(io.BytesIO(pcap_data))
        self.assertEqual(len(sessions), 2)

        # Verify Session 1 (STARTTLS upgraded)
        s1 = next(s for s in sessions if s.client_port == s1_cli_port)
        self.assertEqual(s1.protocol, EmailProtocol.SMTP)
        self.assertTrue(s1.starttls_command_seen)
        self.assertTrue(s1.starttls_negotiated)
        self.assertEqual(s1.negotiated_tls_version, TLSVersion.TLSv1_2)

        # Verify Session 2 (Downgrade detected)
        s2 = next(s for s in sessions if s.client_port == s2_cli_port)
        self.assertEqual(s2.protocol, EmailProtocol.SMTP)
        self.assertTrue(s2.starttls_downgrade_detected)

        # 2. Test API Upload Endpoint
        response = self.client.post(
            "/api/v1/analyze/pcap",
            files={"file": ("capture.pcap", pcap_data, "application/octet-stream")},
        )
        self.assertEqual(response.status_code, 200)
        report_data = response.json()

        self.assertEqual(report_data["total_sessions_parsed"], 2)
        self.assertEqual(report_data["downgrade_attacks_detected"], 1)
        self.assertTrue("analysis_id" in report_data)

        # Verify downgrade session has elevated risk score
        downgrade_assessments = [
            s for s in report_data["sessions"]
            if any("Downgrade" in exp["human_readable_reason"] for exp in s["anomaly_explanations"])
            or any("Downgrade" in cve for cve in s["cve_associations"])
        ]
        self.assertTrue(len(downgrade_assessments) >= 1)
        self.assertGreaterEqual(downgrade_assessments[0]["overall_risk_score"], 80.0)

        analysis_id = report_data["analysis_id"]

        # 3. Test HTML Report Generation Endpoint
        html_response = self.client.get(f"/api/v1/reports/{analysis_id}/html")
        self.assertEqual(html_response.status_code, 200)
        self.assertIn("SecureMailScope Forensic Report", html_response.text)
        self.assertIn("STARTTLS", html_response.text)

        # 4. Test Dashboard Schema Endpoint
        dash_response = self.client.get(f"/api/v1/reports/{analysis_id}/dashboard")
        self.assertEqual(dash_response.status_code, 200)
        dash_data = dash_response.json()
        self.assertEqual(dash_data["analysis_id"], analysis_id)
        self.assertEqual(len(dash_data["metrics"]), 4)


if __name__ == "__main__":
    unittest.main()
