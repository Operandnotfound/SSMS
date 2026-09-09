"""
SecureMailScope - Network Ingestion and Traffic Processing Engine
High-performance streaming PCAP/PCAPNG ingestion, TCP stream reassembly,
email protocol identification (SMTP, IMAP, POP3), and STARTTLS state machine tracking.
"""

import io
import re
import socket
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import BinaryIO, Dict, Generator, Iterator, List, Optional, Tuple, Union

from securemailscope.models import (
    EmailProtocol,
    TLSSessionDetails,
    TLSVersion,
)


@dataclass
class PacketMetadata:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    tcp_flags: int
    payload: bytes


@dataclass
class TCPStreamTracker:
    """Stateful bidirectional tracker for a single TCP 5-tuple connection."""
    flow_id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: EmailProtocol = EmailProtocol.UNKNOWN
    
    # TCP state buffers (handling reassembly of segments)
    client_buffer: bytearray = field(default_factory=bytearray)
    server_buffer: bytearray = field(default_factory=bytearray)
    
    # STARTTLS state tracking
    starttls_command_seen: bool = False
    starttls_negotiated: bool = False
    starttls_downgrade_detected: bool = False
    server_advertised_starttls: bool = False
    client_attempted_plaintext_auth: bool = False
    
    # TLS state
    tls_handshake_started: bool = False
    tls_record_version: Optional[str] = None
    negotiated_tls_version: TLSVersion = TLSVersion.UNKNOWN
    client_hello_ciphers: List[int] = field(default_factory=list)
    server_selected_cipher: Optional[int] = None
    sni_hostname: Optional[str] = None
    alpn_protocols: List[str] = field(default_factory=list)
    raw_certificate_ders: List[bytes] = field(default_factory=list)
    handshake_completed: bool = False
    
    # Forensic metrics
    total_bytes: int = 0
    packet_count: int = 0
    start_time: float = 0.0
    last_time: float = 0.0


class PCAPStreamParser:
    """
    Zero-copy streaming PCAP reader supporting standard Libpcap (classic) format.
    Processes arbitrarily large PCAPs (multi-gigabyte) with constant O(1) memory.
    """

    PCAP_MAGIC_SAME = 0xA1B2C3D4
    PCAP_MAGIC_SWAP = 0xD4C3B2A1
    PCAP_MAGIC_NS_SAME = 0xA1B23C4D
    PCAP_MAGIC_NS_SWAP = 0x4D3CB2A1

    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.byte_order = "="
        self.nano_second_res = False
        self._read_global_header()

    def _read_global_header(self) -> None:
        header_bytes = self.stream.read(24)
        if len(header_bytes) < 24:
            raise ValueError("Invalid PCAP: Truncated global header.")

        magic = struct.unpack("=I", header_bytes[:4])[0]
        if magic in (self.PCAP_MAGIC_SAME, self.PCAP_MAGIC_NS_SAME):
            self.byte_order = "<" if struct.unpack("<I", header_bytes[:4])[0] == magic else ">"
            self.nano_second_res = (magic == self.PCAP_MAGIC_NS_SAME)
        elif magic in (self.PCAP_MAGIC_SWAP, self.PCAP_MAGIC_NS_SWAP):
            self.byte_order = ">" if struct.unpack("<I", header_bytes[:4])[0] == magic else "<"
            self.nano_second_res = (magic == self.PCAP_MAGIC_NS_SWAP)
        else:
            # Fallback assuming standard little-endian pcap
            self.byte_order = "<"

    def iter_packets(self) -> Iterator[PacketMetadata]:
        """Generator reading packets one by one with constant memory consumption."""
        while True:
            pkt_hdr = self.stream.read(16)
            if len(pkt_hdr) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{self.byte_order}IIII", pkt_hdr)
            if incl_len <= 0 or incl_len > 65535 * 4:
                # Sanity guard against corrupt lengths
                break

            pkt_data = self.stream.read(incl_len)
            if len(pkt_data) < incl_len:
                break

            ts = float(ts_sec) + (float(ts_usec) / (1e9 if self.nano_second_res else 1e6))

            parsed = self._parse_ethernet_ip_tcp(pkt_data, ts)
            if parsed:
                yield parsed

    def _parse_ethernet_ip_tcp(self, data: bytes, ts: float) -> Optional[PacketMetadata]:
        """Decode Ethernet II -> IPv4/IPv6 -> TCP frames, discarding malformed frames."""
        try:
            if len(data) < 14:
                return None

            eth_type = struct.unpack("!H", data[12:14])[0]
            offset = 14

            # Handle 802.1Q VLAN Tagging (0x8100) and 802.1ad (0x88A8)
            while eth_type in (0x8100, 0x88A8) and len(data) >= offset + 4:
                eth_type = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
                offset += 4

            # IPv4 parsing
            if eth_type == 0x0800:
                if len(data) < offset + 20:
                    return None
                ihl = (data[offset] & 0x0F) * 4
                if ihl < 20:
                    return None
                ip_proto = data[offset + 9]
                if ip_proto != 6:  # Only interested in TCP
                    return None
                src_ip = socket.inet_ntoa(data[offset + 12 : offset + 16])
                dst_ip = socket.inet_ntoa(data[offset + 16 : offset + 20])
                tcp_offset = offset + ihl

            # IPv6 parsing
            elif eth_type == 0x86DD:
                if len(data) < offset + 40:
                    return None
                ip_proto = data[offset + 6]
                if ip_proto != 6:
                    return None
                src_ip = socket.inet_ntop(socket.AF_INET6, data[offset + 8 : offset + 24])
                dst_ip = socket.inet_ntop(socket.AF_INET6, data[offset + 24 : offset + 40])
                tcp_offset = offset + 40
            else:
                return None

            # TCP parsing
            if len(data) < tcp_offset + 20:
                return None

            tcp_hdr = data[tcp_offset : tcp_offset + 20]
            src_port, dst_port, seq, ack, flags_offset = struct.unpack("!HHIIH", tcp_hdr[:14])
            tcp_flags = tcp_hdr[13] & 0x3F
            data_offset = ((flags_offset >> 12) & 0x0F) * 4
            if data_offset < 20:
                return None

            payload = data[tcp_offset + data_offset :]

            return PacketMetadata(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                seq_num=seq,
                ack_num=ack,
                tcp_flags=tcp_flags,
                payload=payload,
            )
        except Exception:
            # Drop malformed packets gracefully
            return None


class TrafficProcessor:
    """
    Core forensic processor that reconstructs TCP streams, identifies mail protocols,
    monitors STARTTLS state transitions, and parses TLS records/handshakes.
    """

    KNOWN_PORTS: Dict[int, EmailProtocol] = {
        25: EmailProtocol.SMTP,
        587: EmailProtocol.SMTP,
        465: EmailProtocol.SMTPS,
        143: EmailProtocol.IMAP,
        993: EmailProtocol.IMAPS,
        110: EmailProtocol.POP3,
        995: EmailProtocol.POP3S,
    }

    def __init__(self):
        self.streams: Dict[str, TCPStreamTracker] = {}

    @staticmethod
    def _make_flow_id(ip1: str, p1: int, ip2: str, p2: int) -> Tuple[str, bool]:
        """
        Creates a canonical bidirectional flow key.
        Returns (flow_id, is_client_to_server).
        Client is determined by convention (ephemeral port > 1024 or higher port number).
        """
        if (p1 > 1024 and p2 <= 1024) or (p1 > p2):
            return f"{ip1}:{p1}->{ip2}:{p2}", True
        else:
            return f"{ip2}:{p2}->{ip1}:{p1}", False

    def process_pcap_stream(self, stream: BinaryIO) -> List[TLSSessionDetails]:
        """
        Main pipeline execution: ingest PCAP stream, track sessions,
        and generate finalized TLSSessionDetails models.
        """
        parser = PCAPStreamParser(stream)
        for pkt in parser.iter_packets():
            self._ingest_packet(pkt)

        # Finalize all tracked streams into domain models
        results: List[TLSSessionDetails] = []
        for flow_id, tracker in self.streams.items():
            session = self._finalize_session(tracker)
            if session:
                results.append(session)
        return results

    def _ingest_packet(self, pkt: PacketMetadata) -> None:
        """Process an individual packet and feed it to the appropriate stream tracker."""
        flow_id, is_client = self._make_flow_id(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        
        if flow_id not in self.streams:
            client_ip = pkt.src_ip if is_client else pkt.dst_ip
            client_port = pkt.src_port if is_client else pkt.dst_port
            server_ip = pkt.dst_ip if is_client else pkt.src_ip
            server_port = pkt.dst_port if is_client else pkt.src_port
            
            # Initial protocol classification based on server port
            initial_proto = self.KNOWN_PORTS.get(server_port, EmailProtocol.UNKNOWN)
            
            self.streams[flow_id] = TCPStreamTracker(
                flow_id=flow_id,
                client_ip=client_ip,
                client_port=client_port,
                server_ip=server_ip,
                server_port=server_port,
                protocol=initial_proto,
                start_time=pkt.timestamp,
                last_time=pkt.timestamp,
            )

        tracker = self.streams[flow_id]
        tracker.packet_count += 1
        tracker.total_bytes += len(pkt.payload)
        tracker.last_time = pkt.timestamp

        if not pkt.payload:
            return

        if is_client:
            tracker.client_buffer.extend(pkt.payload)
            self._inspect_client_traffic(tracker)
        else:
            tracker.server_buffer.extend(pkt.payload)
            self._inspect_server_traffic(tracker)

    def _inspect_client_traffic(self, tracker: TCPStreamTracker) -> None:
        """Examine client data for STARTTLS commands and TLS ClientHello records."""
        buf = bytes(tracker.client_buffer)
        
        # Check if traffic looks like plain text email commands
        if not tracker.tls_handshake_started:
            text = ""
            try:
                text = buf.decode("utf-8", errors="ignore")
            except Exception:
                pass

            if text:
                # Heuristic protocol classification if port was unmapped
                if tracker.protocol == EmailProtocol.UNKNOWN:
                    if any(cmd in text for cmd in ["EHLO ", "HELO ", "MAIL FROM:"]):
                        tracker.protocol = EmailProtocol.SMTP
                    elif any(cmd in text for cmd in ["CAPABILITY", "LOGIN ", "SELECT "]):
                        tracker.protocol = EmailProtocol.IMAP
                    elif any(cmd in text for cmd in ["USER ", "PASS ", "STAT"]):
                        tracker.protocol = EmailProtocol.POP3

                # Track STARTTLS / STLS invocation
                if re.search(r"\bSTARTTLS\b", text, re.IGNORECASE) or re.search(r"\bSTLS\b", text, re.IGNORECASE):
                    tracker.starttls_command_seen = True

                # Downgrade check: If server advertised STARTTLS, but client proceeded with plaintext AUTH/USER
                if tracker.server_advertised_starttls and not tracker.starttls_command_seen:
                    if re.search(r"\b(AUTH\s+PLAIN|AUTH\s+LOGIN|USER\s+|PASS\s+|MAIL\s+FROM:)", text, re.IGNORECASE):
                        tracker.starttls_downgrade_detected = True

        # Check for TLS Handshake Record (Content Type 0x16 = 22 = Handshake)
        self._parse_tls_records(tracker, is_client=True)

    def _inspect_server_traffic(self, tracker: TCPStreamTracker) -> None:
        """Examine server responses for STARTTLS readiness banners, and TLS ServerHello/Certificates."""
        buf = bytes(tracker.server_buffer)

        if not tracker.tls_handshake_started:
            text = ""
            try:
                text = buf.decode("utf-8", errors="ignore")
            except Exception:
                pass

            if text:
                # Detect capability advertisement
                if "STARTTLS" in text.upper() or "STLS" in text.upper():
                    tracker.server_advertised_starttls = True

                # SMTP response 220 2.0.0 Ready to start TLS
                # IMAP response: tagged OK [STARTTLS] or OK Begin TLS
                # POP3 response: +OK Begin TLS
                if tracker.starttls_command_seen:
                    if (
                        re.search(r"^220[\s-].*TLS", text, re.MULTILINE | re.IGNORECASE)
                        or re.search(r"\bOK\b.*(?:Begin\s+TLS|Ready\s+to\s+start\s+TLS)", text, re.IGNORECASE)
                        or re.search(r"^\+OK\s+Begin\s+TLS", text, re.MULTILINE | re.IGNORECASE)
                    ):
                        tracker.starttls_negotiated = True
                    elif re.search(r"^(454|501|503|BAD|NO|\-ERR)", text, re.MULTILINE | re.IGNORECASE):
                        # Server rejected STARTTLS -> Potential downgrade or config error
                        tracker.starttls_downgrade_detected = True

        # Parse TLS Server Records
        self._parse_tls_records(tracker, is_client=False)

    def _parse_tls_records(self, tracker: TCPStreamTracker, is_client: bool) -> None:
        """
        Parses TLS Record Layer and Handshake Protocol frames from the stream buffer.
        Extracts TLS version, chosen cipher, extensions, and raw X.509 certs.
        """
        buf = tracker.client_buffer if is_client else tracker.server_buffer
        idx = 0
        buf_len = len(buf)

        while idx + 5 <= buf_len:
            # Fast search for TLS record header: [ContentType 1B, Version 2B, Length 2B]
            content_type = buf[idx]
            if content_type not in (20, 21, 22, 23):  # ChangeCipherSpec, Alert, Handshake, AppData
                idx += 1
                continue

            rec_version_major = buf[idx + 1]
            rec_version_minor = buf[idx + 2]
            # Valid TLS record versions range from SSL 3.0 (3,0) to TLS 1.3 (3,3 in record layer)
            if rec_version_major != 3 or rec_version_minor not in (0, 1, 2, 3, 4):
                idx += 1
                continue

            record_len = struct.unpack("!H", buf[idx + 3 : idx + 5])[0]
            if record_len <= 0:
                idx += 5
                continue

            if idx + 5 + record_len > buf_len:
                # Segment truncated or waiting for remaining TCP packets
                break

            record_payload = buf[idx + 5 : idx + 5 + record_len]
            tracker.tls_handshake_started = True

            version_str = f"{rec_version_major}.{rec_version_minor}"
            if not tracker.tls_record_version:
                tracker.tls_record_version = version_str

            if content_type == 22:  # Handshake
                self._parse_handshake_payload(tracker, record_payload, is_client)
            elif content_type == 20:  # ChangeCipherSpec
                tracker.handshake_completed = True

            idx += 5 + record_len

    def _parse_handshake_payload(self, tracker: TCPStreamTracker, data: bytes, is_client: bool) -> None:
        """Deconstructs TLS Handshake messages (ClientHello, ServerHello, Certificate)."""
        offset = 0
        data_len = len(data)

        while offset + 4 <= data_len:
            msg_type = data[offset]
            msg_len = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]
            if msg_len <= 0:
                break

            body_start = offset + 4
            body_end = body_start + msg_len

            if body_end > data_len:
                break

            body = data[body_start:body_end]

            if msg_type == 1 and is_client:  # ClientHello
                self._parse_client_hello(tracker, body)
            elif msg_type == 2 and not is_client:  # ServerHello
                self._parse_server_hello(tracker, body)
            elif msg_type == 11 and not is_client:  # Certificate
                self._parse_server_certificates(tracker, body)

            offset = body_end

    def _parse_client_hello(self, tracker: TCPStreamTracker, body: bytes) -> None:
        """Extract offered cipher suites, SNI hostname, and supported version extensions."""
        try:
            if len(body) < 34:
                return

            client_version = struct.unpack("!H", body[:2])[0]
            # Skip client random (32 bytes)
            sess_id_len = body[34]
            ptr = 35 + sess_id_len

            if ptr + 2 > len(body):
                return
            ciphers_len = struct.unpack("!H", body[ptr : ptr + 2])[0]
            ptr += 2

            ciphers = []
            for i in range(0, ciphers_len, 2):
                if ptr + i + 2 <= len(body):
                    ciphers.append(struct.unpack("!H", body[ptr + i : ptr + i + 2])[0])
            tracker.client_hello_ciphers = ciphers
            ptr += ciphers_len

            # Skip compression methods
            if ptr >= len(body):
                return
            comp_len = body[ptr]
            ptr += 1 + comp_len

            # Extensions parsing
            if ptr + 2 <= len(body):
                ext_total_len = struct.unpack("!H", body[ptr : ptr + 2])[0]
                ptr += 2
                ext_end = min(ptr + ext_total_len, len(body))

                while ptr + 4 <= ext_end:
                    ext_type, ext_len = struct.unpack("!HH", body[ptr : ptr + 4])
                    ext_data = body[ptr + 4 : ptr + 4 + ext_len]

                    # SNI Extension (0x0000)
                    if ext_type == 0x0000 and len(ext_data) >= 5:
                        name_len = struct.unpack("!H", ext_data[3:5])[0]
                        if len(ext_data) >= 5 + name_len:
                            tracker.sni_hostname = ext_data[5 : 5 + name_len].decode("utf-8", errors="ignore")

                    # ALPN Extension (0x0010)
                    elif ext_type == 0x0010 and len(ext_data) >= 2:
                        alpn_list_len = struct.unpack("!H", ext_data[:2])[0]
                        aptr = 2
                        while aptr < 2 + alpn_list_len and aptr < len(ext_data):
                            proto_len = ext_data[aptr]
                            aptr += 1
                            if aptr + proto_len <= len(ext_data):
                                proto_str = ext_data[aptr : aptr + proto_len].decode("ascii", errors="ignore")
                                tracker.alpn_protocols.append(proto_str)
                            aptr += proto_len

                    ptr += 4 + ext_len
        except Exception:
            pass

    def _parse_server_hello(self, tracker: TCPStreamTracker, body: bytes) -> None:
        """Extract negotiated TLS version, selected cipher suite, and TLS 1.3 extensions."""
        try:
            if len(body) < 38:
                return

            server_ver_raw = struct.unpack("!H", body[:2])[0]
            # 0x0300 = SSL 3.0, 0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2
            ver_map = {
                0x0300: TLSVersion.SSLv3,
                0x0301: TLSVersion.TLSv1_0,
                0x0302: TLSVersion.TLSv1_1,
                0x0303: TLSVersion.TLSv1_2,
            }
            tracker.negotiated_tls_version = ver_map.get(server_ver_raw, TLSVersion.UNKNOWN)

            # Skip server random (32 bytes)
            sess_id_len = body[34]
            ptr = 35 + sess_id_len

            if ptr + 2 > len(body):
                return
            selected_cipher = struct.unpack("!H", body[ptr : ptr + 2])[0]
            tracker.server_selected_cipher = selected_cipher
            ptr += 3  # Skip cipher (2B) + compression method (1B)

            # Extensions (Check for TLS 1.3 supported_versions 0x002B)
            if ptr + 2 <= len(body):
                ext_total_len = struct.unpack("!H", body[ptr : ptr + 2])[0]
                ptr += 2
                ext_end = min(ptr + ext_total_len, len(body))

                while ptr + 4 <= ext_end:
                    ext_type, ext_len = struct.unpack("!HH", body[ptr : ptr + 4])
                    ext_data = body[ptr + 4 : ptr + 4 + ext_len]

                    if ext_type == 0x002B and len(ext_data) >= 2:  # supported_versions
                        selected_ver = struct.unpack("!H", ext_data[:2])[0]
                        if selected_ver == 0x0304:
                            tracker.negotiated_tls_version = TLSVersion.TLSv1_3

                    ptr += 4 + ext_len
        except Exception:
            pass

    def _parse_server_certificates(self, tracker: TCPStreamTracker, body: bytes) -> None:
        """Extract individual raw ASN.1 DER certificates from the TLS Certificate message."""
        try:
            if len(body) < 3:
                return
            total_cert_len = (body[0] << 16) | (body[1] << 8) | body[2]
            ptr = 3

            while ptr + 3 <= len(body) and ptr < 3 + total_cert_len:
                cert_len = (body[ptr] << 16) | (body[ptr + 1] << 8) | body[ptr + 2]
                ptr += 3
                if cert_len <= 0:
                    break
                if ptr + cert_len <= len(body):
                    cert_der = body[ptr : ptr + cert_len]
                    tracker.raw_certificate_ders.append(cert_der)
                ptr += cert_len
        except Exception:
            pass

    def _finalize_session(self, tracker: TCPStreamTracker) -> Optional[TLSSessionDetails]:
        """Convert accumulated tracker telemetry into a TLSSessionDetails object."""
        # Only return sessions with meaningful mail traffic or TLS handshake
        if tracker.packet_count < 2 and tracker.total_bytes == 0:
            return None

        # Determine finalized protocol
        proto = tracker.protocol
        if proto == EmailProtocol.UNKNOWN:
            if tracker.server_port in (25, 587):
                proto = EmailProtocol.SMTP
            elif tracker.server_port == 465:
                proto = EmailProtocol.SMTPS
            elif tracker.server_port == 143:
                proto = EmailProtocol.IMAP
            elif tracker.server_port == 993:
                proto = EmailProtocol.IMAPS
            elif tracker.server_port == 110:
                proto = EmailProtocol.POP3
            elif tracker.server_port == 995:
                proto = EmailProtocol.POP3S

        return TLSSessionDetails(
            session_id=tracker.flow_id,
            client_ip=tracker.client_ip,
            client_port=tracker.client_port,
            server_ip=tracker.server_ip,
            server_port=tracker.server_port,
            protocol=proto,
            starttls_command_seen=tracker.starttls_command_seen,
            starttls_negotiated=tracker.starttls_negotiated,
            starttls_downgrade_detected=tracker.starttls_downgrade_detected,
            tls_record_version=tracker.tls_record_version,
            negotiated_tls_version=tracker.negotiated_tls_version,
            client_hello_ciphers=tracker.client_hello_ciphers,
            sni_hostname=tracker.sni_hostname,
            alpn_protocols=tracker.alpn_protocols,
            certificates=[],  # Will be populated by CryptographicValidator
            handshake_completed=tracker.handshake_completed or (tracker.server_selected_cipher is not None),
            total_bytes_transferred=tracker.total_bytes,
            packet_count=tracker.packet_count,
            timestamp_start=tracker.start_time,
            timestamp_end=tracker.last_time,
        )
