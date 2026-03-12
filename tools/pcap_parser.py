"""
PCAP Parser Tools - Network packet capture loading and metadata extraction

Tools:
- load_pcap: Load and parse a .pcap/.pcapng file from local or GCS
- pcap_summary: Show summary of currently loaded PCAP
- pcap_conversations: List network conversations
- pcap_dns: Extract DNS queries and responses
- pcap_http: Extract HTTP transactions
- pcap_timeline: Chronological activity for an IP
- pcap_ioc: Search PCAP for specific IOC (IP, domain, port)
"""

import logging
import os
import io
import ipaddress
import tempfile
from typing import Optional, Dict, List, Tuple
from collections import defaultdict, Counter
from datetime import datetime

# Scapy imports
try:
    # Suppress scapy warnings on import
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    # Disable IPv6 route reading BEFORE importing layers — avoids
    # KeyError: 'scope' in containers with limited network namespaces
    from scapy.config import conf as _scapy_conf
    _scapy_conf.ipv6_enabled = False
    from scapy.utils import PcapReader
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True
    # TLS layer requires cryptography package; import separately
    try:
        from scapy.layers.tls.record import TLS
        from scapy.layers.tls.handshake import (
            TLSClientHello,
            TLSServerHello,
        )
        from scapy.layers.tls.extensions import ServerName
        SCAPY_TLS_AVAILABLE = True
    except Exception:
        TLS = None
        TLSClientHello = None
        TLSServerHello = None
        ServerName = None
        SCAPY_TLS_AVAILABLE = False
        logging.warning(
            "scapy TLS layers unavailable (install cryptography). "
            "TLS handshake parsing disabled."
        )
except Exception as e:
    SCAPY_AVAILABLE = False
    SCAPY_TLS_AVAILABLE = False
    logging.warning(
        f"scapy not available: {e}. PCAP parsing disabled. "
        "Install with: pip install 'scapy[basic]' cryptography"
    )

# 50 MB file size limit
MAX_PCAP_SIZE_BYTES = 50 * 1024 * 1024

# RFC1918 private ranges
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_internal(ip_str: str) -> bool:
    """Check if an IP is in RFC1918 private ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


# =========================================================================
# PCAP SESSION STORE (in-memory, per-process)
# =========================================================================

class PcapSession:
    """Stores parsed PCAP metadata for hunt queries."""

    def __init__(self) -> None:
        self.filename: str = ""
        self.file_size: int = 0
        self.packet_count: int = 0
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

        # Conversations: (src, dst, dport, proto) -> stats
        self.conversations: Dict[
            Tuple[str, str, int, str], Dict
        ] = defaultdict(lambda: {
            "packets": 0,
            "bytes_out": 0,
            "bytes_in": 0,
            "first_seen": None,
            "last_seen": None,
            "timestamps": [],
        })

        # Port counters
        self.dst_ports: Counter = Counter()
        self.src_ports: Counter = Counter()
        self.port_proto: Dict[int, str] = {}

        # Protocol distribution
        self.protocols: Counter = Counter()

        # DNS records
        self.dns_queries: List[Dict] = []
        self.dns_responses: List[Dict] = []

        # HTTP transactions
        self.http_requests: List[Dict] = []

        # TLS metadata
        self.tls_handshakes: List[Dict] = []

        # Unique IPs
        self.src_ips: Counter = Counter()
        self.dst_ips: Counter = Counter()

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def duration_str(self) -> str:
        secs = self.duration_seconds
        if secs < 60:
            return f"{secs:.1f}s"
        if secs < 3600:
            return f"{secs / 60:.1f}min"
        return f"{secs / 3600:.1f}hrs"


# Singleton session
_pcap_session: Optional[PcapSession] = None


def get_pcap_session() -> Optional[PcapSession]:
    return _pcap_session


def _format_bytes(n: int) -> str:
    """Human-readable byte sizes."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n / (1024 ** 2):.1f} MB"
    return f"{n / (1024 ** 3):.1f} GB"


# =========================================================================
# CORE PARSER (streaming, packet-by-packet)
# =========================================================================

def parse_pcap_file(file_path: str) -> PcapSession:
    """
    Parse a PCAP file using scapy's streaming PcapReader.
    Extracts metadata without loading entire file into memory.
    """
    session = PcapSession()
    session.filename = os.path.basename(file_path)
    session.file_size = os.path.getsize(file_path)

    with PcapReader(file_path) as reader:
        for pkt in reader:
            session.packet_count += 1
            ts = float(pkt.time)

            # Track time range
            if session.start_time is None or ts < session.start_time:
                session.start_time = ts
            if session.end_time is None or ts > session.end_time:
                session.end_time = ts

            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_len = len(pkt)

            session.src_ips[src_ip] += 1
            session.dst_ips[dst_ip] += 1

            # Determine protocol and ports
            proto = "OTHER"
            sport = 0
            dport = 0

            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            session.protocols[proto] += 1

            if dport:
                session.dst_ports[dport] += 1
                session.port_proto[dport] = proto
            if sport:
                session.src_ports[sport] += 1

            # Conversation tracking
            conv_key = (src_ip, dst_ip, dport, proto)
            conv = session.conversations[conv_key]
            conv["packets"] += 1
            conv["bytes_out"] += pkt_len
            if conv["first_seen"] is None or ts < conv["first_seen"]:
                conv["first_seen"] = ts
            if conv["last_seen"] is None or ts > conv["last_seen"]:
                conv["last_seen"] = ts
            # Store timestamps for beaconing analysis (cap at 2000)
            if len(conv["timestamps"]) < 2000:
                conv["timestamps"].append(ts)

            # DNS extraction
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0 and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="replace")
                    qname = qname.rstrip(".")
                    session.dns_queries.append({
                        "query": qname,
                        "type": pkt[DNSQR].qtype,
                        "src": src_ip,
                        "ts": ts,
                    })
                elif dns.qr == 1 and pkt.haslayer(DNSRR):
                    qname = ""
                    if pkt.haslayer(DNSQR):
                        qname = pkt[DNSQR].qname
                        if isinstance(qname, bytes):
                            qname = qname.decode(
                                "utf-8", errors="replace"
                            )
                        qname = qname.rstrip(".")
                    rdata = pkt[DNSRR].rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode(
                            "utf-8", errors="replace"
                        )
                    session.dns_responses.append({
                        "query": qname,
                        "answer": str(rdata),
                        "type": pkt[DNSRR].type,
                        "src": src_ip,
                        "ts": ts,
                    })

            # HTTP extraction
            if pkt.haslayer(HTTPRequest):
                req = pkt[HTTPRequest]
                method = (
                    req.Method.decode("utf-8", errors="replace")
                    if isinstance(req.Method, bytes)
                    else str(req.Method)
                )
                path = (
                    req.Path.decode("utf-8", errors="replace")
                    if isinstance(req.Path, bytes)
                    else str(req.Path)
                )
                host = (
                    req.Host.decode("utf-8", errors="replace")
                    if isinstance(req.Host, bytes)
                    else str(req.Host)
                )
                session.http_requests.append({
                    "method": method,
                    "host": host,
                    "path": path,
                    "src": src_ip,
                    "dst": dst_ip,
                    "ts": ts,
                })

            # TLS Client Hello extraction
            if SCAPY_TLS_AVAILABLE and pkt.haslayer(TLS):
                try:
                    if pkt.haslayer(TLSClientHello):
                        ch = pkt[TLSClientHello]
                        sni = ""
                        if hasattr(ch, "ext") and ch.ext:
                            for ext in ch.ext:
                                if hasattr(ext, "servernames"):
                                    for sn in ext.servernames:
                                        name = sn.servername
                                        if isinstance(name, bytes):
                                            name = name.decode(
                                                "utf-8",
                                                errors="replace",
                                            )
                                        sni = name
                                        break
                        session.tls_handshakes.append({
                            "type": "ClientHello",
                            "sni": sni,
                            "src": src_ip,
                            "dst": dst_ip,
                            "dport": dport,
                            "ts": ts,
                        })
                except Exception:
                    pass

    return session


# =========================================================================
# MCP TOOL REGISTRATION
# =========================================================================

def register_pcap_parser_tools(mcp, storage_client, get_bucket_func):
    """Register PCAP parser tools with the MCP server."""

    _storage_client = storage_client
    _get_bucket = get_bucket_func

    @mcp.tool()
    def load_pcap(
        file_path: str,
        from_gcs: bool = False,
        bucket_name: str = "",
    ) -> str:
        """
        Load and parse a .pcap or .pcapng file for threat hunting.
        Extracts conversations, DNS, HTTP, TLS metadata, and port
        usage. Max file size: 50 MB.

        Args:
            file_path: Path to the PCAP file (local or GCS blob)
            from_gcs: If True, load from GCS bucket
            bucket_name: GCS bucket (optional if GCS_LOG_BUCKET set)

        Returns:
            Summary of parsed PCAP with key statistics
        """
        global _pcap_session

        if not SCAPY_AVAILABLE:
            return (
                "Error: scapy not installed. "
                "Install with: pip install scapy"
            )

        try:
            if from_gcs:
                target_bucket = _get_bucket(bucket_name)
                if not target_bucket:
                    return (
                        "Error: No bucket specified and "
                        "GCS_LOG_BUCKET not set."
                    )
                if not _storage_client:
                    return "Error: GCS Client not initialized."

                bucket = _storage_client.bucket(target_bucket)
                blob = bucket.blob(file_path)

                # Check size before download
                blob.reload()
                if blob.size and blob.size > MAX_PCAP_SIZE_BYTES:
                    return (
                        f"Error: File size ({_format_bytes(blob.size)}) "
                        f"exceeds 50 MB limit."
                    )

                # Download to temp file for streaming parse
                with tempfile.NamedTemporaryFile(
                    suffix=".pcap", delete=False
                ) as tmp:
                    blob.download_to_filename(tmp.name)
                    tmp_path = tmp.name

                try:
                    _pcap_session = parse_pcap_file(tmp_path)
                    _pcap_session.filename = os.path.basename(
                        file_path
                    )
                    _pcap_session.file_size = blob.size or 0
                finally:
                    os.unlink(tmp_path)

            else:
                if not os.path.exists(file_path):
                    return f"Error: File not found: {file_path}"

                fsize = os.path.getsize(file_path)
                if fsize > MAX_PCAP_SIZE_BYTES:
                    return (
                        f"Error: File size ({_format_bytes(fsize)}) "
                        f"exceeds 50 MB limit."
                    )

                _pcap_session = parse_pcap_file(file_path)

            # Build summary
            s = _pcap_session
            out = []
            out.append("✅ PCAP Loaded Successfully")
            out.append("")
            out.append(f"  File:      {s.filename}")
            out.append(f"  Size:      {_format_bytes(s.file_size)}")
            out.append(f"  Packets:   {s.packet_count:,}")
            out.append(f"  Duration:  {s.duration_str}")
            if s.start_time:
                t0 = datetime.utcfromtimestamp(s.start_time)
                t1 = datetime.utcfromtimestamp(s.end_time)
                out.append(
                    f"  Time:      {t0:%Y-%m-%d %H:%M:%S} → "
                    f"{t1:%H:%M:%S} UTC"
                )
            out.append(
                f"  Unique Src IPs:  {len(s.src_ips)}"
            )
            out.append(
                f"  Unique Dst IPs:  {len(s.dst_ips)}"
            )
            out.append("")
            out.append("  Protocols:")
            for proto, cnt in s.protocols.most_common(10):
                out.append(f"    {proto:<8} {cnt:>8,} packets")
            out.append("")
            out.append(
                f"  Conversations:   "
                f"{len(s.conversations):,}"
            )
            out.append(
                f"  DNS queries:     {len(s.dns_queries):,}"
            )
            out.append(
                f"  HTTP requests:   {len(s.http_requests):,}"
            )
            out.append(
                f"  TLS handshakes:  {len(s.tls_handshakes):,}"
            )
            out.append("")
            out.append(
                "Use hunt_* commands to analyze: "
                "hunt_talkers, hunt_ports, hunt_dns, "
                "hunt_beacons, hunt_lateral, hunt_exfil, "
                "hunt_tls"
            )

            return "\n".join(out)

        except Exception as e:
            logging.error(f"PCAP parse error: {e}")
            return f"Error loading PCAP: {e}"

    @mcp.tool()
    def pcap_summary() -> str:
        """
        Show summary of the currently loaded PCAP file.
        Returns key statistics and protocol distribution.
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        out = []
        out.append("=== PCAP Summary ===")
        out.append(f"  File:      {s.filename}")
        out.append(f"  Size:      {_format_bytes(s.file_size)}")
        out.append(f"  Packets:   {s.packet_count:,}")
        out.append(f"  Duration:  {s.duration_str}")
        if s.start_time:
            t0 = datetime.utcfromtimestamp(s.start_time)
            t1 = datetime.utcfromtimestamp(s.end_time)
            out.append(
                f"  Time:      {t0:%Y-%m-%d %H:%M:%S} → "
                f"{t1:%H:%M:%S} UTC"
            )
        out.append("")
        out.append("  Protocols:")
        for proto, cnt in s.protocols.most_common(10):
            pct = cnt / s.packet_count * 100 if s.packet_count else 0
            out.append(
                f"    {proto:<8} {cnt:>8,} pkts  "
                f"({pct:.1f}%)"
            )
        out.append("")
        out.append(f"  Unique Src IPs:    {len(s.src_ips)}")
        out.append(f"  Unique Dst IPs:    {len(s.dst_ips)}")
        out.append(f"  Conversations:     {len(s.conversations):,}")
        out.append(f"  DNS queries:       {len(s.dns_queries):,}")
        out.append(f"  HTTP requests:     {len(s.http_requests):,}")
        out.append(f"  TLS handshakes:    {len(s.tls_handshakes):,}")

        return "\n".join(out)

    @mcp.tool()
    def pcap_conversations(
        top_n: int = 20,
        sort_by: str = "bytes",
    ) -> str:
        """
        List top network conversations from loaded PCAP.

        Args:
            top_n: Number of conversations to show (default 20)
            sort_by: Sort by 'bytes', 'packets', or 'duration'
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        convs = []
        for (src, dst, dport, proto), stats in (
            s.conversations.items()
        ):
            convs.append({
                "src": src,
                "dst": dst,
                "dport": dport,
                "proto": proto,
                "packets": stats["packets"],
                "bytes_out": stats["bytes_out"],
                "first": stats["first_seen"],
                "last": stats["last_seen"],
                "duration": (
                    (stats["last_seen"] - stats["first_seen"])
                    if stats["first_seen"] and stats["last_seen"]
                    else 0
                ),
            })

        if sort_by == "packets":
            convs.sort(key=lambda c: c["packets"], reverse=True)
        elif sort_by == "duration":
            convs.sort(key=lambda c: c["duration"], reverse=True)
        else:
            convs.sort(key=lambda c: c["bytes_out"], reverse=True)

        out = []
        out.append(
            f"=== Top {top_n} Conversations (by {sort_by}) ==="
        )
        out.append(
            f"{'#':<4} {'Source':<18} {'Destination':<18} "
            f"{'Port':<7} {'Proto':<6} {'Bytes':<10} "
            f"{'Pkts':<8} {'Duration':<10} {'Dir'}"
        )
        out.append("-" * 95)

        for i, c in enumerate(convs[:top_n], 1):
            src_int = "INT" if is_internal(c["src"]) else "EXT"
            dst_int = "INT" if is_internal(c["dst"]) else "EXT"
            direction = f"{src_int}→{dst_int}"
            dur = (
                f"{c['duration']:.1f}s"
                if c["duration"] < 60
                else f"{c['duration'] / 60:.1f}m"
            )
            out.append(
                f"{i:<4} {c['src']:<18} {c['dst']:<18} "
                f"{c['dport']:<7} {c['proto']:<6} "
                f"{_format_bytes(c['bytes_out']):<10} "
                f"{c['packets']:<8,} {dur:<10} {direction}"
            )

        return "\n".join(out)

    @mcp.tool()
    def pcap_dns(top_n: int = 30) -> str:
        """
        Extract DNS queries and responses from loaded PCAP.
        Groups by domain and shows query counts.

        Args:
            top_n: Number of top domains to show (default 30)
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        if not s.dns_queries and not s.dns_responses:
            return "No DNS activity found in PCAP."

        # Aggregate queries by domain
        domain_counts: Counter = Counter()
        domain_sources: Dict[str, set] = defaultdict(set)
        for q in s.dns_queries:
            domain_counts[q["query"]] += 1
            domain_sources[q["query"]].add(q["src"])

        # Map domains to resolved IPs
        domain_answers: Dict[str, set] = defaultdict(set)
        for r in s.dns_responses:
            if r["query"]:
                domain_answers[r["query"]].add(r["answer"])

        out = []
        out.append(
            f"=== DNS Activity ({len(s.dns_queries)} queries, "
            f"{len(s.dns_responses)} responses) ==="
        )
        out.append(
            f"{'#':<4} {'Domain':<40} {'Queries':<9} "
            f"{'Sources':<9} {'Resolved To'}"
        )
        out.append("-" * 90)

        for i, (domain, cnt) in enumerate(
            domain_counts.most_common(top_n), 1
        ):
            sources = len(domain_sources[domain])
            answers = ", ".join(
                list(domain_answers.get(domain, set()))[:3]
            )
            if len(domain_answers.get(domain, set())) > 3:
                answers += "..."
            out.append(
                f"{i:<4} {domain:<40} {cnt:<9} "
                f"{sources:<9} {answers}"
            )

        return "\n".join(out)

    @mcp.tool()
    def pcap_http(top_n: int = 30) -> str:
        """
        Extract HTTP requests from loaded PCAP.

        Args:
            top_n: Number of requests to show (default 30)
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        if not s.http_requests:
            return "No HTTP requests found in PCAP."

        out = []
        out.append(
            f"=== HTTP Requests ({len(s.http_requests)} total) ==="
        )
        out.append(
            f"{'#':<4} {'Time':<12} {'Source':<18} "
            f"{'Method':<8} {'Host':<30} {'Path'}"
        )
        out.append("-" * 100)

        for i, req in enumerate(s.http_requests[:top_n], 1):
            ts = datetime.utcfromtimestamp(req["ts"])
            out.append(
                f"{i:<4} {ts:%H:%M:%S}    {req['src']:<18} "
                f"{req['method']:<8} {req['host']:<30} "
                f"{req['path'][:50]}"
            )

        if len(s.http_requests) > top_n:
            out.append(
                f"\n... {len(s.http_requests) - top_n} more "
                f"requests not shown"
            )

        return "\n".join(out)

    @mcp.tool()
    def pcap_timeline(
        ip_address: str = "",
        top_n: int = 50,
    ) -> str:
        """
        Show chronological network activity, optionally filtered
        to a specific IP address.

        Args:
            ip_address: Filter to this IP (empty = all activity)
            top_n: Max events to show (default 50)
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        events = []

        # Gather conversation first/last seen as events
        for (src, dst, dport, proto), stats in (
            s.conversations.items()
        ):
            if ip_address and ip_address not in (src, dst):
                continue
            if stats["first_seen"]:
                events.append({
                    "ts": stats["first_seen"],
                    "type": "CONN",
                    "detail": (
                        f"{src} → {dst}:{dport}/{proto} "
                        f"({stats['packets']} pkts, "
                        f"{_format_bytes(stats['bytes_out'])})"
                    ),
                })

        # DNS events
        for q in s.dns_queries:
            if ip_address and q["src"] != ip_address:
                continue
            events.append({
                "ts": q["ts"],
                "type": "DNS",
                "detail": f"{q['src']} queried {q['query']}",
            })

        # HTTP events
        for req in s.http_requests:
            if ip_address and req["src"] != ip_address:
                continue
            events.append({
                "ts": req["ts"],
                "type": "HTTP",
                "detail": (
                    f"{req['src']} → {req['method']} "
                    f"{req['host']}{req['path'][:40]}"
                ),
            })

        events.sort(key=lambda e: e["ts"])

        title = (
            f"=== Timeline for {ip_address} ==="
            if ip_address
            else "=== Network Timeline ==="
        )
        out = [title]
        out.append(
            f"{'Time':<12} {'Type':<6} {'Detail'}"
        )
        out.append("-" * 80)

        for ev in events[:top_n]:
            ts = datetime.utcfromtimestamp(ev["ts"])
            out.append(
                f"{ts:%H:%M:%S}    {ev['type']:<6} "
                f"{ev['detail']}"
            )

        if len(events) > top_n:
            out.append(
                f"\n... {len(events) - top_n} more events "
                f"not shown"
            )

        return "\n".join(out)

    @mcp.tool()
    def pcap_ioc(indicator: str) -> str:
        """
        Search loaded PCAP for a specific indicator of compromise.
        Matches against IPs, domains, and ports.

        Args:
            indicator: IP address, domain name, or port number
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        results = []

        # Check if it's a port number
        try:
            port = int(indicator)
            cnt = s.dst_ports.get(port, 0)
            if cnt:
                results.append(
                    f"Port {port}: {cnt} connections as destination"
                )
                # Find conversations on this port
                for (src, dst, dport, proto), stats in (
                    s.conversations.items()
                ):
                    if dport == port:
                        results.append(
                            f"  {src} → {dst}:{dport}/{proto} "
                            f"({stats['packets']} pkts, "
                            f"{_format_bytes(stats['bytes_out'])})"
                        )
            else:
                results.append(
                    f"Port {port}: not found in PCAP"
                )
            return "\n".join(results)
        except ValueError:
            pass

        # Check as IP
        if indicator.count(".") == 3:
            found = False
            src_cnt = s.src_ips.get(indicator, 0)
            dst_cnt = s.dst_ips.get(indicator, 0)
            if src_cnt or dst_cnt:
                found = True
                loc = "Internal" if is_internal(indicator) else "External"
                results.append(
                    f"IP {indicator} ({loc}):"
                )
                results.append(
                    f"  As source: {src_cnt:,} packets"
                )
                results.append(
                    f"  As destination: {dst_cnt:,} packets"
                )
                results.append("")
                results.append("  Conversations:")
                for (src, dst, dport, proto), stats in (
                    s.conversations.items()
                ):
                    if indicator in (src, dst):
                        results.append(
                            f"    {src} → {dst}:{dport}/{proto}"
                            f"  {stats['packets']} pkts  "
                            f"{_format_bytes(stats['bytes_out'])}"
                        )
            # Check DNS
            for q in s.dns_queries:
                if q["src"] == indicator:
                    found = True
            for r in s.dns_responses:
                if r["answer"] == indicator:
                    results.append(
                        f"  DNS: {r['query']} → {indicator}"
                    )
                    found = True
            if not found:
                results.append(
                    f"IP {indicator}: not found in PCAP"
                )
            return "\n".join(results)

        # Check as domain (search DNS)
        indicator_lower = indicator.lower()
        found = False
        for q in s.dns_queries:
            if indicator_lower in q["query"].lower():
                if not found:
                    results.append(
                        f"Domain matching '{indicator}':"
                    )
                    found = True
                results.append(
                    f"  DNS query: {q['query']} "
                    f"from {q['src']}"
                )

        for r in s.dns_responses:
            if indicator_lower in r["query"].lower():
                results.append(
                    f"  DNS answer: {r['query']} → "
                    f"{r['answer']}"
                )

        # Check HTTP hosts
        for req in s.http_requests:
            if indicator_lower in req["host"].lower():
                if not found:
                    results.append(
                        f"Domain matching '{indicator}':"
                    )
                    found = True
                results.append(
                    f"  HTTP: {req['method']} "
                    f"{req['host']}{req['path'][:40]}"
                )

        # Check TLS SNI
        for th in s.tls_handshakes:
            if indicator_lower in th.get("sni", "").lower():
                if not found:
                    results.append(
                        f"Domain matching '{indicator}':"
                    )
                    found = True
                results.append(
                    f"  TLS SNI: {th['sni']} "
                    f"({th['src']} → {th['dst']}:{th['dport']})"
                )

        if not found:
            results.append(
                f"IOC '{indicator}': not found in PCAP"
            )

        return "\n".join(results)
