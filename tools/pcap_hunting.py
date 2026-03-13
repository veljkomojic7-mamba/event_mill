"""
PCAP Hunting Tools - Threat hunting analyzers for loaded PCAP data

Tools:
- hunt_talkers: Top talkers by volume or connection count
- hunt_ports: Top ports and unusual port detection (ICS-aware)
- hunt_beacons: Detect C2 beaconing patterns
- hunt_dns: DNS anomaly analysis
- hunt_tls: TLS fingerprint and SNI analysis
- hunt_lateral: Lateral movement detection
- hunt_exfil: Data exfiltration indicators
"""

import logging
import math
from typing import Dict, List, Optional
from collections import Counter, defaultdict
from datetime import datetime

from system_context import (
    get_pcap_triage_prompt,
    get_pcap_threat_hunt_prompt,
    get_pcap_reporting_prompt,
)
from tools.pcap_parser import (
    get_pcap_session,
    is_internal,
    _format_bytes,
)

# =========================================================================
# PORT KNOWLEDGE BASE (ICS-aware)
# =========================================================================

# Standard well-known services
KNOWN_SERVICES: Dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
    80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DG", 139: "NetBIOS-SS",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP-Sub",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 5986: "WinRM-S",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt2", 9200: "Elasticsearch",
}

# ICS/SCADA protocols
ICS_PORTS: Dict[int, str] = {
    102: "S7comm/ISO-TSAP",
    502: "Modbus",
    789: "Redlion-Crimson",
    1089: "FF-Annunciation",
    1090: "FF-FMS",
    1091: "FF-SM",
    1911: "Niagara-Fox",
    2222: "EtherNet/IP-Implicit",
    2404: "IEC-60870-5-104",
    4000: "Emerson-ROC",
    4840: "OPC-UA",
    4911: "Niagara-Fox-TLS",
    5094: "HART-IP",
    18245: "GE-SRTP",
    20000: "DNP3",
    34962: "Profinet-RT",
    34963: "Profinet-RTCYC",
    34964: "Profinet-IO-CM",
    44818: "EtherNet/IP-Explicit",
    47808: "BACnet",
    55000: "FL-net",
    55003: "FL-net",
}

# Known attack tool default ports
SUSPICIOUS_PORTS: Dict[int, str] = {
    1234: "Generic-RAT",
    1337: "Backdoor",
    3333: "DarkComet",
    4242: "RevShell-Common",
    4444: "Metasploit",
    5555: "Android-ADB/RAT",
    6666: "IRC-Backdoor",
    6667: "IRC-C2",
    6969: "Backdoor",
    7777: "Backdoor",
    8291: "Mikrotik-Winbox",
    9001: "Tor",
    9090: "Zeus-C2",
    9999: "Generic-Backdoor",
    12345: "NetBus",
    31337: "Back-Orifice",
    50050: "Cobalt-Strike",
}


def _service_name(port: int) -> str:
    """Look up service name for a port."""
    if port in SUSPICIOUS_PORTS:
        return f"⚠️ {SUSPICIOUS_PORTS[port]}"
    if port in ICS_PORTS:
        return f"🏭 {ICS_PORTS[port]}"
    if port in KNOWN_SERVICES:
        return KNOWN_SERVICES[port]
    if port >= 49152:
        return "Ephemeral"
    return "Unknown"


# =========================================================================
# MCP TOOL REGISTRATION
# =========================================================================

def register_pcap_hunting_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register PCAP hunting tools with the MCP server."""

    _gemini_client = gemini_client

    @mcp.tool()
    def hunt_talkers(
        top_n: int = 20,
        by: str = "bytes",
    ) -> str:
        """
        Show top talkers from loaded PCAP by volume or connection
        count. Identifies internal vs external hosts.

        Args:
            top_n: Number of talkers to show (default 20)
            by: Sort by 'bytes', 'connections', or 'packets'
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        # Aggregate per source IP
        ip_stats: Dict[str, Dict] = defaultdict(lambda: {
            "bytes_out": 0,
            "bytes_in": 0,
            "packets": 0,
            "connections": 0,
            "unique_dsts": set(),
            "protocols": set(),
        })

        for (src, dst, dport, proto), stats in (
            s.conversations.items()
        ):
            ip_stats[src]["bytes_out"] += stats["bytes_out"]
            ip_stats[src]["packets"] += stats["packets"]
            ip_stats[src]["connections"] += 1
            ip_stats[src]["unique_dsts"].add(dst)
            ip_stats[src]["protocols"].add(proto)

            # Count reverse bytes for dst
            ip_stats[dst]["bytes_in"] += stats["bytes_out"]

        # Sort
        talkers = []
        for ip, st in ip_stats.items():
            talkers.append({
                "ip": ip,
                "bytes_out": st["bytes_out"],
                "bytes_in": st["bytes_in"],
                "packets": st["packets"],
                "connections": st["connections"],
                "unique_dsts": len(st["unique_dsts"]),
                "protocols": ",".join(sorted(st["protocols"])),
                "location": (
                    "INT" if is_internal(ip) else "EXT"
                ),
            })

        if by in ("connections", "conns"):
            talkers.sort(
                key=lambda t: t["connections"], reverse=True
            )
        elif by == "packets":
            talkers.sort(
                key=lambda t: t["packets"], reverse=True
            )
        else:
            talkers.sort(
                key=lambda t: t["bytes_out"], reverse=True
            )

        out = []
        out.append(
            f"=== Top {top_n} Talkers (by {by}) ==="
        )
        out.append(
            f"{'#':<4} {'IP':<18} {'Loc':<5} "
            f"{'Bytes Out':<12} {'Bytes In':<12} "
            f"{'Conns':<7} {'Dsts':<6} {'Protos'}"
        )
        out.append("-" * 90)

        for i, t in enumerate(talkers[:top_n], 1):
            flag = ""
            # Flag high connection count
            if t["unique_dsts"] > 20:
                flag = " ⚠️"
            out.append(
                f"{i:<4} {t['ip']:<18} {t['location']:<5} "
                f"{_format_bytes(t['bytes_out']):<12} "
                f"{_format_bytes(t['bytes_in']):<12} "
                f"{t['connections']:<7} {t['unique_dsts']:<6} "
                f"{t['protocols']}{flag}"
            )

        return "\n".join(out)

    @mcp.tool()
    def hunt_ports(
        top_n: int = 30,
        unusual_only: bool = False,
    ) -> str:
        """
        Analyze port usage from loaded PCAP. Detects suspicious
        ports, ICS protocols, and unusual activity. ICS-aware.

        Args:
            top_n: Number of ports to show (default 30)
            unusual_only: Only show unusual/suspicious ports
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        # Build port detail
        port_detail: Dict[int, Dict] = {}
        for (src, dst, dport, proto), stats in (
            s.conversations.items()
        ):
            if dport == 0:
                continue
            if dport not in port_detail:
                port_detail[dport] = {
                    "connections": 0,
                    "bytes": 0,
                    "proto": proto,
                    "sources": set(),
                    "destinations": set(),
                    "internal_only": True,
                }
            pd = port_detail[dport]
            pd["connections"] += 1
            pd["bytes"] += stats["bytes_out"]
            pd["sources"].add(src)
            pd["destinations"].add(dst)
            if not is_internal(src) or not is_internal(dst):
                pd["internal_only"] = False

        out = []

        # === Suspicious Ports ===
        suspicious_found = []
        for port, detail in port_detail.items():
            if port in SUSPICIOUS_PORTS:
                suspicious_found.append((port, detail))

        if suspicious_found:
            out.append("🔴 SUSPICIOUS PORTS DETECTED")
            out.append("-" * 60)
            for port, detail in suspicious_found:
                srcs = ", ".join(list(detail["sources"])[:3])
                dsts = ", ".join(
                    list(detail["destinations"])[:3]
                )
                out.append(
                    f"  Port {port}/{detail['proto']} — "
                    f"{SUSPICIOUS_PORTS[port]}"
                )
                out.append(
                    f"    Connections: {detail['connections']}  "
                    f"Bytes: {_format_bytes(detail['bytes'])}"
                )
                out.append(f"    Sources: {srcs}")
                out.append(f"    Destinations: {dsts}")
                out.append("")

        # === ICS Ports ===
        ics_found = []
        for port, detail in port_detail.items():
            if port in ICS_PORTS:
                ics_found.append((port, detail))

        if ics_found:
            out.append("🏭 ICS/SCADA PROTOCOL PORTS")
            out.append("-" * 60)
            for port, detail in ics_found:
                scope = (
                    "Internal Only"
                    if detail["internal_only"]
                    else "⚠️ EXTERNAL TRAFFIC"
                )
                srcs = ", ".join(list(detail["sources"])[:3])
                out.append(
                    f"  Port {port}/{detail['proto']} — "
                    f"{ICS_PORTS[port]} [{scope}]"
                )
                out.append(
                    f"    Connections: {detail['connections']}  "
                    f"Bytes: {_format_bytes(detail['bytes'])}  "
                    f"Sources: {srcs}"
                )
            out.append("")

        if unusual_only:
            if not suspicious_found and not ics_found:
                out.append(
                    "No suspicious or ICS ports found."
                )
            return "\n".join(out)

        # === All Top Ports ===
        out.append(
            f"=== Top {top_n} Destination Ports ==="
        )
        out.append(
            f"{'#':<4} {'Port':<7} {'Proto':<6} "
            f"{'Conns':<8} {'Bytes':<12} {'Service':<22} "
            f"{'Sources'}"
        )
        out.append("-" * 85)

        sorted_ports = sorted(
            port_detail.items(),
            key=lambda x: x[1]["connections"],
            reverse=True,
        )

        for i, (port, detail) in enumerate(
            sorted_ports[:top_n], 1
        ):
            svc = _service_name(port)
            src_count = len(detail["sources"])
            out.append(
                f"{i:<4} {port:<7} {detail['proto']:<6} "
                f"{detail['connections']:<8} "
                f"{_format_bytes(detail['bytes']):<12} "
                f"{svc:<22} {src_count} src(s)"
            )

        return "\n".join(out)

    @mcp.tool()
    def hunt_beacons(
        min_connections: int = 10,
        max_jitter_pct: float = 15.0,
    ) -> str:
        """
        Detect C2 beaconing patterns — regular interval
        connections to the same destination. Flags periodic
        callbacks typical of malware command-and-control.

        Args:
            min_connections: Minimum connections to analyze
            max_jitter_pct: Max jitter percentage to flag
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        beacons = []

        for (src, dst, dport, proto), stats in (
            s.conversations.items()
        ):
            ts_list = sorted(stats["timestamps"])
            if len(ts_list) < min_connections:
                continue

            # Calculate inter-arrival times
            intervals = [
                ts_list[i + 1] - ts_list[i]
                for i in range(len(ts_list) - 1)
            ]

            if not intervals:
                continue

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 0.5:
                # Sub-second intervals are likely data transfer
                continue

            # Standard deviation
            variance = sum(
                (x - mean_interval) ** 2 for x in intervals
            ) / len(intervals)
            std_dev = math.sqrt(variance)

            # Jitter percentage
            jitter_pct = (
                (std_dev / mean_interval * 100)
                if mean_interval > 0
                else 100
            )

            if jitter_pct <= max_jitter_pct:
                duration = ts_list[-1] - ts_list[0]
                beacons.append({
                    "src": src,
                    "dst": dst,
                    "dport": dport,
                    "proto": proto,
                    "count": len(ts_list),
                    "mean_interval": mean_interval,
                    "std_dev": std_dev,
                    "jitter_pct": jitter_pct,
                    "duration": duration,
                })

        # Sort by confidence (lowest jitter = most suspicious)
        beacons.sort(key=lambda b: b["jitter_pct"])

        out = []
        if not beacons:
            out.append(
                "No beaconing patterns detected "
                f"(threshold: {min_connections}+ connections, "
                f"<{max_jitter_pct}% jitter)"
            )
            return "\n".join(out)

        out.append(
            f"🔴 BEACONING DETECTED — "
            f"{len(beacons)} suspicious pattern(s)"
        )
        out.append("-" * 80)

        for i, b in enumerate(beacons, 1):
            confidence = "HIGH"
            if b["jitter_pct"] > 5:
                confidence = "MEDIUM"
            if b["jitter_pct"] > 10:
                confidence = "LOW"

            src_loc = "INT" if is_internal(b["src"]) else "EXT"
            dst_loc = "INT" if is_internal(b["dst"]) else "EXT"

            interval_str = (
                f"{b['mean_interval']:.1f}s"
                if b["mean_interval"] < 60
                else f"{b['mean_interval'] / 60:.1f}min"
            )
            dur_str = (
                f"{b['duration'] / 60:.0f}min"
                if b["duration"] < 3600
                else f"{b['duration'] / 3600:.1f}hrs"
            )

            out.append(
                f"  [{confidence} confidence] "
                f"{b['src']} ({src_loc}) → "
                f"{b['dst']} ({dst_loc}):{b['dport']}"
                f"/{b['proto']}"
            )
            out.append(
                f"    Interval: {interval_str} "
                f"(σ={b['std_dev']:.2f}s, "
                f"jitter={b['jitter_pct']:.1f}%)"
            )
            out.append(
                f"    Callbacks: {b['count']}  "
                f"Duration: {dur_str}"
            )
            svc = _service_name(b["dport"])
            if svc != "Unknown" and svc != "Ephemeral":
                out.append(f"    Service: {svc}")
            out.append("")

        return "\n".join(out)

    @mcp.tool()
    def hunt_dns() -> str:
        """
        Analyze DNS for threat hunting anomalies: DGA detection,
        tunneling indicators, high-frequency queries, and rare
        TLDs.
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        if not s.dns_queries:
            return "No DNS activity found in PCAP."

        out = []
        anomalies_found = False

        # Aggregate by domain
        domain_counts: Counter = Counter()
        domain_sources: Dict[str, set] = defaultdict(set)
        for q in s.dns_queries:
            domain_counts[q["query"]] += 1
            domain_sources[q["query"]].add(q["src"])

        # 1. High-frequency queries (possible beaconing/tunneling)
        high_freq = [
            (d, c) for d, c in domain_counts.items() if c > 50
        ]
        if high_freq:
            anomalies_found = True
            out.append("🟡 HIGH-FREQUENCY DNS QUERIES")
            out.append("-" * 60)
            for domain, count in sorted(
                high_freq, key=lambda x: x[1], reverse=True
            )[:15]:
                out.append(
                    f"  {domain:<45} {count} queries"
                )
            out.append("")

        # 2. Long domain names (DGA / tunneling)
        long_domains = [
            d for d in domain_counts
            if len(d) > 50
        ]
        if long_domains:
            anomalies_found = True
            out.append("🔴 LONG DOMAIN NAMES (possible DGA/tunneling)")
            out.append("-" * 60)
            for domain in long_domains[:15]:
                out.append(
                    f"  {domain[:70]}  "
                    f"(len={len(domain)}, "
                    f"{domain_counts[domain]} queries)"
                )
            out.append("")

        # 3. High-entropy subdomains (DGA detection)
        dga_suspects = []
        for domain in domain_counts:
            parts = domain.split(".")
            if len(parts) >= 2:
                subdomain = parts[0]
                if len(subdomain) >= 8:
                    # Shannon entropy
                    freq: Dict[str, int] = {}
                    for c in subdomain:
                        freq[c] = freq.get(c, 0) + 1
                    entropy = -sum(
                        (cnt / len(subdomain))
                        * math.log2(cnt / len(subdomain))
                        for cnt in freq.values()
                    )
                    if entropy > 3.5:
                        dga_suspects.append(
                            (domain, entropy, domain_counts[domain])
                        )

        if dga_suspects:
            anomalies_found = True
            dga_suspects.sort(
                key=lambda x: x[1], reverse=True
            )
            out.append(
                "🔴 HIGH-ENTROPY DOMAINS (possible DGA)"
            )
            out.append("-" * 60)
            for domain, entropy, count in dga_suspects[:15]:
                out.append(
                    f"  {domain:<45} "
                    f"entropy={entropy:.2f}  "
                    f"{count} queries"
                )
            out.append("")

        # 4. TXT record queries (possible data exfil)
        txt_queries = [
            q for q in s.dns_queries if q["type"] == 16
        ]
        if txt_queries:
            anomalies_found = True
            txt_domains: Counter = Counter()
            for q in txt_queries:
                txt_domains[q["query"]] += 1
            out.append(
                f"🟡 DNS TXT QUERIES ({len(txt_queries)} total)"
            )
            out.append("-" * 60)
            for domain, count in txt_domains.most_common(10):
                out.append(
                    f"  {domain:<45} {count} TXT queries"
                )
            out.append("")

        if not anomalies_found:
            out.append(
                "✅ No DNS anomalies detected "
                f"({len(s.dns_queries)} queries analyzed)"
            )

        return "\n".join(out)

    @mcp.tool()
    def hunt_tls() -> str:
        """
        Analyze TLS handshakes from loaded PCAP. Shows SNI values,
        identifies connections without SNI, and flags unusual TLS
        activity.
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        if not s.tls_handshakes:
            return "No TLS handshakes found in PCAP."

        out = []

        # Group by SNI
        sni_counts: Counter = Counter()
        no_sni = []
        sni_details: Dict[str, List] = defaultdict(list)

        for th in s.tls_handshakes:
            sni = th.get("sni", "")
            if sni:
                sni_counts[sni] += 1
                sni_details[sni].append(th)
            else:
                no_sni.append(th)

        out.append(
            f"=== TLS Analysis ({len(s.tls_handshakes)} "
            f"handshakes) ==="
        )
        out.append("")

        # Connections without SNI (suspicious)
        if no_sni:
            out.append(
                f"🟡 TLS WITHOUT SNI — {len(no_sni)} "
                f"connection(s)"
            )
            out.append("-" * 60)
            seen = set()
            for th in no_sni[:20]:
                key = (th["src"], th["dst"], th["dport"])
                if key not in seen:
                    seen.add(key)
                    dst_loc = (
                        "INT"
                        if is_internal(th["dst"])
                        else "EXT"
                    )
                    out.append(
                        f"  {th['src']} → "
                        f"{th['dst']}:{th['dport']} "
                        f"({dst_loc})"
                    )
            out.append("")

        # SNI table
        out.append("=== TLS Server Names (SNI) ===")
        out.append(
            f"{'#':<4} {'SNI':<45} {'Count':<8} {'Dest IPs'}"
        )
        out.append("-" * 80)

        for i, (sni, cnt) in enumerate(
            sni_counts.most_common(30), 1
        ):
            dst_ips = set(
                th["dst"] for th in sni_details[sni]
            )
            ips_str = ", ".join(list(dst_ips)[:3])
            if len(dst_ips) > 3:
                ips_str += "..."
            out.append(
                f"{i:<4} {sni:<45} {cnt:<8} {ips_str}"
            )

        return "\n".join(out)

    @mcp.tool()
    def hunt_lateral() -> str:
        """
        Detect lateral movement indicators: internal-to-internal
        connections on management ports (SMB, RDP, WinRM, SSH),
        port scan patterns, and ICS protocol cross-zone traffic.
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        out = []
        lateral_found = False

        # Lateral movement ports
        lateral_ports = {
            22: "SSH", 135: "RPC", 139: "NetBIOS",
            445: "SMB", 3389: "RDP", 5985: "WinRM",
            5986: "WinRM-S", 23: "Telnet",
        }

        # ICS lateral ports
        ics_lateral = {
            502: "Modbus", 102: "S7comm",
            44818: "EtherNet/IP", 20000: "DNP3",
            4840: "OPC-UA", 47808: "BACnet",
            2404: "IEC-104",
        }

        # 1. Internal→Internal on management ports
        mgmt_lateral = []
        for (src, dst, dport, proto), stats in (
            s.conversations.items()
        ):
            if (
                is_internal(src)
                and is_internal(dst)
                and dport in lateral_ports
            ):
                mgmt_lateral.append({
                    "src": src,
                    "dst": dst,
                    "port": dport,
                    "service": lateral_ports[dport],
                    "packets": stats["packets"],
                    "bytes": stats["bytes_out"],
                })

        if mgmt_lateral:
            lateral_found = True
            out.append(
                f"🟡 INTERNAL LATERAL MOVEMENT — "
                f"{len(mgmt_lateral)} flow(s) on "
                f"management ports"
            )
            out.append("-" * 70)
            # Group by source
            by_src: Dict[str, list] = defaultdict(list)
            for m in mgmt_lateral:
                by_src[m["src"]].append(m)
            for src, flows in sorted(
                by_src.items(),
                key=lambda x: len(x[1]),
                reverse=True,
            ):
                dsts = set(f["dst"] for f in flows)
                ports = set(f["service"] for f in flows)
                flag = " 🔴 SCAN?" if len(dsts) > 5 else ""
                out.append(
                    f"  {src} → {len(dsts)} targets "
                    f"({', '.join(ports)}){flag}"
                )
                for f in flows[:5]:
                    out.append(
                        f"    → {f['dst']}:{f['port']} "
                        f"({f['service']}) "
                        f"{f['packets']} pkts "
                        f"{_format_bytes(f['bytes'])}"
                    )
                if len(flows) > 5:
                    out.append(
                        f"    ... +{len(flows) - 5} more"
                    )
            out.append("")

        # 2. Port scanning: one internal source, many internal destinations
        #    (east-west only — skip north-south to external)
        src_dst_per_port: Dict[
            tuple, set
        ] = defaultdict(set)
        for (src, dst, dport, proto), stats in (
            s.conversations.items()
        ):
            if (
                is_internal(src)
                and is_internal(dst)
                and dport > 0
            ):
                src_dst_per_port[(src, dport)].add(dst)

        scanners = []
        for (src, dport), dsts in src_dst_per_port.items():
            if len(dsts) >= 5:
                scanners.append((src, dport, len(dsts)))

        if scanners:
            lateral_found = True
            scanners.sort(key=lambda x: x[2], reverse=True)
            out.append(
                f"🔴 PORT SCAN PATTERNS — "
                f"{len(scanners)} pattern(s)"
            )
            out.append("-" * 60)
            for src, dport, dst_count in scanners[:15]:
                svc = _service_name(dport)
                out.append(
                    f"  {src} → {dst_count} hosts "
                    f"on port {dport} ({svc})"
                )
            out.append("")

        # 3. ICS cross-zone (ICS ports from/to external)
        ics_cross = []
        for (src, dst, dport, proto), stats in (
            s.conversations.items()
        ):
            if dport in ics_lateral:
                if not is_internal(src) or not is_internal(dst):
                    ics_cross.append({
                        "src": src,
                        "dst": dst,
                        "port": dport,
                        "service": ics_lateral[dport],
                        "packets": stats["packets"],
                    })

        if ics_cross:
            lateral_found = True
            out.append(
                "🔴 ICS PROTOCOL CROSS-ZONE TRAFFIC"
            )
            out.append("-" * 60)
            for c in ics_cross:
                src_loc = (
                    "INT" if is_internal(c["src"]) else "EXT"
                )
                dst_loc = (
                    "INT" if is_internal(c["dst"]) else "EXT"
                )
                out.append(
                    f"  {c['src']} ({src_loc}) → "
                    f"{c['dst']} ({dst_loc}):{c['port']} "
                    f"({c['service']}) — {c['packets']} pkts"
                )
            out.append("")

        if not lateral_found:
            out.append(
                "✅ No lateral movement indicators detected"
            )

        return "\n".join(out)

    @mcp.tool()
    def hunt_exfil(
        min_ratio: float = 10.0,
        min_bytes_out: int = 1048576,
    ) -> str:
        """
        Detect data exfiltration indicators: asymmetric flows
        (large outbound, small inbound) to external hosts, long
        duration connections, and large DNS transfers.

        Args:
            min_ratio: Min out/in byte ratio to flag (default 10x)
            min_bytes_out: Min outbound bytes to consider (default 1MB)
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."

        out = []
        exfil_found = False

        # 1. Asymmetric outbound flows to external
        asymmetric = []
        # Aggregate by (src, dst) pair
        pair_stats: Dict[
            tuple, Dict
        ] = defaultdict(lambda: {
            "bytes_out": 0,
            "bytes_in": 0,
            "packets": 0,
            "ports": set(),
            "first": None,
            "last": None,
        })

        for (src, dst, dport, proto), stats in (
            s.conversations.items()
        ):
            if is_internal(src) and not is_internal(dst):
                key = (src, dst)
                ps = pair_stats[key]
                ps["bytes_out"] += stats["bytes_out"]
                ps["packets"] += stats["packets"]
                ps["ports"].add(dport)
                if stats["first_seen"]:
                    if (
                        ps["first"] is None
                        or stats["first_seen"] < ps["first"]
                    ):
                        ps["first"] = stats["first_seen"]
                    if (
                        ps["last"] is None
                        or stats["last_seen"] > ps["last"]
                    ):
                        ps["last"] = stats["last_seen"]

        # Also count reverse flows (external → internal) as
        # "bytes_in" for the pair
        for (src, dst, dport, proto), stats in (
            s.conversations.items()
        ):
            if not is_internal(src) and is_internal(dst):
                key = (dst, src)
                if key in pair_stats:
                    pair_stats[key]["bytes_in"] += (
                        stats["bytes_out"]
                    )

        for (src, dst), ps in pair_stats.items():
            if ps["bytes_out"] < min_bytes_out:
                continue
            bytes_in = max(ps["bytes_in"], 1)
            ratio = ps["bytes_out"] / bytes_in
            if ratio >= min_ratio:
                duration = 0
                if ps["first"] and ps["last"]:
                    duration = ps["last"] - ps["first"]
                asymmetric.append({
                    "src": src,
                    "dst": dst,
                    "bytes_out": ps["bytes_out"],
                    "bytes_in": ps["bytes_in"],
                    "ratio": ratio,
                    "packets": ps["packets"],
                    "ports": ps["ports"],
                    "duration": duration,
                })

        if asymmetric:
            exfil_found = True
            asymmetric.sort(
                key=lambda a: a["bytes_out"], reverse=True
            )
            out.append(
                f"🔴 ASYMMETRIC OUTBOUND FLOWS — "
                f"{len(asymmetric)} suspect pair(s)"
            )
            out.append("-" * 70)
            for a in asymmetric[:15]:
                dur_str = (
                    f"{a['duration'] / 60:.0f}min"
                    if a["duration"] < 3600
                    else f"{a['duration'] / 3600:.1f}hrs"
                )
                ports = ", ".join(
                    str(p) for p in sorted(a["ports"])
                )
                out.append(
                    f"  {a['src']} → {a['dst']}"
                )
                out.append(
                    f"    Out: {_format_bytes(a['bytes_out'])}  "
                    f"In: {_format_bytes(a['bytes_in'])}  "
                    f"Ratio: {a['ratio']:.0f}x  "
                    f"Duration: {dur_str}"
                )
                out.append(
                    f"    Ports: {ports}  "
                    f"Packets: {a['packets']:,}"
                )
                out.append("")

        # 2. DNS-based exfil (large number of unique subdomains)
        domain_subs: Dict[str, set] = defaultdict(set)
        for q in s.dns_queries:
            parts = q["query"].split(".")
            if len(parts) >= 3:
                base = ".".join(parts[-2:])
                subdomain = ".".join(parts[:-2])
                domain_subs[base].add(subdomain)

        dns_exfil = [
            (base, subs)
            for base, subs in domain_subs.items()
            if len(subs) > 20
        ]

        if dns_exfil:
            exfil_found = True
            dns_exfil.sort(
                key=lambda x: len(x[1]), reverse=True
            )
            out.append(
                "🟡 DNS EXFIL INDICATORS — "
                "high unique subdomain count"
            )
            out.append("-" * 60)
            for base, subs in dns_exfil[:10]:
                out.append(
                    f"  {base} — {len(subs)} unique "
                    f"subdomains queried"
                )
                for sub in list(subs)[:3]:
                    out.append(f"    {sub}.{base}")
                if len(subs) > 3:
                    out.append(
                        f"    ... +{len(subs) - 3} more"
                    )
            out.append("")

        if not exfil_found:
            out.append(
                "✅ No data exfiltration indicators detected"
            )

        return "\n".join(out)

    # =================================================================
    # AI-ENHANCED HUNT TOOLS (Gemini LLM analysis)
    # =================================================================

    def _ai_enhance(static_output: str, prompt_func, file_name: str) -> str:
        """Run static output through Gemini AI analysis."""
        if not _gemini_client:
            return (
                static_output
                + "\n\n[Note: Set GEMINI_API_KEY to enable "
                "AI-powered analysis]"
            )
        try:
            prompt = prompt_func(
                file_name=file_name,
                pcap_summary_data=static_output,
            )
            response = _gemini_client.models.generate_content(
                model='gemini-3-flash-preview',
                contents=prompt,
            )
            return (
                static_output
                + "\n\n"
                + "=" * 60 + "\n"
                + "\U0001f50d AI ANALYSIS\n"
                + "=" * 60 + "\n"
                + response.text
            )
        except Exception as e:
            logging.error(f"Gemini API error: {e}")
            return (
                static_output
                + f"\n\n[AI Analysis Failed: {e}]"
            )

    @mcp.tool()
    def ai_hunt_talkers(
        top_n: int = 20,
        by: str = "bytes",
    ) -> str:
        """
        AI-enhanced top talkers analysis. Runs hunt_talkers
        then sends output to Gemini for triage, anomaly
        detection, and prioritized recommendations.

        Args:
            top_n: Number of talkers to show (default 20)
            by: Sort by 'bytes', 'connections', or 'packets'
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."
        static = hunt_talkers(top_n=top_n, by=by)
        return _ai_enhance(
            static, get_pcap_triage_prompt, s.filename
        )

    @mcp.tool()
    def ai_hunt_beacons(
        min_connections: int = 10,
        max_jitter_pct: float = 15.0,
    ) -> str:
        """
        AI-enhanced C2 beaconing analysis. Runs hunt_beacons
        then uses Gemini to assess likelihood of real C2,
        map to MITRE ATT&CK, and suggest investigation steps.

        Args:
            min_connections: Minimum connections to analyze
            max_jitter_pct: Max jitter percentage to flag
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."
        static = hunt_beacons(
            min_connections=min_connections,
            max_jitter_pct=max_jitter_pct,
        )
        return _ai_enhance(
            static, get_pcap_threat_hunt_prompt, s.filename
        )

    @mcp.tool()
    def ai_hunt_dns() -> str:
        """
        AI-enhanced DNS anomaly analysis. Runs hunt_dns then
        uses Gemini to evaluate DGA likelihood, classify
        tunneling indicators, and suggest blocklists.
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."
        static = hunt_dns()
        return _ai_enhance(
            static, get_pcap_threat_hunt_prompt, s.filename
        )

    @mcp.tool()
    def ai_hunt_tls() -> str:
        """
        AI-enhanced TLS analysis. Runs hunt_tls then uses
        Gemini to flag suspicious SNI/certificate patterns
        and map to known threat infrastructure.
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."
        static = hunt_tls()
        return _ai_enhance(
            static, get_pcap_threat_hunt_prompt, s.filename
        )

    @mcp.tool()
    def ai_hunt_lateral() -> str:
        """
        AI-enhanced lateral movement analysis. Runs
        hunt_lateral then uses Gemini to map findings
        to kill chain stages and prioritize response.
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."
        static = hunt_lateral()
        return _ai_enhance(
            static, get_pcap_threat_hunt_prompt, s.filename
        )

    @mcp.tool()
    def ai_hunt_exfil(
        min_ratio: float = 10.0,
        min_bytes_out: int = 1048576,
    ) -> str:
        """
        AI-enhanced exfiltration analysis. Runs hunt_exfil
        then uses Gemini to assess severity, extract IOCs,
        and produce a shift-handover report.

        Args:
            min_ratio: Min out/in byte ratio (default 10x)
            min_bytes_out: Min outbound bytes (default 1MB)
        """
        s = get_pcap_session()
        if not s:
            return "No PCAP loaded. Use load_pcap first."
        static = hunt_exfil(
            min_ratio=min_ratio,
            min_bytes_out=min_bytes_out,
        )
        return _ai_enhance(
            static, get_pcap_reporting_prompt, s.filename
        )
