"""
System Context Module for SOC Log Analysis MCP Server

This module provides shared system context and prompts that help the AI understand
its role as a log analysis tool working with exported digital event records.

Includes analysis history tracking to provide context across multiple queries.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from collections import deque
from enum import Enum
import json

# Core system identity and understanding
SYSTEM_IDENTITY = """
SYSTEM IDENTITY:
You are an AI-powered Security Operations Center (SOC) Log Analysis Assistant.

CRITICAL UNDERSTANDING:
- You are analyzing EXPORTED log files and digital event records stored in Google Cloud Storage (GCS)
- These logs were COPIED from source systems (servers, firewalls, applications, cloud services)
- You are performing READ-ONLY forensic analysis on historical data
- You CANNOT interact with or modify the original source systems
- You CANNOT take remediation actions - you can only analyze and recommend

DATA CONTEXT:
- Log files may be hours, days, or weeks old depending on export schedules
- Multiple log sources may be present (web servers, firewalls, auth systems, cloud audit logs)
- Log formats vary: Apache/Nginx access logs, JSON, Syslog, Windows Event Logs, CloudTrail, etc.
- File paths in GCS do NOT correspond to paths on source systems
- You are viewing a snapshot in time, not live data

YOUR ROLE:
1. ANALYZE: Identify patterns, anomalies, and security-relevant events in the exported logs
2. CORRELATE: Connect related events across different log sources when possible
3. CONTEXTUALIZE: Provide threat intelligence and CVE context via internet search
4. RECOMMEND: Suggest investigation steps and remediation actions for humans to execute
5. REPORT: Summarize findings in actionable, professional security reports

LIMITATIONS:
- Cannot access live systems or real-time data
- Cannot execute remediation (block IPs, disable accounts, patch systems, etc.)
- Cannot guarantee log completeness (gaps may exist in exported data)
- Analysis is based on exported snapshots, not current system state
- Cannot verify if threats are still active or have been remediated
"""

# Prompt for pattern discovery and log analysis
PATTERN_ANALYSIS_PROMPT = """
{system_identity}
{session_context}
CURRENT TASK:
You are a Tier 3 SOC Analyst reviewing exported log data. Analyze the following log pattern summary from a file named '{file_name}'.

IMPORTANT: This is EXPORTED log data stored in GCS, not a live system. Your analysis should:
- Identify what type of system originally generated these logs
- Assess security relevance of the patterns found
- Recommend next steps for the human analyst to investigate
- Consider any previous analyses from this session when making recommendations

SUMMARY DATA:
{summary_text}

ANALYSIS TASKS:
1. Identify the likely technology that ORIGINALLY generated these logs (e.g. Nginx, Windows Event Log, AWS CloudTrail)
2. Analyze the patterns for security relevance. If you encounter unfamiliar patterns, IPs, or attack signatures, search the internet for the latest threat intelligence.
3. Specifically analyze for:
   - High volumes of specific errors (e.g. 405 Method Not Allowed, 401 Unauthorized)
   - Suspicious methods (e.g. PROPFIND, CONNECT) that might indicate reconnaissance
   - Any patterns that match recent CVEs or emerging threats
   - Noise that should be filtered out
4. Recommend 2-3 specific "Next Steps" for the analyst using the available tools (search, analyze, etc.)
5. If you identify specific threats, mention any recent CVEs or security advisories related to the patterns found

REMEMBER: You are analyzing historical exported data. Any threats identified may have already been addressed or may still be active - the analyst will need to verify with the source systems.

Use internet search when needed for threat intelligence, CVE lookup, or unfamiliar attack patterns.
Keep your response concise and action-oriented.
"""

# Prompt for conversational SOC assistant
CONVERSATIONAL_ASSISTANT_PROMPT = """
{system_identity}
{session_context}
CURRENT CONTEXT:
You are assisting a SOC analyst who is investigating exported log files stored in Google Cloud Storage.

ANALYST REQUEST:
"{user_input}"

AVAILABLE LOG FILES:
{available_files}

AVAILABLE ANALYSIS TOOLS:
{tool_descriptions}

YOUR TASK:
1. Understand what the analyst wants to find in the exported log data
2. Determine which tool(s) to use and with what parameters
3. Execute the appropriate tool calls by responding with structured JSON
4. Analyze the results and provide actionable insights

IMPORTANT REMINDERS:
- These are EXPORTED logs, not live system access
- File paths are GCS paths, not source system paths
- You can only READ and ANALYZE, not modify or remediate
- Recommend actions for the analyst to take on source systems

RESPONSE FORMAT:
You must respond with valid JSON containing:
{{
  "analysis": "Brief explanation of what you're looking for in the exported logs and why",
  "tool_calls": [
    {{
      "tool": "tool_name",
      "parameters": {{
        "param1": "value1",
        "param2": "value2"
      }}
    }}
  ],
  "internet_search": "query for threat intelligence (optional)"
}}

COMMON WORKFLOWS:
- "Show top talkers/IPs" → analyze_log_attribute with IP regex
- "Show top users" → analyze_log_attribute with user regex (depends on log format)
- "Investigate IP X.X.X.X" → search_log for the IP, then analyze patterns
- "Find errors/warnings" → search_log for "error" or "warning", then analyze
- "Security events/attacks" → discover_log_patterns with full_log=true
- "Suspicious methods" → search_log for "PROPFIND|CONNECT|TRACE" etc.

TOOL PARAMETERS:
- analyze_log_attribute: file_name (required), pattern (regex), bucket_name (optional), limit (optional)
- search_log: file_name (required), query (text), bucket_name (optional), max_results (optional)
- discover_log_patterns: file_name (required), bucket_name (optional), full_log (optional)
- list_logs: bucket_name (optional), prefix (optional)
- list_buckets: no parameters
- soc_workflow: workflow_type (top_talkers|investigate_ip|security_events|attack_patterns), file_name, bucket_name (optional), target (optional)

REGEX PATTERNS:
- IPv4: r"(\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}})"
- HTTP Status: r"\\s(\\d{{3}})\\s"
- HTTP Methods: r"\\"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS|PROPFIND|CONNECT|TRACE)\\s"

Respond ONLY with the JSON format above. No additional text.
"""

# Prompt for final analysis summary
FINAL_ANALYSIS_PROMPT = """
{system_identity}
{session_context}
ANALYST REQUEST: "{user_input}"

ANALYSIS PLAN: {analysis_plan}

TOOL EXECUTION RESULTS FROM EXPORTED LOGS:
{tool_results}

THREAT INTELLIGENCE (from internet search):
{threat_intel}

TASK:
Provide a comprehensive, actionable summary for the SOC analyst.

IMPORTANT CONTEXT:
- The data analyzed came from EXPORTED log files in GCS
- These logs are historical snapshots from source systems
- Any threats identified need verification on the actual source systems
- You cannot confirm if threats are still active or have been remediated

INCLUDE IN YOUR RESPONSE:
1. What was discovered in the exported log data
2. Security implications and risk level assessment
3. Specific indicators of compromise (IoCs) if any were found
4. Recommended immediate actions (for the analyst to take on source systems)
5. Long-term monitoring recommendations
6. Any relevant CVEs or threat intelligence context
7. Caveats about the analysis (data age, completeness, etc.)

Format as a professional security analyst report.
"""

# Helper function to format prompts
def get_pattern_analysis_prompt(file_name: str, summary_text: str, include_history: bool = True) -> str:
    """Get the formatted pattern analysis prompt with optional session history."""
    session_context = get_context_for_prompt() if include_history else ""
    return PATTERN_ANALYSIS_PROMPT.format(
        system_identity=SYSTEM_IDENTITY,
        session_context=session_context,
        file_name=file_name,
        summary_text=summary_text
    )

def get_conversational_prompt(user_input: str, available_files: str, tool_descriptions: str, include_history: bool = True) -> str:
    """Get the formatted conversational assistant prompt with optional session history."""
    session_context = get_context_for_prompt() if include_history else ""
    return CONVERSATIONAL_ASSISTANT_PROMPT.format(
        system_identity=SYSTEM_IDENTITY,
        session_context=session_context,
        user_input=user_input,
        available_files=available_files,
        tool_descriptions=tool_descriptions
    )

def get_final_analysis_prompt(user_input: str, analysis_plan: str, tool_results: str, threat_intel: str, include_history: bool = True) -> str:
    """Get the formatted final analysis prompt with optional session history."""
    session_context = get_context_for_prompt() if include_history else ""
    return FINAL_ANALYSIS_PROMPT.format(
        system_identity=SYSTEM_IDENTITY,
        session_context=session_context,
        user_input=user_input,
        analysis_plan=analysis_plan,
        tool_results=tool_results,
        threat_intel=threat_intel
    )


# =============================================================================
# ANALYSIS HISTORY TRACKING
# =============================================================================

@dataclass
class AnalysisRecord:
    """A single analysis event record."""
    timestamp: str
    file_name: str
    bucket_name: str
    analysis_type: str  # scan, analyze, investigate, search, templates
    query: str  # The pattern, search term, or command used
    summary: str  # Brief summary of findings
    key_findings: List[str] = field(default_factory=list)  # Top findings/IOCs
    record_count: int = 0  # Number of records/lines analyzed
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "file": self.file_name,
            "bucket": self.bucket_name,
            "type": self.analysis_type,
            "query": self.query,
            "summary": self.summary,
            "key_findings": self.key_findings,
            "records": self.record_count
        }
    
    def to_context_string(self) -> str:
        """Format for inclusion in LLM context."""
        findings = ", ".join(self.key_findings[:5]) if self.key_findings else "None noted"
        return f"[{self.timestamp}] {self.analysis_type.upper()} on {self.file_name}: {self.summary} | Key findings: {findings}"


class AnalysisHistory:
    """
    Tracks history of event record analyses for context continuity.
    
    Maintains a rolling window of recent analyses to provide context
    to the LLM for follow-up questions and correlation.
    """
    
    def __init__(self, max_records: int = 20):
        self._history: deque = deque(maxlen=max_records)
        self._files_analyzed: Dict[str, List[str]] = {}  # file -> list of analysis types
        self._iocs_found: Dict[str, List[str]] = {}  # IOC type -> values (IPs, users, etc.)
    
    def add_record(self, record: AnalysisRecord) -> None:
        """Add an analysis record to history."""
        self._history.append(record)
        
        # Track files analyzed
        if record.file_name not in self._files_analyzed:
            self._files_analyzed[record.file_name] = []
        if record.analysis_type not in self._files_analyzed[record.file_name]:
            self._files_analyzed[record.file_name].append(record.analysis_type)
    
    def add_ioc(self, ioc_type: str, value: str) -> None:
        """Track an indicator of compromise found during analysis."""
        if ioc_type not in self._iocs_found:
            self._iocs_found[ioc_type] = []
        if value not in self._iocs_found[ioc_type]:
            self._iocs_found[ioc_type].append(value)
            # Keep IOC lists manageable
            if len(self._iocs_found[ioc_type]) > 50:
                self._iocs_found[ioc_type] = self._iocs_found[ioc_type][-50:]
    
    def add_iocs(self, ioc_type: str, values: List[str]) -> None:
        """Track multiple IOCs of the same type."""
        for value in values:
            self.add_ioc(ioc_type, value)
    
    def get_recent_records(self, limit: int = 10) -> List[AnalysisRecord]:
        """Get the most recent analysis records."""
        return list(self._history)[-limit:]
    
    def get_context_summary(self, max_records: int = 10) -> str:
        """
        Generate a context summary for LLM prompts.
        
        Returns a formatted string summarizing recent analyses
        that can be injected into prompts.
        """
        if not self._history:
            return "No previous analyses in this session."
        
        lines = ["PREVIOUS ANALYSES IN THIS SESSION:"]
        
        # Recent analysis records
        recent = self.get_recent_records(max_records)
        for record in recent:
            lines.append(f"  - {record.to_context_string()}")
        
        # Files analyzed summary
        if self._files_analyzed:
            lines.append("\nFILES ANALYZED:")
            for file_name, types in list(self._files_analyzed.items())[-5:]:
                lines.append(f"  - {file_name}: {', '.join(types)}")
        
        # IOCs found
        if self._iocs_found:
            lines.append("\nIOCs IDENTIFIED:")
            for ioc_type, values in self._iocs_found.items():
                sample = values[:5]
                more = f" (+{len(values)-5} more)" if len(values) > 5 else ""
                lines.append(f"  - {ioc_type}: {', '.join(sample)}{more}")
        
        return "\n".join(lines)
    
    def get_file_history(self, file_name: str) -> List[AnalysisRecord]:
        """Get all analyses performed on a specific file."""
        return [r for r in self._history if r.file_name == file_name]
    
    def get_iocs(self, ioc_type: Optional[str] = None) -> Dict[str, List[str]]:
        """Get tracked IOCs, optionally filtered by type."""
        if ioc_type:
            return {ioc_type: self._iocs_found.get(ioc_type, [])}
        return self._iocs_found.copy()
    
    def clear(self) -> None:
        """Clear all history."""
        self._history.clear()
        self._files_analyzed.clear()
        self._iocs_found.clear()
    
    def to_json(self) -> str:
        """Export history as JSON."""
        return json.dumps({
            "records": [r.to_dict() for r in self._history],
            "files_analyzed": self._files_analyzed,
            "iocs_found": self._iocs_found
        }, indent=2)


# Global analysis history instance
_analysis_history = AnalysisHistory()


def get_analysis_history() -> AnalysisHistory:
    """Get the global analysis history instance."""
    return _analysis_history


def record_analysis(
    file_name: str,
    bucket_name: str,
    analysis_type: str,
    query: str,
    summary: str,
    key_findings: Optional[List[str]] = None,
    record_count: int = 0,
    iocs: Optional[Dict[str, List[str]]] = None
) -> AnalysisRecord:
    """
    Convenience function to record an analysis and return the record.
    
    Args:
        file_name: Name of the file analyzed
        bucket_name: GCS bucket name
        analysis_type: Type of analysis (scan, analyze, investigate, search, templates)
        query: The pattern, search term, or command used
        summary: Brief summary of findings
        key_findings: List of key findings or IOCs
        record_count: Number of records/lines analyzed
        iocs: Dict of IOC type -> values to track
    
    Returns:
        The created AnalysisRecord
    """
    record = AnalysisRecord(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        file_name=file_name,
        bucket_name=bucket_name,
        analysis_type=analysis_type,
        query=query,
        summary=summary,
        key_findings=key_findings or [],
        record_count=record_count
    )
    
    _analysis_history.add_record(record)
    
    # Track IOCs if provided
    if iocs:
        for ioc_type, values in iocs.items():
            _analysis_history.add_iocs(ioc_type, values)
    
    return record


def get_context_for_prompt() -> str:
    """
    Get analysis history context formatted for inclusion in LLM prompts.
    
    Returns:
        Formatted string with session history, or empty string if no history.
    """
    history = get_analysis_history()
    if not history._history:
        return ""
    
    return f"\n\n{history.get_context_summary()}\n"


def clear_session_history() -> None:
    """Clear the analysis history for a new session."""
    _analysis_history.clear()


# =============================================================================
# ATTACK PATH DECOMPOSITION FOR DEFENSE-IN-DEPTH ANALYSIS
# =============================================================================

class AttackPhase(Enum):
    """MITRE ATT&CK-aligned attack phases."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class DefenseLayerType(Enum):
    """Types of defense-in-depth layers."""
    PERIMETER = "perimeter"  # Firewalls, WAF, IDS/IPS
    NETWORK = "network"  # Network segmentation, VLANs, microsegmentation
    ENDPOINT = "endpoint"  # EDR, AV, host-based firewalls
    APPLICATION = "application"  # Input validation, auth, session mgmt
    DATA = "data"  # Encryption, DLP, access controls
    IDENTITY = "identity"  # IAM, MFA, PAM
    MONITORING = "monitoring"  # SIEM, logging, alerting


@dataclass
class DefenseLayer:
    """
    Represents a defensive control layer that must be bypassed.
    
    Models a specific security control within the defense-in-depth architecture
    that an attacker must overcome to progress their attack.
    """
    layer_type: DefenseLayerType
    control_name: str  # e.g., "Web Application Firewall", "MFA", "Network Segmentation"
    description: str
    bypass_techniques: List[str] = field(default_factory=list)  # Known bypass methods
    detection_capabilities: List[str] = field(default_factory=list)  # What this layer can detect
    log_sources: List[str] = field(default_factory=list)  # Associated log sources
    effectiveness: str = "unknown"  # high, medium, low, bypassed, unknown
    
    def to_dict(self) -> Dict:
        return {
            "layer_type": self.layer_type.value,
            "control_name": self.control_name,
            "description": self.description,
            "bypass_techniques": self.bypass_techniques,
            "detection_capabilities": self.detection_capabilities,
            "log_sources": self.log_sources,
            "effectiveness": self.effectiveness
        }


@dataclass
class AttackStep:
    """
    Represents a single step in an attack path.
    
    Each step corresponds to an action an adversary must complete,
    including the defensive layers they must bypass.
    """
    step_number: int
    phase: AttackPhase
    technique_id: str  # MITRE ATT&CK technique ID (e.g., T1190)
    technique_name: str  # Human-readable name
    description: str  # What the attacker does in this step
    target_asset: str  # The asset being targeted
    required_access: str  # What access level is needed to attempt this step
    resulting_access: str  # What access is gained if successful
    defense_layers: List[DefenseLayer] = field(default_factory=list)  # Defenses to bypass
    evidence_sources: List[str] = field(default_factory=list)  # Where to find evidence
    iocs: List[str] = field(default_factory=list)  # Indicators of compromise
    detection_opportunities: List[str] = field(default_factory=list)  # How to detect this step
    status: str = "unknown"  # attempted, successful, blocked, unknown
    confidence: str = "low"  # Confidence in this assessment: high, medium, low
    
    def to_dict(self) -> Dict:
        return {
            "step_number": self.step_number,
            "phase": self.phase.value,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "description": self.description,
            "target_asset": self.target_asset,
            "required_access": self.required_access,
            "resulting_access": self.resulting_access,
            "defense_layers": [d.to_dict() for d in self.defense_layers],
            "evidence_sources": self.evidence_sources,
            "iocs": self.iocs,
            "detection_opportunities": self.detection_opportunities,
            "status": self.status,
            "confidence": self.confidence
        }
    
    def to_context_string(self) -> str:
        """Format for inclusion in LLM context."""
        defenses = ", ".join([d.control_name for d in self.defense_layers]) or "None identified"
        return (f"Step {self.step_number} [{self.phase.value}]: {self.technique_name} ({self.technique_id}) "
                f"-> Target: {self.target_asset} | Defenses: {defenses} | Status: {self.status}")


@dataclass
class AttackPath:
    """
    Represents a complete attack path from initial access to objective.
    
    Models the full sequence of steps an adversary would need to complete
    to successfully compromise assets protected by defense-in-depth.
    """
    path_id: str
    name: str  # Descriptive name for this attack path
    description: str
    threat_actor: str = "Unknown"  # Attributed threat actor if known
    objective: str = ""  # Ultimate goal (data theft, ransomware, etc.)
    target_assets: List[str] = field(default_factory=list)  # Final target assets
    entry_point: str = ""  # Initial entry vector
    steps: List[AttackStep] = field(default_factory=list)
    overall_status: str = "analyzing"  # analyzing, partial, complete, blocked
    blocked_at_step: Optional[int] = None  # Step number where attack was blocked
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def add_step(self, step: AttackStep) -> None:
        """Add a step to the attack path."""
        self.steps.append(step)
        self.steps.sort(key=lambda s: s.step_number)
    
    def get_defense_layers_summary(self) -> Dict[str, List[str]]:
        """Get summary of all defense layers across the attack path."""
        layers: Dict[str, List[str]] = {}
        for step in self.steps:
            for defense in step.defense_layers:
                layer_type = defense.layer_type.value
                if layer_type not in layers:
                    layers[layer_type] = []
                if defense.control_name not in layers[layer_type]:
                    layers[layer_type].append(defense.control_name)
        return layers
    
    def get_detection_opportunities(self) -> List[Tuple[int, str, List[str]]]:
        """Get all detection opportunities across steps."""
        return [(step.step_number, step.technique_name, step.detection_opportunities) 
                for step in self.steps if step.detection_opportunities]
    
    def get_weakest_link(self) -> Optional[AttackStep]:
        """Identify the step with fewest/weakest defenses."""
        if not self.steps:
            return None
        # Find step with fewest defense layers or lowest effectiveness
        return min(self.steps, key=lambda s: len(s.defense_layers))
    
    def to_dict(self) -> Dict:
        return {
            "path_id": self.path_id,
            "name": self.name,
            "description": self.description,
            "threat_actor": self.threat_actor,
            "objective": self.objective,
            "target_assets": self.target_assets,
            "entry_point": self.entry_point,
            "steps": [s.to_dict() for s in self.steps],
            "overall_status": self.overall_status,
            "blocked_at_step": self.blocked_at_step,
            "created_at": self.created_at,
            "defense_layers_summary": self.get_defense_layers_summary()
        }
    
    def to_json(self) -> str:
        """Export attack path as JSON."""
        return json.dumps(self.to_dict(), indent=2)
    
    def to_context_string(self) -> str:
        """Format for inclusion in LLM context."""
        lines = [
            f"ATTACK PATH: {self.name} (ID: {self.path_id})",
            f"Objective: {self.objective}",
            f"Entry Point: {self.entry_point}",
            f"Status: {self.overall_status}",
            f"Steps ({len(self.steps)}):"
        ]
        for step in self.steps:
            lines.append(f"  {step.to_context_string()}")
        return "\n".join(lines)


# =============================================================================
# PCAP / NETWORK TRAFFIC ANALYSIS PROMPTS
# =============================================================================

# Core system identity for Network/PCAP analysis
PCAP_SYSTEM_IDENTITY = """
SYSTEM IDENTITY:
You are an AI-powered Security Operations Center (SOC) Network Traffic Analysis Assistant.

CRITICAL UNDERSTANDING:
- You are analyzing PARSED METADATA and SUMMARIES extracted from PCAP (Packet Capture) files.
- You are NOT looking at raw packet payloads due to context window limitations.
- You are performing READ-ONLY forensic analysis on historical network traffic.
- You CANNOT interact with or modify the original network or endpoints.
- You CANNOT take remediation actions (e.g., block IPs on firewalls) - you can only analyze and recommend.

DATA CONTEXT:
- The data provided is a distilled summary including: Top Talkers, connection states, identified protocols, lateral movement indicators, and extracted metadata (e.g., HTTP headers, DNS queries).
- File sizes for the original PCAPs were massive; you are viewing a highly optimized subset.
- Network traffic captures a specific snapshot in time.
- Internal IP addresses typically follow RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).

YOUR ROLE:
1. TRIAGE: Quickly identify if the network behavior warrants escalation.
2. HUNT: Proactively look for hidden threats, Command and Control (C2) beaconing, and lateral movement.
3. CONTEXTUALIZE: Map findings to MITRE ATT&CK tactics and techniques.
4. EXTRACT: Isolate high-fidelity Indicators of Compromise (IoCs) from the noise.
5. REPORT: Summarize findings for shift handovers and incident response tickets.

LIMITATIONS:
- Cannot access live network streams (no live packet sniffing).
- Cannot guarantee full payload visibility (data is pre-parsed).
- Cannot execute active defense measures.
"""

# Prompt for Tier 1/Tier 2 Triage and Priority Analysis
PCAP_TRIAGE_PROMPT = """
{pcap_system_identity}
{session_context}
CURRENT TASK:
You are a SOC Analyst conducting initial triage on a parsed network traffic capture. Analyze the following PCAP summary from a file named '{file_name}'.

IMPORTANT: Focus on separating benign network noise from actual anomalous behavior.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. THE BASELINE CHECK: Review the 'Top Talkers' and 'Lateral Movement' indicators. Identify any anomalous patterns (e.g., unusual port usage, unexpected internal-to-internal communication, or massive data exfiltration spikes).
2. C2 BEACONING HUNTER: Analyze the summary for indicators of Command and Control (C2) beaconing. Look for:
   - Repetitive connection attempts to external IPs.
   - Uniform payload sizes.
   - Consistent communication intervals, especially over ports 80/443 or unusual high-numbered ports.
3. PRIORITIZATION: Rank the top 3 findings by severity (Critical, High, Medium, Low) and explain exactly why they are suspicious based on standard network baseline behavior.
4. NEXT STEPS: Recommend 2 specific next steps for the human analyst using available tools (e.g., "query the firewall logs for IP X.X.X.X" or "check EDR telemetry for the host at Y.Y.Y.Y").

Keep your response concise, prioritized, and action-oriented.

Finally, end your response with a TL;DR section:

⚡ TL;DR
- One-line overall risk verdict (e.g., "HIGH - Potential C2 beaconing detected")
- Top 1-3 bullet points: the most critical findings the analyst must act on NOW
"""

# Prompt for Deep Dive Threat Hunting and Hypothesis Generation
PCAP_THREAT_HUNT_PROMPT = """
{pcap_system_identity}
{session_context}
CURRENT TASK:
You are a proactive Threat Hunter analyzing a parsed PCAP summary for advanced persistent threats (APTs) or stealthy network intrusions.

FILE: '{file_name}'

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. MITRE ATT&CK MAPPING: Review the observed network behavior. Map the activities to the MITRE ATT&CK framework. List the specific Tactics and Techniques (with IDs) that this traffic might represent, providing a brief justification for each.
2. HYPOTHESIS GENERATION: Based on the static analysis provided, formulate three (3) distinct hypotheses about what an attacker might be attempting to achieve on this network (e.g., "Hypothesis 1: Data Exfiltration via DNS Tunneling").
3. EVIDENCE GATHERING: For each hypothesis, explicitly state what specific secondary logs the human analyst should query next to confirm or deny the theory (e.g., Windows Event Logs, Active Directory authentication logs, specific application logs).

Use internet search if you encounter unfamiliar protocols, suspicious external domains, or attack signatures to provide up-to-date threat intelligence.

Finally, end your response with a TL;DR section:

⚡ TL;DR
- One-line overall risk verdict (e.g., "MEDIUM - Possible APT staging activity")
- Top 1-3 bullet points: the most critical hypotheses and what to check next
"""

# Prompt for Final Reporting and IOC Extraction
PCAP_REPORTING_AND_IOC_PROMPT = """
{pcap_system_identity}
{session_context}
CURRENT TASK:
You are a Senior Incident Responder tasked with wrapping up the analysis of network traffic from '{file_name}' and preparing documentation for the SOC.

SUMMARY DATA:
{pcap_summary_data}

PREVIOUS ANALYSIS RESULTS:
{previous_analysis_context}

ANALYSIS TASKS:
Provide a comprehensive, actionable summary formatted strictly for a professional security context.

INCLUDE IN YOUR RESPONSE:
1. EXECUTIVE SUMMARY: A concise shift handover note summarizing the traffic scope and the most critical security findings.
2. INDICATORS OF COMPROMISE (IoCs): Extract all potential IoCs from the summary data. Output them as a clean, actionable list formatted strictly as:
   - [Type (IP/Domain/Port)] | [Value] | [Context/Reason for suspicion]
   *Note: Exclude standard private RFC 1918 IPs unless they are the confirmed source of internal lateral movement.*
3. IMMEDIATE ACTIONS: Clear recommended next steps for the incoming analyst or incident response team to take on the source systems or firewalls.
4. LIMITATION CAVEATS: A brief note on what cannot be determined from this parsed PCAP data alone.

Format as a professional security analyst shift-handover report.

Finally, end your response with a TL;DR section:

⚡ TL;DR
- One-line overall risk verdict (e.g., "CRITICAL - Active exfiltration indicators found")
- Top 1-3 bullet points: the most urgent IOCs and immediate actions
"""


# PCAP prompt helper functions
def get_pcap_triage_prompt(
    file_name: str,
    pcap_summary_data: str,
    include_history: bool = True,
) -> str:
    """Get the formatted PCAP triage prompt."""
    session_context = (
        get_context_for_prompt() if include_history else ""
    )
    return PCAP_TRIAGE_PROMPT.format(
        pcap_system_identity=PCAP_SYSTEM_IDENTITY,
        session_context=session_context,
        file_name=file_name,
        pcap_summary_data=pcap_summary_data,
    )


def get_pcap_threat_hunt_prompt(
    file_name: str,
    pcap_summary_data: str,
    include_history: bool = True,
) -> str:
    """Get the formatted PCAP threat hunt prompt."""
    session_context = (
        get_context_for_prompt() if include_history else ""
    )
    return PCAP_THREAT_HUNT_PROMPT.format(
        pcap_system_identity=PCAP_SYSTEM_IDENTITY,
        session_context=session_context,
        file_name=file_name,
        pcap_summary_data=pcap_summary_data,
    )


def get_pcap_reporting_prompt(
    file_name: str,
    pcap_summary_data: str,
    previous_analysis_context: str = "No previous analysis.",
    include_history: bool = True,
) -> str:
    """Get the formatted PCAP reporting and IOC extraction prompt."""
    session_context = (
        get_context_for_prompt() if include_history else ""
    )
    return PCAP_REPORTING_AND_IOC_PROMPT.format(
        pcap_system_identity=PCAP_SYSTEM_IDENTITY,
        session_context=session_context,
        file_name=file_name,
        pcap_summary_data=pcap_summary_data,
        previous_analysis_context=previous_analysis_context,
    )


# =============================================================================
# ATTACK PATH ANALYSIS PROMPTS
# =============================================================================

ATTACK_PATH_ANALYSIS_PROMPT = """
{system_identity}
{session_context}
ATTACK PATH DECOMPOSITION TASK:
You are analyzing log evidence to reconstruct an attack path against assets protected by defense-in-depth.

TARGET ASSET(S): {target_assets}
SUSPECTED ENTRY POINT: {entry_point}
AVAILABLE LOG EVIDENCE:
{log_evidence}

ANALYSIS OBJECTIVES:
1. Decompose the attack into discrete steps aligned with MITRE ATT&CK phases
2. For each step, identify:
   - The specific technique used (with ATT&CK ID if known)
   - The defensive layer(s) the attacker had to bypass
   - Evidence of success or failure at each step
   - Detection opportunities that were missed or triggered

3. Map the defense-in-depth layers involved:
   - PERIMETER: Firewalls, WAF, IDS/IPS
   - NETWORK: Segmentation, VLANs, microsegmentation
   - ENDPOINT: EDR, AV, host-based controls
   - APPLICATION: Input validation, authentication, authorization
   - DATA: Encryption, DLP, access controls
   - IDENTITY: IAM, MFA, PAM
   - MONITORING: SIEM, logging, alerting

4. Identify the "weakest link" - which defense layer failed or was bypassed

RESPONSE FORMAT:
Provide your analysis as a structured attack path with:
- Overall attack summary
- Step-by-step breakdown with defense layer analysis
- Gap analysis: which defenses were missing or ineffective
- Recommendations for strengthening defense-in-depth

Remember: You are analyzing EXPORTED historical logs. The attack may be ongoing, completed, or already remediated.
"""

DEFENSE_GAP_ANALYSIS_PROMPT = """
{system_identity}
{session_context}
DEFENSE-IN-DEPTH GAP ANALYSIS:

Based on the attack path analysis, evaluate the effectiveness of each defense layer.

ATTACK PATH SUMMARY:
{attack_path_summary}

For each defense layer type, assess:
1. Was this layer present in the attack path?
2. Did it detect the attack? (Evidence in logs)
3. Did it prevent/block the attack?
4. What gaps allowed bypass?

DEFENSE LAYERS TO EVALUATE:
- PERIMETER CONTROLS: {perimeter_controls}
- NETWORK CONTROLS: {network_controls}
- ENDPOINT CONTROLS: {endpoint_controls}
- APPLICATION CONTROLS: {application_controls}
- DATA CONTROLS: {data_controls}
- IDENTITY CONTROLS: {identity_controls}
- MONITORING CONTROLS: {monitoring_controls}

Provide:
1. Layer-by-layer effectiveness rating (Effective/Partial/Bypassed/Missing)
2. Specific gaps identified from log evidence
3. Prioritized recommendations to close gaps
4. Quick wins vs. strategic improvements
"""


# =============================================================================
# ATTACK PATH TRACKING
# =============================================================================

class AttackPathTracker:
    """
    Tracks attack paths identified during analysis sessions.
    
    Maintains a collection of attack paths being analyzed,
    allowing correlation across multiple log sources.
    """
    
    def __init__(self):
        self._paths: Dict[str, AttackPath] = {}
        self._path_counter: int = 0
    
    def create_path(
        self,
        name: str,
        description: str,
        objective: str = "",
        target_assets: Optional[List[str]] = None,
        entry_point: str = "",
        threat_actor: str = "Unknown"
    ) -> AttackPath:
        """Create a new attack path and return it."""
        self._path_counter += 1
        path_id = f"AP-{self._path_counter:04d}"
        
        path = AttackPath(
            path_id=path_id,
            name=name,
            description=description,
            threat_actor=threat_actor,
            objective=objective,
            target_assets=target_assets or [],
            entry_point=entry_point
        )
        
        self._paths[path_id] = path
        return path
    
    def get_path(self, path_id: str) -> Optional[AttackPath]:
        """Get an attack path by ID."""
        return self._paths.get(path_id)
    
    def get_all_paths(self) -> List[AttackPath]:
        """Get all tracked attack paths."""
        return list(self._paths.values())
    
    def add_step_to_path(
        self,
        path_id: str,
        phase: AttackPhase,
        technique_id: str,
        technique_name: str,
        description: str,
        target_asset: str,
        required_access: str = "none",
        resulting_access: str = "none",
        defense_layers: Optional[List[DefenseLayer]] = None,
        evidence_sources: Optional[List[str]] = None,
        iocs: Optional[List[str]] = None,
        detection_opportunities: Optional[List[str]] = None,
        status: str = "unknown",
        confidence: str = "low"
    ) -> Optional[AttackStep]:
        """Add a step to an existing attack path."""
        path = self._paths.get(path_id)
        if not path:
            return None
        
        step_number = len(path.steps) + 1
        step = AttackStep(
            step_number=step_number,
            phase=phase,
            technique_id=technique_id,
            technique_name=technique_name,
            description=description,
            target_asset=target_asset,
            required_access=required_access,
            resulting_access=resulting_access,
            defense_layers=defense_layers or [],
            evidence_sources=evidence_sources or [],
            iocs=iocs or [],
            detection_opportunities=detection_opportunities or [],
            status=status,
            confidence=confidence
        )
        
        path.add_step(step)
        return step
    
    def update_path_status(self, path_id: str, status: str, blocked_at: Optional[int] = None) -> bool:
        """Update the overall status of an attack path."""
        path = self._paths.get(path_id)
        if not path:
            return False
        path.overall_status = status
        path.blocked_at_step = blocked_at
        return True
    
    def get_context_summary(self) -> str:
        """Generate context summary of all attack paths for LLM prompts."""
        if not self._paths:
            return "No attack paths identified in this session."
        
        lines = ["ATTACK PATHS UNDER ANALYSIS:"]
        for path in self._paths.values():
            lines.append(f"\n{path.to_context_string()}")
        return "\n".join(lines)
    
    def clear(self) -> None:
        """Clear all tracked attack paths."""
        self._paths.clear()
        self._path_counter = 0
    
    def to_json(self) -> str:
        """Export all attack paths as JSON."""
        return json.dumps({
            "attack_paths": [p.to_dict() for p in self._paths.values()]
        }, indent=2)


# Global attack path tracker instance
_attack_path_tracker = AttackPathTracker()


def get_attack_path_tracker() -> AttackPathTracker:
    """Get the global attack path tracker instance."""
    return _attack_path_tracker


def get_attack_path_analysis_prompt(
    target_assets: str,
    entry_point: str,
    log_evidence: str,
    include_history: bool = True
) -> str:
    """Get the formatted attack path analysis prompt."""
    session_context = get_context_for_prompt() if include_history else ""
    return ATTACK_PATH_ANALYSIS_PROMPT.format(
        system_identity=SYSTEM_IDENTITY,
        session_context=session_context,
        target_assets=target_assets,
        entry_point=entry_point,
        log_evidence=log_evidence
    )


def get_defense_gap_analysis_prompt(
    attack_path_summary: str,
    perimeter_controls: str = "Unknown",
    network_controls: str = "Unknown",
    endpoint_controls: str = "Unknown",
    application_controls: str = "Unknown",
    data_controls: str = "Unknown",
    identity_controls: str = "Unknown",
    monitoring_controls: str = "Unknown",
    include_history: bool = True
) -> str:
    """Get the formatted defense gap analysis prompt."""
    session_context = get_context_for_prompt() if include_history else ""
    return DEFENSE_GAP_ANALYSIS_PROMPT.format(
        system_identity=SYSTEM_IDENTITY,
        session_context=session_context,
        attack_path_summary=attack_path_summary,
        perimeter_controls=perimeter_controls,
        network_controls=network_controls,
        endpoint_controls=endpoint_controls,
        application_controls=application_controls,
        data_controls=data_controls,
        identity_controls=identity_controls,
        monitoring_controls=monitoring_controls
    )


def clear_attack_paths() -> None:
    """Clear all attack paths for a new session."""
    _attack_path_tracker.clear()


# =============================================================================
# THREAT MODEL ATTACK PATH ANALYSIS
# =============================================================================

@dataclass
class SecurityControl:
    """
    A security control that must be bypassed for an attack to succeed.
    
    Derived from threat modeling reports or tabletop exercise documentation.
    """
    control_id: str  # Unique identifier (e.g., "SC-001", "CTRL-WAF-01")
    name: str  # Human-readable name
    control_type: DefenseLayerType  # Which defense layer this belongs to
    description: str  # What this control does
    implementation_status: str = "implemented"  # implemented, partial, planned, missing
    bypass_difficulty: str = "medium"  # trivial, low, medium, high, very_high
    bypass_requirements: List[str] = field(default_factory=list)  # What attacker needs to bypass
    detection_capability: str = "medium"  # none, low, medium, high
    compensating_controls: List[str] = field(default_factory=list)  # Related controls that provide backup
    source_document: str = ""  # Reference to threat model or tabletop doc
    
    def to_dict(self) -> Dict:
        return {
            "control_id": self.control_id,
            "name": self.name,
            "control_type": self.control_type.value,
            "description": self.description,
            "implementation_status": self.implementation_status,
            "bypass_difficulty": self.bypass_difficulty,
            "bypass_requirements": self.bypass_requirements,
            "detection_capability": self.detection_capability,
            "compensating_controls": self.compensating_controls,
            "source_document": self.source_document
        }


@dataclass
class AttackSequenceEvent:
    """
    A discrete event in an attack sequence that must be accomplished.
    
    Represents a specific action or milestone the attacker must achieve,
    along with the security controls that would prevent or detect it.
    """
    event_id: str  # Unique identifier (e.g., "EVT-001")
    sequence_order: int  # Order in the attack sequence (1, 2, 3...)
    name: str  # Short name for the event
    description: str  # Detailed description of what must happen
    attack_technique: str = ""  # MITRE ATT&CK technique if applicable
    technique_id: str = ""  # MITRE ATT&CK ID (e.g., T1190)
    prerequisite_events: List[str] = field(default_factory=list)  # Event IDs that must complete first
    target_asset: str = ""  # Asset being targeted
    required_access: str = "none"  # Access level needed to attempt
    resulting_access: str = "none"  # Access gained if successful
    blocking_controls: List[str] = field(default_factory=list)  # Control IDs that would block this
    detecting_controls: List[str] = field(default_factory=list)  # Control IDs that would detect this
    success_indicators: List[str] = field(default_factory=list)  # How to know this event succeeded
    failure_indicators: List[str] = field(default_factory=list)  # How to know this event was blocked
    source_document: str = ""  # Reference to threat model or tabletop doc
    
    def to_dict(self) -> Dict:
        return {
            "event_id": self.event_id,
            "sequence_order": self.sequence_order,
            "name": self.name,
            "description": self.description,
            "attack_technique": self.attack_technique,
            "technique_id": self.technique_id,
            "prerequisite_events": self.prerequisite_events,
            "target_asset": self.target_asset,
            "required_access": self.required_access,
            "resulting_access": self.resulting_access,
            "blocking_controls": self.blocking_controls,
            "detecting_controls": self.detecting_controls,
            "success_indicators": self.success_indicators,
            "failure_indicators": self.failure_indicators,
            "source_document": self.source_document
        }


@dataclass
class ThreatScenario:
    """
    A complete threat scenario derived from threat modeling or tabletop exercises.
    
    Contains the full attack sequence and all security controls that must be
    bypassed for a successful attack against protected assets.
    """
    scenario_id: str
    name: str  # Descriptive name (e.g., "Ransomware via Phishing")
    description: str
    source_type: str  # "threat_model", "tabletop_exercise", "incident_review", "red_team"
    source_document: str  # Reference to source document
    threat_actor_profile: str = ""  # Description of assumed threat actor
    attack_objective: str = ""  # Ultimate goal of the attack
    target_assets: List[str] = field(default_factory=list)  # Assets at risk
    entry_vectors: List[str] = field(default_factory=list)  # Possible entry points
    security_controls: List[SecurityControl] = field(default_factory=list)
    attack_sequence: List[AttackSequenceEvent] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)  # Assumptions made in the scenario
    created_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def add_control(self, control: SecurityControl) -> None:
        """Add a security control to the scenario."""
        self.security_controls.append(control)
    
    def add_event(self, event: AttackSequenceEvent) -> None:
        """Add an attack sequence event."""
        self.attack_sequence.append(event)
        self.attack_sequence.sort(key=lambda e: e.sequence_order)
    
    def get_controls_by_type(self, control_type: DefenseLayerType) -> List[SecurityControl]:
        """Get all controls of a specific type."""
        return [c for c in self.security_controls if c.control_type == control_type]
    
    def get_control_by_id(self, control_id: str) -> Optional[SecurityControl]:
        """Get a control by its ID."""
        for c in self.security_controls:
            if c.control_id == control_id:
                return c
        return None
    
    def get_critical_path(self) -> List[AttackSequenceEvent]:
        """Get the minimum sequence of events required for attack success."""
        # Return events in order - all are required for success
        return sorted(self.attack_sequence, key=lambda e: e.sequence_order)
    
    def get_controls_for_event(self, event_id: str) -> Dict[str, List[SecurityControl]]:
        """Get blocking and detecting controls for a specific event."""
        event = next((e for e in self.attack_sequence if e.event_id == event_id), None)
        if not event:
            return {"blocking": [], "detecting": []}
        
        blocking = [self.get_control_by_id(cid) for cid in event.blocking_controls]
        detecting = [self.get_control_by_id(cid) for cid in event.detecting_controls]
        
        return {
            "blocking": [c for c in blocking if c is not None],
            "detecting": [c for c in detecting if c is not None]
        }
    
    def get_weakest_point(self) -> Optional[AttackSequenceEvent]:
        """Find the event with fewest/weakest controls."""
        if not self.attack_sequence:
            return None
        
        def control_strength(event: AttackSequenceEvent) -> int:
            blocking = len(event.blocking_controls)
            detecting = len(event.detecting_controls)
            return blocking * 2 + detecting  # Blocking controls weighted higher
        
        return min(self.attack_sequence, key=control_strength)
    
    def get_defense_coverage(self) -> Dict[str, Dict]:
        """Analyze defense coverage across all events."""
        coverage = {}
        for layer in DefenseLayerType:
            controls = self.get_controls_by_type(layer)
            coverage[layer.value] = {
                "control_count": len(controls),
                "controls": [c.name for c in controls],
                "implementation_status": {
                    "implemented": len([c for c in controls if c.implementation_status == "implemented"]),
                    "partial": len([c for c in controls if c.implementation_status == "partial"]),
                    "planned": len([c for c in controls if c.implementation_status == "planned"]),
                    "missing": len([c for c in controls if c.implementation_status == "missing"])
                }
            }
        return coverage
    
    def to_dict(self) -> Dict:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "source_type": self.source_type,
            "source_document": self.source_document,
            "threat_actor_profile": self.threat_actor_profile,
            "attack_objective": self.attack_objective,
            "target_assets": self.target_assets,
            "entry_vectors": self.entry_vectors,
            "security_controls": [c.to_dict() for c in self.security_controls],
            "attack_sequence": [e.to_dict() for e in self.attack_sequence],
            "assumptions": self.assumptions,
            "created_at": self.created_at,
            "defense_coverage": self.get_defense_coverage()
        }
    
    def to_json(self) -> str:
        """Export scenario as JSON."""
        return json.dumps(self.to_dict(), indent=2)


# =============================================================================
# THREAT SCENARIO PROMPTS
# =============================================================================

THREAT_MODEL_ANALYSIS_PROMPT = """
{system_identity}
{session_context}
THREAT MODEL ANALYSIS TASK:
You are analyzing a threat modeling report or tabletop exercise minutes to extract:
1. Security controls that must be bypassed for a successful attack
2. The sequence of attack events that must be accomplished

SOURCE DOCUMENT TYPE: {source_type}
DOCUMENT CONTENT:
{document_content}

EXTRACTION OBJECTIVES:

1. IDENTIFY SECURITY CONTROLS:
   For each control mentioned, extract:
   - Control name and unique ID
   - Control type (perimeter, network, endpoint, application, data, identity, monitoring)
   - Implementation status (implemented, partial, planned, missing)
   - Bypass difficulty (trivial, low, medium, high, very_high)
   - What an attacker would need to bypass it
   - Detection capability (none, low, medium, high)

2. IDENTIFY ATTACK SEQUENCE EVENTS:
   For each step in the attack scenario, extract:
   - Event name and sequence order
   - What must happen for this step to succeed
   - MITRE ATT&CK technique if applicable
   - Prerequisites (which events must complete first)
   - Which controls would BLOCK this event
   - Which controls would DETECT this event
   - Indicators of success or failure

3. MAP CONTROLS TO EVENTS:
   Create a matrix showing which controls protect against which attack events.

4. IDENTIFY GAPS:
   - Events with no blocking controls
   - Events with no detecting controls
   - Missing or partially implemented controls on critical path

RESPONSE FORMAT:
Provide structured output with:
- Scenario summary
- Complete list of security controls
- Ordered attack sequence with control mappings
- Gap analysis and recommendations
"""

TABLETOP_MINUTES_PROMPT = """
{system_identity}
{session_context}
TABLETOP EXERCISE ANALYSIS:
You are reviewing tabletop exercise minutes to extract the attack scenario and control effectiveness.

EXERCISE DETAILS:
{exercise_details}

MINUTES CONTENT:
{minutes_content}

ANALYSIS TASKS:

1. SCENARIO RECONSTRUCTION:
   - What was the simulated attack scenario?
   - What was the threat actor profile?
   - What was the attack objective?
   - What were the target assets?

2. ATTACK SEQUENCE EXTRACTION:
   Extract each step discussed in the exercise:
   - What action did the simulated attacker take?
   - What was the expected outcome?
   - What controls were tested?
   - Did controls work as expected?

3. CONTROL EFFECTIVENESS:
   For each control discussed:
   - Was it effective, partially effective, or ineffective?
   - What gaps were identified?
   - What improvements were recommended?

4. DECISION POINTS:
   Identify key decision points where:
   - A control could have blocked the attack
   - Detection could have occurred
   - Response actions were discussed

Provide structured output suitable for building a ThreatScenario model.
"""


# =============================================================================
# THREAT SCENARIO TRACKER
# =============================================================================

class ThreatScenarioTracker:
    """
    Tracks threat scenarios derived from threat models and tabletop exercises.
    """
    
    def __init__(self):
        self._scenarios: Dict[str, ThreatScenario] = {}
        self._scenario_counter: int = 0
        self._control_counter: int = 0
        self._event_counter: int = 0
    
    def create_scenario(
        self,
        name: str,
        description: str,
        source_type: str,
        source_document: str,
        threat_actor_profile: str = "",
        attack_objective: str = "",
        target_assets: Optional[List[str]] = None,
        entry_vectors: Optional[List[str]] = None,
        assumptions: Optional[List[str]] = None
    ) -> ThreatScenario:
        """Create a new threat scenario."""
        self._scenario_counter += 1
        scenario_id = f"TS-{self._scenario_counter:04d}"
        
        scenario = ThreatScenario(
            scenario_id=scenario_id,
            name=name,
            description=description,
            source_type=source_type,
            source_document=source_document,
            threat_actor_profile=threat_actor_profile,
            attack_objective=attack_objective,
            target_assets=target_assets or [],
            entry_vectors=entry_vectors or [],
            assumptions=assumptions or []
        )
        
        self._scenarios[scenario_id] = scenario
        return scenario
    
    def add_control_to_scenario(
        self,
        scenario_id: str,
        name: str,
        control_type: DefenseLayerType,
        description: str,
        implementation_status: str = "implemented",
        bypass_difficulty: str = "medium",
        bypass_requirements: Optional[List[str]] = None,
        detection_capability: str = "medium",
        compensating_controls: Optional[List[str]] = None,
        source_document: str = ""
    ) -> Optional[SecurityControl]:
        """Add a security control to a scenario."""
        scenario = self._scenarios.get(scenario_id)
        if not scenario:
            return None
        
        self._control_counter += 1
        control_id = f"SC-{self._control_counter:04d}"
        
        control = SecurityControl(
            control_id=control_id,
            name=name,
            control_type=control_type,
            description=description,
            implementation_status=implementation_status,
            bypass_difficulty=bypass_difficulty,
            bypass_requirements=bypass_requirements or [],
            detection_capability=detection_capability,
            compensating_controls=compensating_controls or [],
            source_document=source_document
        )
        
        scenario.add_control(control)
        return control
    
    def add_event_to_scenario(
        self,
        scenario_id: str,
        name: str,
        description: str,
        sequence_order: int,
        attack_technique: str = "",
        technique_id: str = "",
        prerequisite_events: Optional[List[str]] = None,
        target_asset: str = "",
        required_access: str = "none",
        resulting_access: str = "none",
        blocking_controls: Optional[List[str]] = None,
        detecting_controls: Optional[List[str]] = None,
        success_indicators: Optional[List[str]] = None,
        failure_indicators: Optional[List[str]] = None,
        source_document: str = ""
    ) -> Optional[AttackSequenceEvent]:
        """Add an attack sequence event to a scenario."""
        scenario = self._scenarios.get(scenario_id)
        if not scenario:
            return None
        
        self._event_counter += 1
        event_id = f"EVT-{self._event_counter:04d}"
        
        event = AttackSequenceEvent(
            event_id=event_id,
            sequence_order=sequence_order,
            name=name,
            description=description,
            attack_technique=attack_technique,
            technique_id=technique_id,
            prerequisite_events=prerequisite_events or [],
            target_asset=target_asset,
            required_access=required_access,
            resulting_access=resulting_access,
            blocking_controls=blocking_controls or [],
            detecting_controls=detecting_controls or [],
            success_indicators=success_indicators or [],
            failure_indicators=failure_indicators or [],
            source_document=source_document
        )
        
        scenario.add_event(event)
        return event
    
    def get_scenario(self, scenario_id: str) -> Optional[ThreatScenario]:
        """Get a scenario by ID."""
        return self._scenarios.get(scenario_id)
    
    def get_all_scenarios(self) -> List[ThreatScenario]:
        """Get all tracked scenarios."""
        return list(self._scenarios.values())
    
    def clear(self) -> None:
        """Clear all tracked scenarios."""
        self._scenarios.clear()
        self._scenario_counter = 0
        self._control_counter = 0
        self._event_counter = 0
    
    def to_json(self) -> str:
        """Export all scenarios as JSON."""
        return json.dumps({
            "threat_scenarios": [s.to_dict() for s in self._scenarios.values()]
        }, indent=2)


# Global threat scenario tracker
_threat_scenario_tracker = ThreatScenarioTracker()


def get_threat_scenario_tracker() -> ThreatScenarioTracker:
    """Get the global threat scenario tracker instance."""
    return _threat_scenario_tracker


def clear_threat_scenarios() -> None:
    """Clear all threat scenarios for a new session."""
    _threat_scenario_tracker.clear()


# =============================================================================
# THREAT SCENARIO MARKDOWN EXPORT
# =============================================================================

def generate_threat_scenario_markdown(
    scenario: ThreatScenario,
    view_type: str = "tree"
) -> str:
    """
    Generate a markdown representation of a threat scenario.
    
    Args:
        scenario: The ThreatScenario to render
        view_type: "tree" for hierarchical view, "table" for tabular view
    
    Returns:
        Markdown-formatted string
    """
    lines = []
    
    # Header
    lines.append(f"# Threat Scenario: {scenario.name}")
    lines.append("")
    lines.append(f"**Scenario ID:** `{scenario.scenario_id}`  ")
    lines.append(f"**Source:** {scenario.source_type} - {scenario.source_document}  ")
    lines.append(f"**Created:** {scenario.created_at}  ")
    lines.append("")
    
    # Summary
    lines.append("## Scenario Summary")
    lines.append("")
    lines.append(scenario.description)
    lines.append("")
    lines.append(f"**Threat Actor:** {scenario.threat_actor_profile or 'Not specified'}  ")
    lines.append(f"**Attack Objective:** {scenario.attack_objective or 'Not specified'}  ")
    if scenario.target_assets:
        lines.append(f"**Target Assets:** {', '.join(scenario.target_assets)}  ")
    if scenario.entry_vectors:
        lines.append(f"**Entry Vectors:** {', '.join(scenario.entry_vectors)}  ")
    lines.append("")
    
    # Assumptions
    if scenario.assumptions:
        lines.append("### Assumptions")
        for assumption in scenario.assumptions:
            lines.append(f"- {assumption}")
        lines.append("")
    
    # Security Controls
    lines.append("## Security Controls")
    lines.append("")
    lines.append("Controls that must be bypassed or evaded for attack success:")
    lines.append("")
    
    if view_type == "table":
        lines.extend(_render_controls_table(scenario))
    else:
        lines.extend(_render_controls_tree(scenario))
    
    # Attack Sequence
    lines.append("## Attack Sequence")
    lines.append("")
    lines.append("Events that must be accomplished for a successful attack:")
    lines.append("")
    
    if view_type == "table":
        lines.extend(_render_sequence_table(scenario))
    else:
        lines.extend(_render_sequence_tree(scenario))
    
    # Control-Event Matrix
    lines.append("## Control Coverage Matrix")
    lines.append("")
    lines.extend(_render_control_matrix(scenario))
    
    # Gap Analysis
    lines.append("## Gap Analysis")
    lines.append("")
    lines.extend(_render_gap_analysis(scenario))
    
    # Defense Coverage Summary
    lines.append("## Defense-in-Depth Coverage")
    lines.append("")
    lines.extend(_render_defense_coverage(scenario))
    
    # Footer
    lines.append("---")
    lines.append(f"*Generated from {scenario.source_type}. Review and validate with security team.*")
    
    return "\n".join(lines)


def _render_controls_table(scenario: ThreatScenario) -> List[str]:
    """Render controls as a table."""
    lines = []
    lines.append("| ID | Control | Type | Status | Bypass Difficulty | Detection |")
    lines.append("|-----|---------|------|--------|-------------------|-----------|")
    
    for control in scenario.security_controls:
        status_icon = {"implemented": "✅", "partial": "⚠️", "planned": "📋", "missing": "❌"}.get(control.implementation_status, "❓")
        lines.append(f"| `{control.control_id}` | {control.name} | {control.control_type.value} | {status_icon} {control.implementation_status} | {control.bypass_difficulty} | {control.detection_capability} |")
    
    lines.append("")
    return lines


def _render_controls_tree(scenario: ThreatScenario) -> List[str]:
    """Render controls grouped by defense layer."""
    lines = []
    
    for layer in DefenseLayerType:
        controls = scenario.get_controls_by_type(layer)
        if controls:
            lines.append(f"### {layer.value.upper()} Layer")
            lines.append("")
            for control in controls:
                status_icon = {"implemented": "✅", "partial": "⚠️", "planned": "📋", "missing": "❌"}.get(control.implementation_status, "❓")
                diff_icon = {"trivial": "🟢", "low": "🟡", "medium": "🟠", "high": "🔴", "very_high": "⛔"}.get(control.bypass_difficulty, "❓")
                
                lines.append(f"- **{control.name}** (`{control.control_id}`)")
                lines.append(f"  - Status: {status_icon} {control.implementation_status}")
                lines.append(f"  - Bypass Difficulty: {diff_icon} {control.bypass_difficulty}")
                lines.append(f"  - Detection: {control.detection_capability}")
                if control.bypass_requirements:
                    lines.append(f"  - Bypass Requirements: {', '.join(control.bypass_requirements)}")
                lines.append("")
    
    return lines


def _render_sequence_table(scenario: ThreatScenario) -> List[str]:
    """Render attack sequence as a table."""
    lines = []
    lines.append("| # | Event | Technique | Target | Blocking Controls | Detecting Controls |")
    lines.append("|---|-------|-----------|--------|-------------------|-------------------|")
    
    for event in scenario.attack_sequence:
        technique = f"{event.attack_technique} ({event.technique_id})" if event.technique_id else event.attack_technique or "N/A"
        blocking = ", ".join(event.blocking_controls) or "None"
        detecting = ", ".join(event.detecting_controls) or "None"
        lines.append(f"| {event.sequence_order} | {event.name} | {technique} | {event.target_asset} | {blocking} | {detecting} |")
    
    lines.append("")
    return lines


def _render_sequence_tree(scenario: ThreatScenario) -> List[str]:
    """Render attack sequence as a tree."""
    lines = []
    
    for i, event in enumerate(scenario.attack_sequence):
        is_last = i == len(scenario.attack_sequence) - 1
        prefix = "└──" if is_last else "├──"
        child_prefix = "    " if is_last else "│   "
        
        # Check if this event has blocking controls
        has_blocking = len(event.blocking_controls) > 0
        has_detecting = len(event.detecting_controls) > 0
        
        if not has_blocking and not has_detecting:
            status = "⚠️ UNPROTECTED"
        elif not has_blocking:
            status = "🟡 DETECT ONLY"
        else:
            status = "🛡️ PROTECTED"
        
        lines.append(f"{prefix} **Step {event.sequence_order}: {event.name}** {status}")
        lines.append(f"{child_prefix}*{event.description}*")
        
        if event.technique_id:
            lines.append(f"{child_prefix}Technique: {event.attack_technique} (`{event.technique_id}`)")
        
        lines.append(f"{child_prefix}Target: {event.target_asset}")
        lines.append(f"{child_prefix}Access: {event.required_access} → {event.resulting_access}")
        
        if event.blocking_controls:
            lines.append(f"{child_prefix}")
            lines.append(f"{child_prefix}**Blocking Controls:** {', '.join(event.blocking_controls)}")
        
        if event.detecting_controls:
            lines.append(f"{child_prefix}**Detecting Controls:** {', '.join(event.detecting_controls)}")
        
        if event.success_indicators:
            lines.append(f"{child_prefix}Success Indicators: {', '.join(event.success_indicators[:3])}")
        
        lines.append("")
    
    return lines


def _render_control_matrix(scenario: ThreatScenario) -> List[str]:
    """Render a matrix of controls vs events."""
    lines = []
    
    if not scenario.attack_sequence or not scenario.security_controls:
        lines.append("*No data available for matrix.*")
        lines.append("")
        return lines
    
    # Header row
    header = "| Control |"
    separator = "|---------|"
    for event in scenario.attack_sequence:
        header += f" E{event.sequence_order} |"
        separator += "------|"
    
    lines.append(header)
    lines.append(separator)
    
    # Control rows
    for control in scenario.security_controls:
        row = f"| {control.name} |"
        for event in scenario.attack_sequence:
            if control.control_id in event.blocking_controls:
                row += " 🛡️ |"
            elif control.control_id in event.detecting_controls:
                row += " 👁️ |"
            else:
                row += " - |"
        lines.append(row)
    
    lines.append("")
    lines.append("*Legend: 🛡️ = Blocks, 👁️ = Detects, - = No coverage*")
    lines.append("")
    return lines


def _render_gap_analysis(scenario: ThreatScenario) -> List[str]:
    """Render gap analysis section."""
    lines = []
    
    # Find unprotected events
    unprotected = [e for e in scenario.attack_sequence if not e.blocking_controls]
    detect_only = [e for e in scenario.attack_sequence if e.detecting_controls and not e.blocking_controls]
    
    # Find weak controls
    weak_controls = [c for c in scenario.security_controls if c.implementation_status in ("partial", "planned", "missing")]
    easy_bypass = [c for c in scenario.security_controls if c.bypass_difficulty in ("trivial", "low")]
    
    if unprotected:
        lines.append("### ⚠️ Unprotected Attack Steps")
        lines.append("")
        lines.append("These steps have NO blocking controls:")
        for event in unprotected:
            lines.append(f"- **Step {event.sequence_order}: {event.name}**")
        lines.append("")
    
    if detect_only:
        lines.append("### 🟡 Detection-Only Steps")
        lines.append("")
        lines.append("These steps can be detected but not blocked:")
        for event in detect_only:
            lines.append(f"- **Step {event.sequence_order}: {event.name}** - Detected by: {', '.join(event.detecting_controls)}")
        lines.append("")
    
    if weak_controls:
        lines.append("### 📋 Incomplete Controls")
        lines.append("")
        for control in weak_controls:
            lines.append(f"- **{control.name}** - Status: {control.implementation_status}")
        lines.append("")
    
    if easy_bypass:
        lines.append("### 🔓 Easy-to-Bypass Controls")
        lines.append("")
        for control in easy_bypass:
            lines.append(f"- **{control.name}** - Bypass difficulty: {control.bypass_difficulty}")
            if control.bypass_requirements:
                lines.append(f"  - Requirements: {', '.join(control.bypass_requirements)}")
        lines.append("")
    
    # Weakest point
    weakest = scenario.get_weakest_point()
    if weakest:
        lines.append("### 🎯 Weakest Point in Attack Chain")
        lines.append("")
        lines.append(f"**Step {weakest.sequence_order}: {weakest.name}** has the least protection.")
        lines.append(f"- Blocking controls: {len(weakest.blocking_controls)}")
        lines.append(f"- Detecting controls: {len(weakest.detecting_controls)}")
        lines.append("")
    
    if not unprotected and not weak_controls and not easy_bypass:
        lines.append("✅ No critical gaps identified. All attack steps have blocking controls.")
        lines.append("")
    
    return lines


def _render_defense_coverage(scenario: ThreatScenario) -> List[str]:
    """Render defense-in-depth coverage summary."""
    lines = []
    coverage = scenario.get_defense_coverage()
    
    lines.append("| Layer | Controls | Implemented | Partial | Planned | Missing |")
    lines.append("|-------|----------|-------------|---------|---------|---------|")
    
    for layer, data in coverage.items():
        status = data["implementation_status"]
        lines.append(f"| {layer.upper()} | {data['control_count']} | {status['implemented']} | {status['partial']} | {status['planned']} | {status['missing']} |")
    
    lines.append("")
    return lines


def export_threat_scenario_to_file(
    scenario: ThreatScenario,
    output_path: str,
    view_type: str = "tree"
) -> str:
    """
    Export a threat scenario to a markdown file.
    
    Args:
        scenario: The ThreatScenario to export
        output_path: File path for the markdown output
        view_type: "tree" or "table"
    
    Returns:
        The output file path
    """
    markdown = generate_threat_scenario_markdown(scenario, view_type=view_type)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(markdown)
    
    return output_path


def get_threat_model_analysis_prompt(
    source_type: str,
    document_content: str,
    include_history: bool = True
) -> str:
    """Get the formatted threat model analysis prompt."""
    session_context = get_context_for_prompt() if include_history else ""
    return THREAT_MODEL_ANALYSIS_PROMPT.format(
        system_identity=SYSTEM_IDENTITY,
        session_context=session_context,
        source_type=source_type,
        document_content=document_content
    )


def get_tabletop_minutes_prompt(
    exercise_details: str,
    minutes_content: str,
    include_history: bool = True
) -> str:
    """Get the formatted tabletop minutes analysis prompt."""
    session_context = get_context_for_prompt() if include_history else ""
    return TABLETOP_MINUTES_PROMPT.format(
        system_identity=SYSTEM_IDENTITY,
        session_context=session_context,
        exercise_details=exercise_details,
        minutes_content=minutes_content
    )
