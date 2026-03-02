"""
Risk Assessment Analysis Tool - Analyze analyst PDF reports for attack path validation

This tool analyzes internal risk assessment and threat modeling reports to:
- Extract and validate attack path narratives against MITRE ICS attack stages
- Identify missing stages that are relevant to the attack type
- Assess control effectiveness with evidence basis tracking
- Flag independence violations and duplicate controls
- Output in JSON or metasploit-style text format

Context files are loaded from: context/risk_assessment/
- methodology.md - Scoring methodology and workflow
- constraints.md - Safety guardrails and determinism boundary
- role.md - LLM assistant role definition

Stage catalog loaded from: tools/stage_catalog.json
"""

import logging
import os
import json
import re
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from functools import lru_cache

# Import visualization module for storing results
try:
    from tools.visualization import set_last_risk_assessment_result
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False
    def set_last_risk_assessment_result(x): pass

# PDF reading support
try:
    import fitz  # pymupdf
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
    logging.warning("pymupdf not installed. PDF reading disabled.")


# =============================================================================
# CONTEXT LOADING
# =============================================================================

def _get_context_dir() -> Path:
    """Get the path to the risk_assessment context directory."""
    # tools/risk_assessment.py -> context/risk_assessment/
    tools_dir = Path(__file__).parent
    return tools_dir.parent / "context" / "risk_assessment"


def _get_stage_catalog_path() -> Path:
    """Get the path to the stage catalog JSON file."""
    return Path(__file__).parent / "stage_catalog.json"


@lru_cache(maxsize=1)
def load_stage_catalog() -> Dict[str, Any]:
    """
    Load the stage catalog from stage_catalog.json.
    Returns the parsed JSON with stage definitions and MITRE references.
    """
    catalog_path = _get_stage_catalog_path()
    if not catalog_path.exists():
        logging.warning(f"Stage catalog not found: {catalog_path}")
        return {"stages": []}
    
    with open(catalog_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _compress_markdown(content: str) -> str:
    """
    Compress markdown content for LLM context by:
    - Removing excessive whitespace
    - Removing horizontal rules
    - Condensing headers
    - Removing code block formatting (keep content)
    """
    # Remove horizontal rules
    content = re.sub(r'^-{3,}$', '', content, flags=re.MULTILINE)
    content = re.sub(r'^\*{3,}$', '', content, flags=re.MULTILINE)
    
    # Condense multiple blank lines to single
    content = re.sub(r'\n{3,}', '\n\n', content)
    
    # Remove leading/trailing whitespace per line
    lines = [line.strip() for line in content.split('\n')]
    content = '\n'.join(lines)
    
    # Remove empty lines at start/end
    content = content.strip()
    
    return content


@lru_cache(maxsize=3)
def load_context_file(filename: str) -> str:
    """
    Load and compress a context markdown file.
    
    Args:
        filename: Name of the file (e.g., 'methodology.md')
    
    Returns:
        Compressed markdown content
    """
    context_dir = _get_context_dir()
    file_path = context_dir / filename
    
    if not file_path.exists():
        logging.warning(f"Context file not found: {file_path}")
        return ""
    
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    return _compress_markdown(content)


def build_compressed_context() -> str:
    """
    Build a compressed context string from all context files.
    This provides the LLM with methodology, constraints, and role information
    while minimizing token usage.
    """
    sections = []
    
    # Load role (most important for LLM behavior)
    role = load_context_file("role.md")
    if role:
        sections.append(f"=== ROLE ===\n{role}")
    
    # Load constraints (safety guardrails)
    constraints = load_context_file("constraints.md")
    if constraints:
        sections.append(f"=== CONSTRAINTS ===\n{constraints}")
    
    # Load methodology (scoring and workflow) - extract key sections only
    methodology = load_context_file("methodology.md")
    if methodology:
        # Extract only the most critical sections for context
        key_sections = []
        
        # Extract scoring formula
        if "CompositeScore" in methodology:
            match = re.search(r'CompositeScore.*?0\.38\)', methodology, re.DOTALL)
            if match:
                key_sections.append(f"Scoring: {match.group(0)}")
        
        # Extract control state values
        if "State" in methodology and "absent" in methodology:
            key_sections.append("Control States: absent | partial | present | unknown")
            key_sections.append("Scope Values: all | most | some | few | unknown")
        
        if key_sections:
            sections.append(f"=== METHODOLOGY (KEY POINTS) ===\n" + "\n".join(key_sections))
    
    return "\n\n".join(sections)


def get_stage_names_from_catalog() -> List[str]:
    """Get canonical stage names from the stage catalog."""
    catalog = load_stage_catalog()
    return [stage["canonical_name"] for stage in catalog.get("stages", [])]


def get_stage_by_id(stage_id: str) -> Optional[Dict[str, Any]]:
    """Get a stage definition by its ID from the catalog."""
    catalog = load_stage_catalog()
    for stage in catalog.get("stages", []):
        if stage.get("stage_id") == stage_id:
            return stage
    return None


# =============================================================================
# MITRE ICS ATTACK STAGES
# =============================================================================

class AttackStage(Enum):
    """MITRE ICS aligned attack stages."""
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact/Action on Objective"


# Attack type to required/optional stages mapping
# This prevents false "missing stage" flags for attacks that don't need certain stages
ATTACK_TYPE_STAGES = {
    "ddos": {
        "required": [AttackStage.INITIAL_ACCESS, AttackStage.IMPACT],
        "optional": [AttackStage.COMMAND_AND_CONTROL],
        "not_applicable": [
            AttackStage.PERSISTENCE, AttackStage.PRIVILEGE_ESCALATION,
            AttackStage.CREDENTIAL_ACCESS, AttackStage.LATERAL_MOVEMENT,
            AttackStage.COLLECTION, AttackStage.EXFILTRATION
        ]
    },
    "ransomware": {
        "required": [
            AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION,
            AttackStage.PRIVILEGE_ESCALATION, AttackStage.IMPACT
        ],
        "optional": [
            AttackStage.PERSISTENCE, AttackStage.DEFENSE_EVASION,
            AttackStage.CREDENTIAL_ACCESS, AttackStage.DISCOVERY,
            AttackStage.LATERAL_MOVEMENT
        ],
        "not_applicable": [AttackStage.EXFILTRATION]  # Unless double extortion
    },
    "data_theft": {
        "required": [
            AttackStage.INITIAL_ACCESS, AttackStage.COLLECTION,
            AttackStage.EXFILTRATION
        ],
        "optional": [
            AttackStage.EXECUTION, AttackStage.PERSISTENCE,
            AttackStage.PRIVILEGE_ESCALATION, AttackStage.DEFENSE_EVASION,
            AttackStage.CREDENTIAL_ACCESS, AttackStage.DISCOVERY,
            AttackStage.LATERAL_MOVEMENT, AttackStage.COMMAND_AND_CONTROL
        ],
        "not_applicable": []
    },
    "apt": {
        "required": [
            AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION,
            AttackStage.PERSISTENCE, AttackStage.DISCOVERY
        ],
        "optional": [
            AttackStage.PRIVILEGE_ESCALATION, AttackStage.DEFENSE_EVASION,
            AttackStage.CREDENTIAL_ACCESS, AttackStage.LATERAL_MOVEMENT,
            AttackStage.COLLECTION, AttackStage.COMMAND_AND_CONTROL,
            AttackStage.EXFILTRATION, AttackStage.IMPACT
        ],
        "not_applicable": []
    },
    "insider_threat": {
        "required": [AttackStage.COLLECTION, AttackStage.IMPACT],
        "optional": [
            AttackStage.PRIVILEGE_ESCALATION, AttackStage.EXFILTRATION
        ],
        "not_applicable": [
            AttackStage.INITIAL_ACCESS, AttackStage.PERSISTENCE,
            AttackStage.COMMAND_AND_CONTROL
        ]
    },
    "web_attack": {
        "required": [AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION],
        "optional": [
            AttackStage.PRIVILEGE_ESCALATION, AttackStage.COLLECTION,
            AttackStage.IMPACT
        ],
        "not_applicable": [
            AttackStage.PERSISTENCE, AttackStage.LATERAL_MOVEMENT,
            AttackStage.COMMAND_AND_CONTROL
        ]
    },
    "generic": {
        "required": [AttackStage.INITIAL_ACCESS, AttackStage.IMPACT],
        "optional": list(AttackStage),
        "not_applicable": []
    }
}


# =============================================================================
# DATA CLASSES FOR STRUCTURED OUTPUT
# =============================================================================

@dataclass
class ControlAssessment:
    """Assessment of a security control."""
    control_name: str
    control_type: str  # preventive | detective | responsive
    effectiveness_rating: str  # strong | moderate | weak | nominal
    evidence_basis: str  # tested | benchmark | vendor_claim | assumption
    independence_flag: bool = False
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StageAssessment:
    """Assessment of an attack stage."""
    name: str
    technique_claimed: str = ""
    mitre_technique_id: str = ""
    controls: List[ControlAssessment] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    gaps_detected: List[str] = field(default_factory=list)
    stage_present: bool = True
    relevance: str = "required"  # required | optional | not_applicable
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "technique_claimed": self.technique_claimed,
            "mitre_technique_id": self.mitre_technique_id,
            "controls": [c.to_dict() for c in self.controls],
            "assumptions": self.assumptions,
            "gaps_detected": self.gaps_detected,
            "stage_present": self.stage_present,
            "relevance": self.relevance
        }


@dataclass
class RiskAssessmentResult:
    """Complete risk assessment analysis result."""
    metadata: Dict[str, Any] = field(default_factory=dict)
    attack_type: str = "generic"
    attack_narrative: str = ""
    stages: List[StageAssessment] = field(default_factory=list)
    cross_stage_flags: Dict[str, List[str]] = field(default_factory=dict)
    confidence_assessment: Dict[str, float] = field(default_factory=dict)
    missing_required_stages: List[str] = field(default_factory=list)
    analysis_notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata,
            "attack_type": self.attack_type,
            "attack_narrative": self.attack_narrative,
            "stages": [s.to_dict() for s in self.stages],
            "cross_stage_flags": self.cross_stage_flags,
            "confidence_assessment": self.confidence_assessment,
            "missing_required_stages": self.missing_required_stages,
            "analysis_notes": self.analysis_notes
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
    
    def to_metasploit_text(self) -> str:
        """Format output in metasploit-style text."""
        lines = []
        
        # Header
        lines.append("")
        lines.append("=" * 70)
        lines.append("  RISK ASSESSMENT ANALYSIS")
        lines.append("=" * 70)
        lines.append("")
        
        # Metadata
        if self.metadata:
            lines.append("[*] Metadata:")
            for key, value in self.metadata.items():
                lines.append(f"    {key}: {value}")
            lines.append("")
        
        # Attack Type and Narrative
        lines.append(f"[*] Attack Type: {self.attack_type.upper()}")
        if self.attack_narrative:
            lines.append(f"[*] Narrative: {self.attack_narrative[:200]}...")
        lines.append("")
        
        # Stages
        lines.append("[*] Attack Stages Analysis:")
        lines.append("-" * 50)
        
        for stage in self.stages:
            if stage.stage_present:
                status = "[+]"
                color_hint = "PRESENT"
            elif stage.relevance == "not_applicable":
                status = "[-]"
                color_hint = "N/A"
            else:
                status = "[!]"
                color_hint = "MISSING"
            
            lines.append(f"  {status} {stage.name} ({color_hint})")
            
            if stage.technique_claimed:
                lines.append(f"      Technique: {stage.technique_claimed}")
                if stage.mitre_technique_id:
                    lines.append(f"      MITRE ID: {stage.mitre_technique_id}")
            
            if stage.controls:
                lines.append(f"      Controls ({len(stage.controls)}):")
                for ctrl in stage.controls:
                    eff_icon = {"strong": "███", "moderate": "██░", "weak": "█░░", "nominal": "░░░"}.get(ctrl.effectiveness_rating, "???")
                    lines.append(f"        - {ctrl.control_name}")
                    lines.append(f"          Type: {ctrl.control_type} | Effectiveness: {eff_icon} {ctrl.effectiveness_rating}")
                    lines.append(f"          Evidence: {ctrl.evidence_basis}")
                    if ctrl.independence_flag:
                        lines.append(f"          [!] INDEPENDENCE VIOLATION")
            
            if stage.gaps_detected:
                lines.append(f"      [!] Gaps Detected:")
                for gap in stage.gaps_detected:
                    lines.append(f"          - {gap}")
            
            if stage.assumptions:
                lines.append(f"      [?] Assumptions:")
                for assumption in stage.assumptions:
                    lines.append(f"          - {assumption}")
            
            lines.append("")
        
        # Missing Required Stages
        if self.missing_required_stages:
            lines.append("[!] MISSING REQUIRED STAGES:")
            for stage_name in self.missing_required_stages:
                lines.append(f"    - {stage_name}")
            lines.append("")
        
        # Cross-Stage Flags
        if self.cross_stage_flags:
            lines.append("[*] Cross-Stage Analysis:")
            if self.cross_stage_flags.get("independence_violations"):
                lines.append("    [!] Independence Violations:")
                for violation in self.cross_stage_flags["independence_violations"]:
                    lines.append(f"        - {violation}")
            if self.cross_stage_flags.get("duplicate_controls"):
                lines.append("    [!] Duplicate Controls:")
                for dup in self.cross_stage_flags["duplicate_controls"]:
                    lines.append(f"        - {dup}")
            lines.append("")
        
        # Confidence Assessment
        if self.confidence_assessment:
            lines.append("[*] Confidence Assessment:")
            sc = self.confidence_assessment.get("structural_completeness", 0)
            es = self.confidence_assessment.get("evidence_strength", 0)
            ad = self.confidence_assessment.get("assumption_density", 0)
            
            lines.append(f"    Structural Completeness: {sc:.1%} {'█' * int(sc * 10)}{'░' * (10 - int(sc * 10))}")
            lines.append(f"    Evidence Strength:       {es:.1%} {'█' * int(es * 10)}{'░' * (10 - int(es * 10))}")
            lines.append(f"    Assumption Density:      {ad:.1%} {'█' * int(ad * 10)}{'░' * (10 - int(ad * 10))} (lower is better)")
            lines.append("")
        
        # Analysis Notes
        if self.analysis_notes:
            lines.append("[*] Analysis Notes:")
            for note in self.analysis_notes:
                lines.append(f"    - {note}")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)


# =============================================================================
# PROMPT FOR LLM ANALYSIS
# =============================================================================

def build_risk_assessment_prompt(
    attack_type: str,
    required_stages: str,
    optional_stages: str,
    not_applicable_stages: str,
    document_content: str,
    output_schema: str,
    include_context: bool = True
) -> str:
    """
    Build the risk assessment analysis prompt with compressed context.
    
    Args:
        attack_type: Type of attack being analyzed
        required_stages: Comma-separated required stages
        optional_stages: Comma-separated optional stages
        not_applicable_stages: Comma-separated N/A stages
        document_content: Extracted document text
        output_schema: JSON schema for output
        include_context: Whether to include compressed context from markdown files
    
    Returns:
        Complete prompt string
    """
    sections = []
    
    # Include compressed context if available
    if include_context:
        compressed_context = build_compressed_context()
        if compressed_context:
            sections.append(compressed_context)
    
    # Core prompt
    core_prompt = f"""You are a security analyst reviewing an internal risk assessment report.
Your task is to extract and validate the attack path narrative against MITRE ICS attack stages.

CRITICAL INSTRUCTIONS:
1. DO NOT invent attack stages that are not described in the document
2. DO NOT flag stages as "missing" if they are not relevant to the attack type
3. Only extract information that is explicitly stated or clearly implied in the document
4. Be conservative - if unsure whether a stage is covered, mark it as an assumption

ATTACK TYPE CONTEXT:
The attack type is: {attack_type}
For this attack type:
- Required stages: {required_stages}
- Optional stages: {optional_stages}
- Not applicable stages: {not_applicable_stages}

DOCUMENT CONTENT:
{document_content}

ANALYSIS TASKS:

1. EXTRACT METADATA:
   - Analyst name (if mentioned)
   - Report date
   - Adversary intent classification (opportunistic | targeted | strategic)

2. FOR EACH ATTACK STAGE, EXTRACT:
   - Whether the stage is present in the attack narrative
   - The specific technique claimed (if any)
   - MITRE ATT&CK technique ID (if mentioned or clearly identifiable)
   - Security controls mentioned for this stage:
     * Control name
     * Control type (preventive | detective | responsive)
     * Effectiveness rating (strong | moderate | weak | nominal)
     * Evidence basis (tested | benchmark | vendor_claim | assumption)
     * Independence flag (true if control depends on another control in the path)
   - Any assumptions made about this stage
   - Any gaps detected in coverage

3. CROSS-STAGE ANALYSIS:
   - Identify controls that appear in multiple stages (potential single point of failure)
   - Identify independence violations (controls that depend on each other)

4. CONFIDENCE ASSESSMENT:
   - Structural completeness: What percentage of required stages are covered? (0.0-1.0)
   - Evidence strength: What percentage of controls have tested/benchmark evidence? (0.0-1.0)
   - Assumption density: What percentage of the analysis relies on assumptions? (0.0-1.0)

RESPOND WITH VALID JSON ONLY - no markdown, no explanation, just the JSON object:
{output_schema}
"""
    sections.append(core_prompt)
    
    return "\n\n".join(sections)


# =============================================================================
# PDF EXTRACTION
# =============================================================================

def extract_text_from_pdf(pdf_path: str) -> str:
    """Extract text content from a PDF file."""
    if not PDF_SUPPORT:
        raise ImportError("pymupdf not installed. Install with: pip install pymupdf")
    
    text_parts = []
    with fitz.open(pdf_path) as doc:
        for page_num, page in enumerate(doc, 1):
            text = page.get_text()
            if text.strip():
                text_parts.append(f"--- Page {page_num} ---\n{text}")
    
    return "\n\n".join(text_parts)


def extract_text_from_pdf_bytes(pdf_bytes: bytes, filename: str = "document.pdf") -> str:
    """Extract text content from PDF bytes."""
    if not PDF_SUPPORT:
        raise ImportError("pymupdf not installed. Install with: pip install pymupdf")
    
    text_parts = []
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        for page_num, page in enumerate(doc, 1):
            text = page.get_text()
            if text.strip():
                text_parts.append(f"--- Page {page_num} ---\n{text}")
    
    return "\n\n".join(text_parts)


# =============================================================================
# TOOL REGISTRATION
# =============================================================================

def register_risk_assessment_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register risk assessment analysis tools with the MCP server."""
    
    _storage_client = storage_client
    _gemini_client = gemini_client
    _get_bucket = get_bucket_func

    @mcp.tool()
    def analyze_risk_assessment_pdf(
        file_path: str,
        attack_type: str = "generic",
        output_format: str = "text",
        from_gcs: bool = False,
        bucket_name: str = ""
    ) -> str:
        """
        Analyzes an analyst's risk assessment PDF report to validate attack path narratives
        against MITRE ICS attack stages.
        
        Extracts:
        - Attack stages present in the narrative
        - Security controls and their effectiveness
        - Gaps and missing stages (only those relevant to the attack type)
        - Confidence assessment of the analysis
        
        Args:
            file_path: Path to the PDF file (local or GCS blob path)
            attack_type: Type of attack (ddos, ransomware, data_theft, apt, insider_threat, web_attack, generic)
            output_format: Output format - 'text' for metasploit-style or 'json' for structured JSON
            from_gcs: If True, load from GCS bucket
            bucket_name: GCS bucket name (uses default if not specified)
        
        Returns:
            Analysis results in the specified format
        """
        if not PDF_SUPPORT:
            return "Error: PDF support not available. Install pymupdf: pip install pymupdf"
        
        if not _gemini_client:
            return "Error: GEMINI_API_KEY not set. AI analysis features are disabled."
        
        # Validate attack type
        attack_type = attack_type.lower().replace(" ", "_").replace("-", "_")
        if attack_type not in ATTACK_TYPE_STAGES:
            valid_types = ", ".join(ATTACK_TYPE_STAGES.keys())
            return f"Error: Invalid attack type '{attack_type}'. Valid types: {valid_types}"
        
        try:
            doc_name = os.path.basename(file_path)
            
            # Extract PDF content
            if from_gcs:
                target_bucket = _get_bucket(bucket_name)
                if not target_bucket:
                    return "Error: No bucket specified and GCS_LOG_BUCKET not set."
                if not _storage_client:
                    return "Error: GCS Client not initialized."
                
                bucket = _storage_client.bucket(target_bucket)
                blob = bucket.blob(file_path)
                pdf_bytes = blob.download_as_bytes()
                document_content = extract_text_from_pdf_bytes(pdf_bytes, doc_name)
                source_ref = f"gcs://{target_bucket}/{file_path}"
            else:
                if not os.path.exists(file_path):
                    return f"Error: File not found: {file_path}"
                document_content = extract_text_from_pdf(file_path)
                source_ref = f"file://{file_path}"
            
            if not document_content.strip():
                return f"Error: No text content could be extracted from {file_path}"
            
            # Get stage requirements for this attack type
            stage_config = ATTACK_TYPE_STAGES[attack_type]
            required_stages = [s.value for s in stage_config["required"]]
            optional_stages = [s.value for s in stage_config["optional"] if s not in stage_config["required"]]
            not_applicable_stages = [s.value for s in stage_config["not_applicable"]]
            
            # Build output schema example
            output_schema = json.dumps({
                "metadata": {
                    "analyst_name": "",
                    "report_date": "",
                    "adversary_intent": "opportunistic | targeted | strategic"
                },
                "attack_narrative": "Brief summary of the attack path described",
                "stages": [
                    {
                        "name": "Stage Name",
                        "technique_claimed": "Technique described in document",
                        "mitre_technique_id": "T1234 if identifiable",
                        "controls": [
                            {
                                "control_name": "",
                                "control_type": "preventive | detective | responsive",
                                "effectiveness_rating": "strong | moderate | weak | nominal",
                                "evidence_basis": "tested | benchmark | vendor_claim | assumption",
                                "independence_flag": False,
                                "notes": ""
                            }
                        ],
                        "assumptions": [],
                        "gaps_detected": [],
                        "stage_present": True,
                        "relevance": "required | optional | not_applicable"
                    }
                ],
                "cross_stage_flags": {
                    "independence_violations": [],
                    "duplicate_controls": []
                },
                "confidence_assessment": {
                    "structural_completeness": 0.0,
                    "evidence_strength": 0.0,
                    "assumption_density": 0.0
                },
                "analysis_notes": []
            }, indent=2)
            
            # Build prompt with compressed context
            prompt = build_risk_assessment_prompt(
                attack_type=attack_type,
                required_stages=", ".join(required_stages),
                optional_stages=", ".join(optional_stages) if optional_stages else "None",
                not_applicable_stages=", ".join(not_applicable_stages) if not_applicable_stages else "None",
                document_content=document_content[:50000],  # Limit content size
                output_schema=output_schema,
                include_context=True
            )
            
            # Call Gemini
            response = _gemini_client.models.generate_content(
                model='gemini-2.5-pro',
                contents=prompt
            )
            
            # Parse response
            response_text = response.text.strip()
            
            # Clean up response - remove markdown code blocks if present
            if response_text.startswith("```"):
                lines = response_text.split("\n")
                # Remove first line (```json) and last line (```)
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                response_text = "\n".join(lines)
            
            try:
                result_data = json.loads(response_text)
            except json.JSONDecodeError as e:
                return f"Error parsing LLM response as JSON: {e}\n\nRaw response:\n{response_text[:1000]}"
            
            # Build result object
            result = RiskAssessmentResult(
                metadata=result_data.get("metadata", {}),
                attack_type=attack_type,
                attack_narrative=result_data.get("attack_narrative", ""),
                cross_stage_flags=result_data.get("cross_stage_flags", {}),
                confidence_assessment=result_data.get("confidence_assessment", {}),
                analysis_notes=result_data.get("analysis_notes", [])
            )
            
            # Process stages
            for stage_data in result_data.get("stages", []):
                controls = []
                for ctrl_data in stage_data.get("controls", []):
                    controls.append(ControlAssessment(
                        control_name=ctrl_data.get("control_name", ""),
                        control_type=ctrl_data.get("control_type", ""),
                        effectiveness_rating=ctrl_data.get("effectiveness_rating", ""),
                        evidence_basis=ctrl_data.get("evidence_basis", ""),
                        independence_flag=ctrl_data.get("independence_flag", False),
                        notes=ctrl_data.get("notes", "")
                    ))
                
                stage = StageAssessment(
                    name=stage_data.get("name", ""),
                    technique_claimed=stage_data.get("technique_claimed", ""),
                    mitre_technique_id=stage_data.get("mitre_technique_id", ""),
                    controls=controls,
                    assumptions=stage_data.get("assumptions", []),
                    gaps_detected=stage_data.get("gaps_detected", []),
                    stage_present=stage_data.get("stage_present", True),
                    relevance=stage_data.get("relevance", "optional")
                )
                result.stages.append(stage)
            
            # Identify missing required stages
            present_stage_names = {s.name for s in result.stages if s.stage_present}
            for required_stage in required_stages:
                if required_stage not in present_stage_names:
                    result.missing_required_stages.append(required_stage)
            
            # Add source info to metadata
            result.metadata["source_file"] = source_ref
            result.metadata["analysis_timestamp"] = datetime.now().isoformat()
            
            # Store result for visualization
            set_last_risk_assessment_result(result.to_dict())
            
            # Return in requested format
            if output_format.lower() == "json":
                return result.to_json()
            else:
                return result.to_metasploit_text()
            
        except Exception as e:
            logging.error(f"Error analyzing risk assessment PDF: {e}")
            return f"Error analyzing risk assessment PDF: {str(e)}"

    @mcp.tool()
    def list_attack_types() -> str:
        """
        Lists available attack types and their required/optional stages.
        Use this to understand which stages are relevant for different attack scenarios.
        
        Returns:
            Formatted list of attack types and their stage requirements
        """
        lines = []
        lines.append("=" * 60)
        lines.append("ATTACK TYPES AND STAGE REQUIREMENTS")
        lines.append("=" * 60)
        lines.append("")
        
        for attack_type, config in ATTACK_TYPE_STAGES.items():
            lines.append(f"[*] {attack_type.upper()}")
            lines.append(f"    Required stages:")
            for stage in config["required"]:
                lines.append(f"      - {stage.value}")
            
            optional = [s for s in config["optional"] if s not in config["required"]]
            if optional:
                lines.append(f"    Optional stages:")
                for stage in optional:
                    lines.append(f"      - {stage.value}")
            
            if config["not_applicable"]:
                lines.append(f"    Not applicable:")
                for stage in config["not_applicable"]:
                    lines.append(f"      - {stage.value}")
            
            lines.append("")
        
        return "\n".join(lines)

    @mcp.tool()
    def show_risk_assessment_context() -> str:
        """
        Shows the loaded context files used for risk assessment analysis.
        Useful for debugging and understanding what context is provided to the LLM.
        
        Returns:
            Summary of loaded context files and stage catalog
        """
        lines = []
        lines.append("=" * 60)
        lines.append("RISK ASSESSMENT CONTEXT")
        lines.append("=" * 60)
        lines.append("")
        
        # Context directory
        context_dir = _get_context_dir()
        lines.append(f"[*] Context Directory: {context_dir}")
        lines.append(f"    Exists: {context_dir.exists()}")
        lines.append("")
        
        # Context files
        context_files = ["role.md", "constraints.md", "methodology.md"]
        lines.append("[*] Context Files:")
        for filename in context_files:
            filepath = context_dir / filename
            if filepath.exists():
                size = filepath.stat().st_size
                content = load_context_file(filename)
                compressed_size = len(content)
                lines.append(f"    [+] {filename}")
                lines.append(f"        Original: {size:,} bytes")
                lines.append(f"        Compressed: {compressed_size:,} chars")
            else:
                lines.append(f"    [-] {filename} (NOT FOUND)")
        lines.append("")
        
        # Stage catalog
        catalog_path = _get_stage_catalog_path()
        lines.append(f"[*] Stage Catalog: {catalog_path}")
        lines.append(f"    Exists: {catalog_path.exists()}")
        
        catalog = load_stage_catalog()
        if catalog.get("stages"):
            lines.append(f"    Stages: {len(catalog['stages'])}")
            lines.append(f"    Version: {catalog.get('schema_version', 'unknown')}")
            lines.append("")
            lines.append("[*] Stage Catalog Contents:")
            for stage in catalog["stages"]:
                mitre_id = stage.get("mitre", {}).get("enterprise_tactic_id", "N/A")
                lines.append(f"    - {stage['canonical_name']} ({mitre_id})")
        lines.append("")
        
        # Compressed context preview
        compressed = build_compressed_context()
        lines.append(f"[*] Compressed Context Size: {len(compressed):,} chars")
        lines.append("")
        
        return "\n".join(lines)
