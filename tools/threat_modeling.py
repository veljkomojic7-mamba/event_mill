"""
Threat Modeling Tools - Attack path analysis from threat models and tabletop exercises

Tools:
- load_threat_intel_pdf: Load a threat intel PDF report as context for analysis
- load_threat_intel_text: Load threat intel text content as context
- list_threat_intel_context: List loaded threat intel context
- clear_threat_intel_context: Clear loaded threat intel context
- analyze_threat_model: Parse threat model documents to extract attack paths and controls
- analyze_tabletop_minutes: Parse tabletop exercise minutes for scenario analysis
- create_threat_scenario: Create a new threat scenario for tracking
- add_security_control: Add a security control to a scenario
- add_attack_event: Add an attack sequence event to a scenario
- list_threat_scenarios: List all tracked threat scenarios
- export_threat_scenario: Export a scenario to markdown
- get_scenario_gaps: Analyze gaps in a threat scenario's defenses
"""

import logging
import os
import io
from typing import Optional, List, Dict
from datetime import datetime

# PDF reading support
try:
    import fitz  # pymupdf
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
    logging.warning("pymupdf not installed. PDF reading disabled. Install with: pip install pymupdf")

from system_context import (
    ThreatScenario,
    SecurityControl,
    AttackSequenceEvent,
    DefenseLayerType,
    ThreatScenarioTracker,
    get_threat_scenario_tracker,
    get_threat_model_analysis_prompt,
    get_tabletop_minutes_prompt,
    generate_threat_scenario_markdown,
    export_threat_scenario_to_file,
)


# =============================================================================
# THREAT INTEL CONTEXT STORE
# =============================================================================

class ThreatIntelContext:
    """
    Stores threat intelligence context loaded from PDFs and text documents.
    This context is injected into threat model analysis prompts.
    """
    
    def __init__(self, max_context_chars: int = 100000):
        self._documents: Dict[str, Dict] = {}  # doc_id -> {name, content, source, loaded_at}
        self._max_context_chars = max_context_chars
    
    def add_document(self, name: str, content: str, source: str = "manual") -> str:
        """Add a document to the context store. Returns document ID."""
        doc_id = f"TI-{len(self._documents) + 1:04d}"
        
        # Truncate if too long
        if len(content) > self._max_context_chars:
            content = content[:self._max_context_chars] + "\n\n[TRUNCATED - Document exceeded max context length]"
        
        self._documents[doc_id] = {
            "name": name,
            "content": content,
            "source": source,
            "loaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "char_count": len(content)
        }
        return doc_id
    
    def get_document(self, doc_id: str) -> Optional[Dict]:
        """Get a specific document by ID."""
        return self._documents.get(doc_id)
    
    def get_all_documents(self) -> Dict[str, Dict]:
        """Get all loaded documents."""
        return self._documents.copy()
    
    def get_combined_context(self, max_chars: Optional[int] = None) -> str:
        """Get combined context from all loaded documents."""
        if not self._documents:
            return ""
        
        sections = []
        total_chars = 0
        limit = max_chars or self._max_context_chars
        
        for doc_id, doc in self._documents.items():
            header = f"\n{'='*60}\nTHREAT INTEL: {doc['name']} ({doc_id})\nSource: {doc['source']}\n{'='*60}\n"
            section = header + doc["content"]
            
            if total_chars + len(section) > limit:
                remaining = limit - total_chars
                if remaining > 500:  # Only add if we can include meaningful content
                    sections.append(section[:remaining] + "\n[TRUNCATED]")
                break
            
            sections.append(section)
            total_chars += len(section)
        
        return "\n".join(sections)
    
    def remove_document(self, doc_id: str) -> bool:
        """Remove a document from the context store."""
        if doc_id in self._documents:
            del self._documents[doc_id]
            return True
        return False
    
    def clear(self) -> None:
        """Clear all loaded documents."""
        self._documents.clear()
    
    def get_summary(self) -> str:
        """Get a summary of loaded documents."""
        if not self._documents:
            return "No threat intel context loaded."
        
        lines = [f"Loaded {len(self._documents)} threat intel document(s):"]
        total_chars = 0
        for doc_id, doc in self._documents.items():
            lines.append(f"  - {doc_id}: {doc['name']} ({doc['char_count']:,} chars) - {doc['source']}")
            total_chars += doc['char_count']
        lines.append(f"Total context: {total_chars:,} characters")
        return "\n".join(lines)


# Global threat intel context store
_threat_intel_context = ThreatIntelContext()


def get_threat_intel_context() -> ThreatIntelContext:
    """Get the global threat intel context store."""
    return _threat_intel_context


def extract_text_from_pdf(pdf_path: str) -> str:
    """
    Extract text content from a PDF file using pymupdf.
    
    Args:
        pdf_path: Path to the PDF file
    
    Returns:
        Extracted text content
    """
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
    """
    Extract text content from PDF bytes (e.g., from GCS).
    
    Args:
        pdf_bytes: Raw PDF file bytes
        filename: Name for reference
    
    Returns:
        Extracted text content
    """
    if not PDF_SUPPORT:
        raise ImportError("pymupdf not installed. Install with: pip install pymupdf")
    
    text_parts = []
    
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        for page_num, page in enumerate(doc, 1):
            text = page.get_text()
            if text.strip():
                text_parts.append(f"--- Page {page_num} ---\n{text}")
    
    return "\n\n".join(text_parts)


def register_threat_modeling_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register threat modeling tools with the MCP server."""
    
    _storage_client = storage_client
    _gemini_client = gemini_client
    _get_bucket = get_bucket_func
    _tracker = get_threat_scenario_tracker()
    _threat_intel = get_threat_intel_context()

    # =========================================================================
    # THREAT INTEL CONTEXT TOOLS
    # =========================================================================

    @mcp.tool()
    def load_threat_intel_pdf(
        file_path: str,
        document_name: str = "",
        from_gcs: bool = False,
        bucket_name: str = ""
    ) -> str:
        """
        Loads a threat intelligence PDF report as context for subsequent threat model analysis.
        The extracted text will be included as background context when analyzing threat models.
        
        Args:
            file_path: Path to the PDF file (local path or GCS blob path if from_gcs=True)
            document_name: Optional name for the document (defaults to filename)
            from_gcs: If True, load from GCS bucket instead of local filesystem
            bucket_name: GCS bucket name (required if from_gcs=True)
        
        Returns:
            Confirmation with document ID and extracted content summary
        """
        if not PDF_SUPPORT:
            return "Error: PDF support not available. Install pymupdf: pip install pymupdf"
        
        try:
            name = document_name or os.path.basename(file_path)
            
            if from_gcs:
                # Load from GCS
                target_bucket = _get_bucket(bucket_name)
                if not target_bucket:
                    return "Error: No bucket specified and GCS_LOG_BUCKET not set."
                if not _storage_client:
                    return "Error: GCS Client not initialized."
                
                bucket = _storage_client.bucket(target_bucket)
                blob = bucket.blob(file_path)
                pdf_bytes = blob.download_as_bytes()
                content = extract_text_from_pdf_bytes(pdf_bytes, name)
                source = f"gcs://{target_bucket}/{file_path}"
            else:
                # Load from local filesystem
                if not os.path.exists(file_path):
                    return f"Error: File not found: {file_path}"
                content = extract_text_from_pdf(file_path)
                source = f"file://{file_path}"
            
            if not content.strip():
                return f"Error: No text content could be extracted from {file_path}"
            
            doc_id = _threat_intel.add_document(name, content, source)
            
            # Count pages (approximate from markers)
            page_count = content.count("--- Page ")
            
            output = []
            output.append("✅ Threat Intel PDF Loaded")
            output.append("")
            output.append(f"**Document ID:** `{doc_id}`")
            output.append(f"**Name:** {name}")
            output.append(f"**Source:** {source}")
            output.append(f"**Pages:** ~{page_count}")
            output.append(f"**Characters:** {len(content):,}")
            output.append("")
            output.append("This context will be included in subsequent threat model analysis.")
            output.append("")
            output.append(_threat_intel.get_summary())
            
            return "\n".join(output)
            
        except Exception as e:
            logging.error(f"Error loading threat intel PDF: {e}")
            return f"Error loading threat intel PDF: {str(e)}"

    @mcp.tool()
    def load_threat_intel_text(
        content: str,
        document_name: str,
        source: str = "manual_input"
    ) -> str:
        """
        Loads threat intelligence text content as context for subsequent threat model analysis.
        Use this for pasting threat intel reports, advisories, or other text content.
        
        Args:
            content: The text content to load as context
            document_name: Name for the document
            source: Source reference (e.g., 'CISA Advisory', 'Mandiant Report')
        
        Returns:
            Confirmation with document ID
        """
        try:
            if not content.strip():
                return "Error: No content provided."
            
            doc_id = _threat_intel.add_document(document_name, content, source)
            
            output = []
            output.append("✅ Threat Intel Text Loaded")
            output.append("")
            output.append(f"**Document ID:** `{doc_id}`")
            output.append(f"**Name:** {document_name}")
            output.append(f"**Source:** {source}")
            output.append(f"**Characters:** {len(content):,}")
            output.append("")
            output.append("This context will be included in subsequent threat model analysis.")
            output.append("")
            output.append(_threat_intel.get_summary())
            
            return "\n".join(output)
            
        except Exception as e:
            logging.error(f"Error loading threat intel text: {e}")
            return f"Error loading threat intel text: {str(e)}"

    @mcp.tool()
    def list_threat_intel_context() -> str:
        """
        Lists all loaded threat intelligence context documents.
        
        Returns:
            Summary of all loaded threat intel documents
        """
        summary = _threat_intel.get_summary()
        
        if not _threat_intel._documents:
            return summary + "\n\nUse 'load_threat_intel_pdf' or 'load_threat_intel_text' to add context."
        
        output = []
        output.append("=" * 60)
        output.append("📚 THREAT INTEL CONTEXT")
        output.append("=" * 60)
        output.append("")
        output.append(summary)
        output.append("")
        output.append("Commands:")
        output.append("  - Add PDF: load_threat_intel_pdf(file_path='...')")
        output.append("  - Add text: load_threat_intel_text(content='...', document_name='...')")
        output.append("  - Clear all: clear_threat_intel_context()")
        
        return "\n".join(output)

    @mcp.tool()
    def clear_threat_intel_context(document_id: str = "") -> str:
        """
        Clears loaded threat intelligence context.
        
        Args:
            document_id: Optional specific document ID to remove. If empty, clears all.
        
        Returns:
            Confirmation of cleared context
        """
        if document_id:
            if _threat_intel.remove_document(document_id):
                return f"✅ Removed threat intel document: {document_id}\n\n{_threat_intel.get_summary()}"
            else:
                return f"Error: Document '{document_id}' not found."
        else:
            _threat_intel.clear()
            return "✅ Cleared all threat intel context."

    # =========================================================================
    # THREAT MODEL ANALYSIS TOOLS
    # =========================================================================

    @mcp.tool()
    def analyze_threat_model_pdf(
        file_path: str,
        source_type: str = "threat_model",
        from_gcs: bool = False,
        bucket_name: str = ""
    ) -> str:
        """
        Analyzes a threat modeling PDF document to extract attack paths and controls.
        Reads the PDF file directly and performs AI analysis.
        
        Args:
            file_path: Path to the PDF file (local path or GCS blob path if from_gcs=True)
            source_type: Type of document ('threat_model', 'security_assessment', 'red_team_report')
            from_gcs: If True, load from GCS bucket instead of local filesystem
            bucket_name: GCS bucket name (required if from_gcs=True, or uses default)
        
        Returns:
            Structured analysis of attack paths, controls, and gaps
        """
        if not PDF_SUPPORT:
            return "Error: PDF support not available. Install pymupdf: pip install pymupdf"
        
        if not _gemini_client:
            return "Error: GEMINI_API_KEY not set. AI analysis features are disabled."
        
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
            
            # Get threat intel context if available
            threat_intel_context = _threat_intel.get_combined_context()
            
            # Build enhanced document content with threat intel context
            if threat_intel_context:
                enhanced_content = f"""THREAT INTELLIGENCE CONTEXT:
The following threat intelligence has been loaded to provide background context for this analysis.
Use this information to inform your understanding of threat actors, TTPs, and attack patterns.

{threat_intel_context}

{'='*60}
THREAT MODEL DOCUMENT TO ANALYZE:
{'='*60}

{document_content}"""
            else:
                enhanced_content = document_content
            
            prompt = get_threat_model_analysis_prompt(
                source_type=source_type,
                document_content=enhanced_content,
                include_history=True
            )
            
            response = _gemini_client.models.generate_content(
                model='gemini-2.5-pro',
                contents=prompt
            )
            
            output = []
            output.append("=" * 60)
            output.append("🎯 THREAT MODEL ANALYSIS (PDF)")
            output.append(f"Source: {source_type} - {doc_name}")
            output.append(f"File: {source_ref}")
            if threat_intel_context:
                output.append(f"📚 Threat Intel Context: {len(_threat_intel._documents)} document(s) applied")
            output.append("=" * 60)
            output.append("")
            output.append(response.text)
            output.append("")
            output.append("=" * 60)
            output.append("💡 Next Steps:")
            output.append("  1. Use 'create_threat_scenario' to create a trackable scenario")
            output.append("  2. Use 'add_security_control' to add identified controls")
            output.append("  3. Use 'add_attack_event' to add attack sequence events")
            output.append("  4. Use 'export_threat_scenario' to generate a markdown report")
            
            return "\n".join(output)
            
        except Exception as e:
            logging.error(f"Error analyzing threat model PDF: {e}")
            return f"Error analyzing threat model PDF: {str(e)}"

    @mcp.tool()
    def analyze_threat_model(
        document_content: str,
        source_type: str = "threat_model",
        source_document: str = "uploaded_document"
    ) -> str:
        """
        Analyzes a threat modeling report or security assessment document to extract:
        - Security controls that must be bypassed for a successful attack
        - Attack sequence events that must be accomplished
        - Defense-in-depth gaps and weaknesses
        
        Args:
            document_content: The text content of the threat model document
            source_type: Type of document ('threat_model', 'security_assessment', 'red_team_report')
            source_document: Reference name for the source document
        
        Returns:
            Structured analysis of attack paths, controls, and gaps
        """
        if not _gemini_client:
            return "Error: GEMINI_API_KEY not set. AI analysis features are disabled."
        
        try:
            # Get threat intel context if available
            threat_intel_context = _threat_intel.get_combined_context()
            
            # Build enhanced document content with threat intel context
            if threat_intel_context:
                enhanced_content = f"""THREAT INTELLIGENCE CONTEXT:
The following threat intelligence has been loaded to provide background context for this analysis.
Use this information to inform your understanding of threat actors, TTPs, and attack patterns.

{threat_intel_context}

{'='*60}
THREAT MODEL DOCUMENT TO ANALYZE:
{'='*60}

{document_content}"""
            else:
                enhanced_content = document_content
            
            prompt = get_threat_model_analysis_prompt(
                source_type=source_type,
                document_content=enhanced_content,
                include_history=True
            )
            
            response = _gemini_client.models.generate_content(
                model='gemini-2.5-pro',
                contents=prompt
            )
            
            output = []
            output.append("=" * 60)
            output.append("🎯 THREAT MODEL ANALYSIS")
            output.append(f"Source: {source_type} - {source_document}")
            if threat_intel_context:
                output.append(f"📚 Threat Intel Context: {len(_threat_intel._documents)} document(s) applied")
            output.append("=" * 60)
            output.append("")
            output.append(response.text)
            output.append("")
            output.append("=" * 60)
            output.append("💡 Next Steps:")
            output.append("  1. Use 'create_threat_scenario' to create a trackable scenario")
            output.append("  2. Use 'add_security_control' to add identified controls")
            output.append("  3. Use 'add_attack_event' to add attack sequence events")
            output.append("  4. Use 'export_threat_scenario' to generate a markdown report")
            
            return "\n".join(output)
            
        except Exception as e:
            logging.error(f"Error analyzing threat model: {e}")
            return f"Error analyzing threat model: {str(e)}"

    @mcp.tool()
    def analyze_tabletop_minutes(
        minutes_content: str,
        exercise_name: str = "Tabletop Exercise",
        exercise_date: str = ""
    ) -> str:
        """
        Analyzes tabletop exercise minutes to extract:
        - Attack scenario details and threat actor profile
        - Security controls tested and their effectiveness
        - Gaps identified during the exercise
        - Recommended improvements
        
        Args:
            minutes_content: The text content of the tabletop exercise minutes
            exercise_name: Name of the tabletop exercise
            exercise_date: Date the exercise was conducted
        
        Returns:
            Structured analysis of the exercise findings
        """
        if not _gemini_client:
            return "Error: GEMINI_API_KEY not set. AI analysis features are disabled."
        
        try:
            exercise_details = f"Exercise: {exercise_name}"
            if exercise_date:
                exercise_details += f" (Date: {exercise_date})"
            
            # Get threat intel context if available
            threat_intel_context = _threat_intel.get_combined_context()
            
            # Build enhanced minutes content with threat intel context
            if threat_intel_context:
                enhanced_content = f"""THREAT INTELLIGENCE CONTEXT:
The following threat intelligence has been loaded to provide background context for this analysis.
Use this information to inform your understanding of threat actors, TTPs, and attack patterns.

{threat_intel_context}

{'='*60}
TABLETOP EXERCISE MINUTES TO ANALYZE:
{'='*60}

{minutes_content}"""
            else:
                enhanced_content = minutes_content
            
            prompt = get_tabletop_minutes_prompt(
                exercise_details=exercise_details,
                minutes_content=enhanced_content,
                include_history=True
            )
            
            response = _gemini_client.models.generate_content(
                model='gemini-2.5-pro',
                contents=prompt
            )
            
            output = []
            output.append("=" * 60)
            output.append("📋 TABLETOP EXERCISE ANALYSIS")
            output.append(f"Exercise: {exercise_name}")
            if exercise_date:
                output.append(f"Date: {exercise_date}")
            if threat_intel_context:
                output.append(f"📚 Threat Intel Context: {len(_threat_intel._documents)} document(s) applied")
            output.append("=" * 60)
            output.append("")
            output.append(response.text)
            output.append("")
            output.append("=" * 60)
            output.append("💡 Next Steps:")
            output.append("  1. Use 'create_threat_scenario' to create a trackable scenario")
            output.append("  2. Add controls and events based on the analysis")
            output.append("  3. Export to markdown for documentation")
            
            return "\n".join(output)
            
        except Exception as e:
            logging.error(f"Error analyzing tabletop minutes: {e}")
            return f"Error analyzing tabletop minutes: {str(e)}"

    @mcp.tool()
    def create_threat_scenario(
        name: str,
        description: str,
        source_type: str = "threat_model",
        source_document: str = "",
        threat_actor: str = "",
        objective: str = "",
        target_assets: str = "",
        entry_vectors: str = ""
    ) -> str:
        """
        Creates a new threat scenario for tracking attack paths and security controls.
        
        Args:
            name: Descriptive name for the scenario (e.g., "Ransomware via Phishing")
            description: Detailed description of the threat scenario
            source_type: Source type ('threat_model', 'tabletop_exercise', 'incident_review', 'red_team')
            source_document: Reference to the source document
            threat_actor: Description of the assumed threat actor
            objective: Ultimate goal of the attack
            target_assets: Comma-separated list of target assets
            entry_vectors: Comma-separated list of possible entry points
        
        Returns:
            Confirmation with the scenario ID for adding controls and events
        """
        try:
            assets = [a.strip() for a in target_assets.split(",") if a.strip()] if target_assets else []
            vectors = [v.strip() for v in entry_vectors.split(",") if v.strip()] if entry_vectors else []
            
            scenario = _tracker.create_scenario(
                name=name,
                description=description,
                source_type=source_type,
                source_document=source_document,
                threat_actor_profile=threat_actor,
                attack_objective=objective,
                target_assets=assets,
                entry_vectors=vectors
            )
            
            output = []
            output.append("✅ Threat Scenario Created")
            output.append("")
            output.append(f"**Scenario ID:** `{scenario.scenario_id}`")
            output.append(f"**Name:** {scenario.name}")
            output.append(f"**Source:** {scenario.source_type}")
            if scenario.threat_actor_profile:
                output.append(f"**Threat Actor:** {scenario.threat_actor_profile}")
            if scenario.attack_objective:
                output.append(f"**Objective:** {scenario.attack_objective}")
            if scenario.target_assets:
                output.append(f"**Target Assets:** {', '.join(scenario.target_assets)}")
            output.append("")
            output.append("Next steps:")
            output.append(f"  - Add controls: add_security_control(scenario_id='{scenario.scenario_id}', ...)")
            output.append(f"  - Add events: add_attack_event(scenario_id='{scenario.scenario_id}', ...)")
            
            return "\n".join(output)
            
        except Exception as e:
            logging.error(f"Error creating threat scenario: {e}")
            return f"Error creating threat scenario: {str(e)}"

    @mcp.tool()
    def add_security_control(
        scenario_id: str,
        name: str,
        control_type: str,
        description: str,
        implementation_status: str = "implemented",
        bypass_difficulty: str = "medium",
        bypass_requirements: str = "",
        detection_capability: str = "medium"
    ) -> str:
        """
        Adds a security control to a threat scenario.
        
        Args:
            scenario_id: The scenario ID (e.g., 'TS-0001')
            name: Name of the control (e.g., 'Web Application Firewall')
            control_type: Defense layer type ('perimeter', 'network', 'endpoint', 'application', 'data', 'identity', 'monitoring')
            description: What this control does
            implementation_status: Status ('implemented', 'partial', 'planned', 'missing')
            bypass_difficulty: How hard to bypass ('trivial', 'low', 'medium', 'high', 'very_high')
            bypass_requirements: Comma-separated list of what attacker needs to bypass
            detection_capability: Detection level ('none', 'low', 'medium', 'high')
        
        Returns:
            Confirmation with the control ID
        """
        try:
            # Map string to enum
            type_map = {
                "perimeter": DefenseLayerType.PERIMETER,
                "network": DefenseLayerType.NETWORK,
                "endpoint": DefenseLayerType.ENDPOINT,
                "application": DefenseLayerType.APPLICATION,
                "data": DefenseLayerType.DATA,
                "identity": DefenseLayerType.IDENTITY,
                "monitoring": DefenseLayerType.MONITORING
            }
            
            layer_type = type_map.get(control_type.lower())
            if not layer_type:
                return f"Error: Invalid control_type '{control_type}'. Must be one of: {', '.join(type_map.keys())}"
            
            bypass_reqs = [r.strip() for r in bypass_requirements.split(",") if r.strip()] if bypass_requirements else []
            
            control = _tracker.add_control_to_scenario(
                scenario_id=scenario_id,
                name=name,
                control_type=layer_type,
                description=description,
                implementation_status=implementation_status,
                bypass_difficulty=bypass_difficulty,
                bypass_requirements=bypass_reqs,
                detection_capability=detection_capability
            )
            
            if not control:
                return f"Error: Scenario '{scenario_id}' not found. Use list_threat_scenarios to see available scenarios."
            
            output = []
            output.append("✅ Security Control Added")
            output.append("")
            output.append(f"**Control ID:** `{control.control_id}`")
            output.append(f"**Name:** {control.name}")
            output.append(f"**Type:** {control.control_type.value}")
            output.append(f"**Status:** {control.implementation_status}")
            output.append(f"**Bypass Difficulty:** {control.bypass_difficulty}")
            output.append("")
            output.append(f"Added to scenario: {scenario_id}")
            
            return "\n".join(output)
            
        except Exception as e:
            logging.error(f"Error adding security control: {e}")
            return f"Error adding security control: {str(e)}"

    @mcp.tool()
    def add_attack_event(
        scenario_id: str,
        name: str,
        description: str,
        sequence_order: int,
        target_asset: str = "",
        technique_name: str = "",
        technique_id: str = "",
        required_access: str = "none",
        resulting_access: str = "none",
        blocking_controls: str = "",
        detecting_controls: str = "",
        success_indicators: str = ""
    ) -> str:
        """
        Adds an attack sequence event to a threat scenario.
        
        Args:
            scenario_id: The scenario ID (e.g., 'TS-0001')
            name: Short name for the event (e.g., 'Phishing Email Delivery')
            description: Detailed description of what must happen
            sequence_order: Order in the attack sequence (1, 2, 3...)
            target_asset: Asset being targeted in this step
            technique_name: MITRE ATT&CK technique name (optional)
            technique_id: MITRE ATT&CK ID like 'T1566' (optional)
            required_access: Access level needed to attempt this step
            resulting_access: Access gained if successful
            blocking_controls: Comma-separated control IDs that would block this (e.g., 'SC-0001,SC-0002')
            detecting_controls: Comma-separated control IDs that would detect this
            success_indicators: Comma-separated indicators of success
        
        Returns:
            Confirmation with the event ID
        """
        try:
            blocking = [c.strip() for c in blocking_controls.split(",") if c.strip()] if blocking_controls else []
            detecting = [c.strip() for c in detecting_controls.split(",") if c.strip()] if detecting_controls else []
            indicators = [i.strip() for i in success_indicators.split(",") if i.strip()] if success_indicators else []
            
            event = _tracker.add_event_to_scenario(
                scenario_id=scenario_id,
                name=name,
                description=description,
                sequence_order=sequence_order,
                target_asset=target_asset,
                attack_technique=technique_name,
                technique_id=technique_id,
                required_access=required_access,
                resulting_access=resulting_access,
                blocking_controls=blocking,
                detecting_controls=detecting,
                success_indicators=indicators
            )
            
            if not event:
                return f"Error: Scenario '{scenario_id}' not found. Use list_threat_scenarios to see available scenarios."
            
            # Determine protection status
            if blocking:
                status = "🛡️ PROTECTED"
            elif detecting:
                status = "🟡 DETECT ONLY"
            else:
                status = "⚠️ UNPROTECTED"
            
            output = []
            output.append("✅ Attack Event Added")
            output.append("")
            output.append(f"**Event ID:** `{event.event_id}`")
            output.append(f"**Step {event.sequence_order}:** {event.name}")
            output.append(f"**Status:** {status}")
            if event.technique_id:
                output.append(f"**Technique:** {event.attack_technique} ({event.technique_id})")
            output.append(f"**Target:** {event.target_asset}")
            output.append(f"**Access:** {event.required_access} → {event.resulting_access}")
            if blocking:
                output.append(f"**Blocking Controls:** {', '.join(blocking)}")
            if detecting:
                output.append(f"**Detecting Controls:** {', '.join(detecting)}")
            output.append("")
            output.append(f"Added to scenario: {scenario_id}")
            
            return "\n".join(output)
            
        except Exception as e:
            logging.error(f"Error adding attack event: {e}")
            return f"Error adding attack event: {str(e)}"

    @mcp.tool()
    def list_threat_scenarios() -> str:
        """
        Lists all tracked threat scenarios in the current session.
        
        Returns:
            Summary of all scenarios with their IDs, controls, and events
        """
        try:
            scenarios = _tracker.get_all_scenarios()
            
            if not scenarios:
                return "No threat scenarios have been created in this session.\n\nUse 'create_threat_scenario' to create one."
            
            output = []
            output.append("=" * 60)
            output.append("📋 THREAT SCENARIOS")
            output.append("=" * 60)
            output.append("")
            
            for scenario in scenarios:
                output.append(f"**{scenario.scenario_id}:** {scenario.name}")
                output.append(f"  Source: {scenario.source_type}")
                output.append(f"  Controls: {len(scenario.security_controls)}")
                output.append(f"  Attack Events: {len(scenario.attack_sequence)}")
                
                # Quick gap check
                unprotected = [e for e in scenario.attack_sequence if not e.blocking_controls]
                if unprotected:
                    output.append(f"  ⚠️ Unprotected Events: {len(unprotected)}")
                
                output.append("")
            
            output.append("=" * 60)
            output.append("Commands:")
            output.append("  - View details: get_scenario_gaps(scenario_id='...')")
            output.append("  - Export: export_threat_scenario(scenario_id='...', output_path='...')")
            
            return "\n".join(output)
            
        except Exception as e:
            logging.error(f"Error listing threat scenarios: {e}")
            return f"Error listing threat scenarios: {str(e)}"

    @mcp.tool()
    def get_scenario_gaps(scenario_id: str) -> str:
        """
        Analyzes a threat scenario for defense gaps and weaknesses.
        
        Args:
            scenario_id: The scenario ID to analyze (e.g., 'TS-0001')
        
        Returns:
            Gap analysis showing unprotected events, weak controls, and recommendations
        """
        try:
            scenario = _tracker.get_scenario(scenario_id)
            
            if not scenario:
                return f"Error: Scenario '{scenario_id}' not found. Use list_threat_scenarios to see available scenarios."
            
            output = []
            output.append("=" * 60)
            output.append(f"🔍 GAP ANALYSIS: {scenario.name}")
            output.append("=" * 60)
            output.append("")
            
            # Unprotected events
            unprotected = [e for e in scenario.attack_sequence if not e.blocking_controls]
            detect_only = [e for e in scenario.attack_sequence if e.detecting_controls and not e.blocking_controls]
            
            if unprotected:
                output.append("### ⚠️ UNPROTECTED ATTACK STEPS")
                output.append("These steps have NO blocking controls:")
                for event in unprotected:
                    output.append(f"  - Step {event.sequence_order}: {event.name}")
                    if event.detecting_controls:
                        output.append(f"    (Detection only: {', '.join(event.detecting_controls)})")
                output.append("")
            
            # Weak controls
            weak = [c for c in scenario.security_controls if c.implementation_status in ("partial", "planned", "missing")]
            if weak:
                output.append("### 📋 INCOMPLETE CONTROLS")
                for control in weak:
                    output.append(f"  - {control.name}: {control.implementation_status}")
                output.append("")
            
            # Easy bypass controls
            easy = [c for c in scenario.security_controls if c.bypass_difficulty in ("trivial", "low")]
            if easy:
                output.append("### 🔓 EASY-TO-BYPASS CONTROLS")
                for control in easy:
                    output.append(f"  - {control.name}: {control.bypass_difficulty} difficulty")
                    if control.bypass_requirements:
                        output.append(f"    Requirements: {', '.join(control.bypass_requirements)}")
                output.append("")
            
            # Weakest point
            weakest = scenario.get_weakest_point()
            if weakest:
                output.append("### 🎯 WEAKEST POINT IN ATTACK CHAIN")
                output.append(f"Step {weakest.sequence_order}: {weakest.name}")
                output.append(f"  - Blocking controls: {len(weakest.blocking_controls)}")
                output.append(f"  - Detecting controls: {len(weakest.detecting_controls)}")
                output.append("")
            
            # Defense coverage
            coverage = scenario.get_defense_coverage()
            output.append("### 🛡️ DEFENSE-IN-DEPTH COVERAGE")
            for layer, data in coverage.items():
                if data["control_count"] > 0:
                    status = data["implementation_status"]
                    output.append(f"  {layer.upper()}: {data['control_count']} controls")
                    output.append(f"    Implemented: {status['implemented']}, Partial: {status['partial']}, Missing: {status['missing']}")
            
            # Summary
            output.append("")
            if not unprotected and not weak and not easy:
                output.append("✅ No critical gaps identified. All attack steps have blocking controls.")
            else:
                total_issues = len(unprotected) + len(weak) + len(easy)
                output.append(f"⚠️ {total_issues} potential issues identified. Review and remediate.")
            
            return "\n".join(output)
            
        except Exception as e:
            logging.error(f"Error analyzing scenario gaps: {e}")
            return f"Error analyzing scenario gaps: {str(e)}"

    @mcp.tool()
    def export_threat_scenario(
        scenario_id: str,
        output_path: str = "",
        view_type: str = "tree"
    ) -> str:
        """
        Exports a threat scenario to a markdown file.
        
        Args:
            scenario_id: The scenario ID to export (e.g., 'TS-0001')
            output_path: File path for the markdown output (default: scenario_id.md in current dir)
            view_type: View format ('tree' for hierarchical, 'table' for tabular)
        
        Returns:
            Confirmation with the output file path, or the markdown content if no path specified
        """
        try:
            scenario = _tracker.get_scenario(scenario_id)
            
            if not scenario:
                return f"Error: Scenario '{scenario_id}' not found. Use list_threat_scenarios to see available scenarios."
            
            markdown = generate_threat_scenario_markdown(scenario, view_type=view_type)
            
            if output_path:
                # Write to file
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(markdown)
                
                return f"✅ Exported threat scenario to: {output_path}\n\nView the file to see the full attack path analysis with:\n  - Security controls by defense layer\n  - Attack sequence with protection status\n  - Control coverage matrix\n  - Gap analysis\n  - Defense-in-depth coverage"
            else:
                # Return markdown content directly
                return markdown
            
        except Exception as e:
            logging.error(f"Error exporting threat scenario: {e}")
            return f"Error exporting threat scenario: {str(e)}"
