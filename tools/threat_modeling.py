"""
Threat Modeling Tools - Attack path analysis from threat models and tabletop exercises

Tools:
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
from typing import Optional, List

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


def register_threat_modeling_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register threat modeling tools with the MCP server."""
    
    _storage_client = storage_client
    _gemini_client = gemini_client
    _get_bucket = get_bucket_func
    _tracker = get_threat_scenario_tracker()

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
            prompt = get_threat_model_analysis_prompt(
                source_type=source_type,
                document_content=document_content,
                include_history=True
            )
            
            response = _gemini_client.models.generate_content(
                model='gemini-2.5-pro-preview-05-06',
                contents=prompt
            )
            
            output = []
            output.append("=" * 60)
            output.append("🎯 THREAT MODEL ANALYSIS")
            output.append(f"Source: {source_type} - {source_document}")
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
            
            prompt = get_tabletop_minutes_prompt(
                exercise_details=exercise_details,
                minutes_content=minutes_content,
                include_history=True
            )
            
            response = _gemini_client.models.generate_content(
                model='gemini-2.5-pro-preview-05-06',
                contents=prompt
            )
            
            output = []
            output.append("=" * 60)
            output.append("📋 TABLETOP EXERCISE ANALYSIS")
            output.append(f"Exercise: {exercise_name}")
            if exercise_date:
                output.append(f"Date: {exercise_date}")
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
