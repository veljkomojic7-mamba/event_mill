"""
Attack Path Visualization Module - Generate visual representations of attack paths

This module provides visualization capabilities for risk assessment results:
- ASCII art attack path diagrams
- Mermaid flowchart syntax (renders in markdown viewers/GitHub)
- Text-based stage flow diagrams

Can be called after analyze_risk_assessment_pdf to visualize the attack path.
"""

import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


# =============================================================================
# ASCII ART RENDERING
# =============================================================================

def render_ascii_attack_path(result_data: Dict[str, Any], compact: bool = False) -> str:
    """
    Render an attack path as ASCII art box-and-arrow diagram.
    
    Args:
        result_data: Risk assessment result dictionary (from RiskAssessmentResult.to_dict())
        compact: If True, use compact single-line boxes
    
    Returns:
        ASCII art string representation of the attack path
    """
    stages = result_data.get("stages", [])
    attack_type = result_data.get("attack_type", "unknown")
    narrative = result_data.get("attack_narrative", "")
    
    if not stages:
        return "No attack stages found in the assessment."
    
    lines = []
    
    # Header
    lines.append("")
    lines.append("╔" + "═" * 70 + "╗")
    lines.append("║" + f" ATTACK PATH VISUALIZATION - {attack_type.upper()} ".center(70) + "║")
    lines.append("╚" + "═" * 70 + "╝")
    lines.append("")
    
    if narrative:
        # Wrap narrative to 68 chars
        wrapped = _wrap_text(narrative, 68)
        for line in wrapped[:3]:  # Max 3 lines
            lines.append(f"  {line}")
        if len(wrapped) > 3:
            lines.append("  ...")
        lines.append("")
    
    # Render stages
    present_stages = [s for s in stages if s.get("stage_present", True)]
    missing_stages = [s for s in stages if not s.get("stage_present", True) and s.get("relevance") == "required"]
    
    if compact:
        lines.extend(_render_compact_path(present_stages))
    else:
        lines.extend(_render_detailed_path(present_stages))
    
    # Missing stages warning
    if missing_stages:
        lines.append("")
        lines.append("  ⚠️  MISSING REQUIRED STAGES:")
        for stage in missing_stages:
            lines.append(f"      ╳ {stage.get('name', 'Unknown')}")
    
    # Legend
    lines.append("")
    lines.append("  ─────────────────────────────────────────────────────────────────")
    lines.append("  Legend: ███ strong | ██░ moderate | █░░ weak | ░░░ nominal")
    lines.append("          [P] preventive | [D] detective | [R] responsive")
    lines.append("")
    
    return "\n".join(lines)


def _render_compact_path(stages: List[Dict]) -> List[str]:
    """Render stages as a compact horizontal flow."""
    lines = []
    
    # Build stage boxes
    stage_boxes = []
    for stage in stages:
        name = stage.get("name", "Unknown")
        # Truncate to 15 chars
        if len(name) > 15:
            name = name[:12] + "..."
        stage_boxes.append(name)
    
    # Render as flow
    flow_line = "  "
    for i, box in enumerate(stage_boxes):
        flow_line += f"[{box}]"
        if i < len(stage_boxes) - 1:
            flow_line += " ──► "
    
    lines.append(flow_line)
    return lines


def _render_detailed_path(stages: List[Dict]) -> List[str]:
    """Render stages as detailed vertical boxes with controls."""
    lines = []
    
    for i, stage in enumerate(stages):
        name = stage.get("name", "Unknown")
        technique = stage.get("technique_claimed", "")
        mitre_id = stage.get("mitre_technique_id", "")
        controls = stage.get("controls", [])
        gaps = stage.get("gaps_detected", [])
        
        # Stage box
        box_width = 66
        lines.append("  ┌" + "─" * box_width + "┐")
        
        # Stage header
        header = f" {i+1}. {name}"
        if mitre_id:
            header += f" ({mitre_id})"
        lines.append("  │" + header.ljust(box_width) + "│")
        
        # Technique
        if technique:
            tech_line = f"    Technique: {technique[:50]}"
            lines.append("  │" + tech_line.ljust(box_width) + "│")
        
        # Controls
        if controls:
            lines.append("  │" + "    Controls:".ljust(box_width) + "│")
            for ctrl in controls[:4]:  # Max 4 controls shown
                ctrl_name = ctrl.get("control_name", "Unknown")[:30]
                ctrl_type = ctrl.get("control_type", "?")[0].upper()  # P/D/R
                eff = ctrl.get("effectiveness_rating", "unknown")
                eff_bar = {"strong": "███", "moderate": "██░", "weak": "█░░", "nominal": "░░░"}.get(eff, "???")
                
                ctrl_line = f"      [{ctrl_type}] {ctrl_name} {eff_bar}"
                lines.append("  │" + ctrl_line.ljust(box_width) + "│")
            
            if len(controls) > 4:
                lines.append("  │" + f"      ... +{len(controls)-4} more controls".ljust(box_width) + "│")
        
        # Gaps
        if gaps:
            lines.append("  │" + "    ⚠ Gaps:".ljust(box_width) + "│")
            for gap in gaps[:2]:
                gap_line = f"      • {gap[:50]}"
                lines.append("  │" + gap_line.ljust(box_width) + "│")
        
        lines.append("  └" + "─" * box_width + "┘")
        
        # Arrow to next stage
        if i < len(stages) - 1:
            lines.append("           │")
            lines.append("           ▼")
    
    return lines


def _wrap_text(text: str, width: int) -> List[str]:
    """Wrap text to specified width."""
    words = text.split()
    lines = []
    current_line = ""
    
    for word in words:
        if len(current_line) + len(word) + 1 <= width:
            current_line += (" " if current_line else "") + word
        else:
            if current_line:
                lines.append(current_line)
            current_line = word
    
    if current_line:
        lines.append(current_line)
    
    return lines


# =============================================================================
# MERMAID DIAGRAM RENDERING
# =============================================================================

def render_mermaid_attack_path(result_data: Dict[str, Any], direction: str = "TB") -> str:
    """
    Render an attack path as a Mermaid flowchart diagram.
    
    Args:
        result_data: Risk assessment result dictionary
        direction: Flow direction - TB (top-bottom), LR (left-right)
    
    Returns:
        Mermaid diagram syntax string (can be rendered in markdown)
    """
    stages = result_data.get("stages", [])
    attack_type = result_data.get("attack_type", "unknown")
    
    if not stages:
        return "```mermaid\nflowchart TB\n    A[No stages found]\n```"
    
    lines = []
    lines.append("```mermaid")
    lines.append(f"flowchart {direction}")
    lines.append(f"    subgraph attack[\"{attack_type.upper()} Attack Path\"]")
    lines.append("    direction TB")
    
    # Generate node IDs and definitions
    present_stages = [s for s in stages if s.get("stage_present", True)]
    
    for i, stage in enumerate(present_stages):
        name = stage.get("name", "Unknown")
        mitre_id = stage.get("mitre_technique_id", "")
        controls = stage.get("controls", [])
        gaps = stage.get("gaps_detected", [])
        
        node_id = f"S{i}"
        
        # Determine node style based on controls/gaps
        if gaps:
            # Has gaps - warning style
            label = f"{name}"
            if mitre_id:
                label += f"<br/><small>{mitre_id}</small>"
            label += f"<br/><small>⚠ {len(gaps)} gap(s)</small>"
            lines.append(f"    {node_id}[[\"{label}\"]]")
        elif controls:
            # Has controls - protected
            ctrl_count = len(controls)
            label = f"{name}"
            if mitre_id:
                label += f"<br/><small>{mitre_id}</small>"
            label += f"<br/><small>🛡 {ctrl_count} control(s)</small>"
            lines.append(f"    {node_id}[\"{label}\"]")
        else:
            # No controls - unprotected
            label = f"{name}"
            if mitre_id:
                label += f"<br/><small>{mitre_id}</small>"
            lines.append(f"    {node_id}([\"{label}\"])")
    
    # Generate edges
    for i in range(len(present_stages) - 1):
        lines.append(f"    S{i} --> S{i+1}")
    
    lines.append("    end")
    
    # Style definitions
    lines.append("")
    lines.append("    %% Styling")
    
    for i, stage in enumerate(present_stages):
        gaps = stage.get("gaps_detected", [])
        controls = stage.get("controls", [])
        
        if gaps:
            lines.append(f"    style S{i} fill:#ffcccc,stroke:#cc0000")
        elif not controls:
            lines.append(f"    style S{i} fill:#ffffcc,stroke:#cccc00")
        else:
            lines.append(f"    style S{i} fill:#ccffcc,stroke:#00cc00")
    
    lines.append("```")
    
    return "\n".join(lines)


def render_mermaid_control_matrix(result_data: Dict[str, Any]) -> str:
    """
    Render a control coverage matrix as a Mermaid diagram.
    
    Args:
        result_data: Risk assessment result dictionary
    
    Returns:
        Mermaid diagram showing control coverage across stages
    """
    stages = result_data.get("stages", [])
    
    if not stages:
        return "```mermaid\nflowchart TB\n    A[No stages found]\n```"
    
    lines = []
    lines.append("```mermaid")
    lines.append("flowchart LR")
    lines.append("    subgraph controls[\"Control Coverage Matrix\"]")
    
    # Collect all unique controls
    all_controls = {}
    for stage in stages:
        for ctrl in stage.get("controls", []):
            ctrl_name = ctrl.get("control_name", "Unknown")
            if ctrl_name not in all_controls:
                all_controls[ctrl_name] = {
                    "type": ctrl.get("control_type", "unknown"),
                    "effectiveness": ctrl.get("effectiveness_rating", "unknown"),
                    "stages": []
                }
            all_controls[ctrl_name]["stages"].append(stage.get("name", "Unknown"))
    
    # Render controls
    for i, (ctrl_name, ctrl_info) in enumerate(all_controls.items()):
        node_id = f"C{i}"
        eff = ctrl_info["effectiveness"]
        stage_count = len(ctrl_info["stages"])
        
        label = f"{ctrl_name[:25]}<br/><small>{eff} | {stage_count} stage(s)</small>"
        lines.append(f"    {node_id}[\"{label}\"]")
    
    lines.append("    end")
    
    # Style based on effectiveness
    lines.append("")
    for i, (ctrl_name, ctrl_info) in enumerate(all_controls.items()):
        eff = ctrl_info["effectiveness"]
        if eff == "strong":
            lines.append(f"    style C{i} fill:#00cc00,color:#fff")
        elif eff == "moderate":
            lines.append(f"    style C{i} fill:#cccc00")
        elif eff == "weak":
            lines.append(f"    style C{i} fill:#ff9900")
        else:
            lines.append(f"    style C{i} fill:#cc0000,color:#fff")
    
    lines.append("```")
    
    return "\n".join(lines)


# =============================================================================
# COMBINED OUTPUT
# =============================================================================

def generate_attack_path_visualization(
    result_data: Dict[str, Any],
    output_format: str = "ascii",
    include_controls: bool = True
) -> str:
    """
    Generate attack path visualization in the specified format.
    
    Args:
        result_data: Risk assessment result dictionary
        output_format: "ascii", "mermaid", "both"
        include_controls: Whether to include control matrix (for mermaid)
    
    Returns:
        Visualization string
    """
    outputs = []
    
    if output_format in ("ascii", "both"):
        outputs.append(render_ascii_attack_path(result_data))
    
    if output_format in ("mermaid", "both"):
        outputs.append("")
        outputs.append("## Mermaid Diagram")
        outputs.append("")
        outputs.append("Copy the following into a markdown file or mermaid-enabled viewer:")
        outputs.append("")
        outputs.append(render_mermaid_attack_path(result_data))
        
        if include_controls:
            outputs.append("")
            outputs.append("### Control Coverage")
            outputs.append("")
            outputs.append(render_mermaid_control_matrix(result_data))
    
    return "\n".join(outputs)


# =============================================================================
# TOOL REGISTRATION
# =============================================================================

# Store last analysis result for visualization
_last_risk_assessment_result: Optional[Dict[str, Any]] = None


def set_last_risk_assessment_result(result: Dict[str, Any]) -> None:
    """Store the last risk assessment result for visualization."""
    global _last_risk_assessment_result
    _last_risk_assessment_result = result


def get_last_risk_assessment_result() -> Optional[Dict[str, Any]]:
    """Get the last stored risk assessment result."""
    return _last_risk_assessment_result


def register_visualization_tools(mcp):
    """Register visualization tools with the MCP server."""
    
    @mcp.tool()
    def visualize_attack_path(
        output_format: str = "ascii",
        json_data: str = ""
    ) -> str:
        """
        Generates a visual representation of the last analyzed attack path.
        
        Call this after running analyze_risk_assessment_pdf to visualize the results.
        
        Args:
            output_format: Output format - 'ascii' for terminal art, 'mermaid' for diagrams, 'both' for all
            json_data: Optional JSON string of risk assessment result (if not using last result)
        
        Returns:
            Visual representation of the attack path
        """
        result_data = None
        
        if json_data:
            try:
                result_data = json.loads(json_data)
            except json.JSONDecodeError as e:
                return f"Error parsing JSON data: {e}"
        else:
            result_data = get_last_risk_assessment_result()
        
        if not result_data:
            return """No risk assessment data available.

Run a risk assessment first:
  ra <pdf_path> [attack_type] [--gcs]

Then visualize:
  visualize [ascii|mermaid|both]

Or provide JSON data directly:
  visualize_attack_path(json_data='{"stages": [...]}')"""
        
        return generate_attack_path_visualization(
            result_data,
            output_format=output_format.lower(),
            include_controls=True
        )
    
    @mcp.tool()
    def visualize_attack_path_compact() -> str:
        """
        Generates a compact single-line visualization of the attack path.
        
        Returns:
            Compact ASCII flow diagram
        """
        result_data = get_last_risk_assessment_result()
        
        if not result_data:
            return "No risk assessment data available. Run 'ra <pdf>' first."
        
        stages = result_data.get("stages", [])
        attack_type = result_data.get("attack_type", "unknown")
        
        if not stages:
            return "No attack stages found."
        
        lines = []
        lines.append(f"\n  {attack_type.upper()} ATTACK PATH:")
        lines.append("")
        
        present_stages = [s for s in stages if s.get("stage_present", True)]
        lines.extend(_render_compact_path(present_stages))
        
        # Add control summary
        lines.append("")
        total_controls = sum(len(s.get("controls", [])) for s in present_stages)
        total_gaps = sum(len(s.get("gaps_detected", [])) for s in present_stages)
        lines.append(f"  Stages: {len(present_stages)} | Controls: {total_controls} | Gaps: {total_gaps}")
        lines.append("")
        
        return "\n".join(lines)
