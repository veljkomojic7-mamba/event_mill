"""
Event Mill MCP Tools

This package contains modular tool implementations for the Event Mill MCP server.
Each module groups related functionality for easier maintenance.

Modules:
- navigation: Bucket/file listing and reading (list_buckets, list_logs, read_log_segment, get_log_metadata)
- search: Log searching (search_log)
- analysis: Pattern analysis (analyze_log_grok, analyze_log_regex, discover_log_patterns)
- investigation: AI-powered investigation (investigate_log, soc_workflow)
- templates: Template generation (generate_pattern_templates, get_parsing_patterns)
- threat_modeling: Threat model and tabletop analysis (analyze_threat_model, create_threat_scenario, etc.)
"""

from tools.navigation import register_navigation_tools
from tools.search import register_search_tools
from tools.analysis import register_analysis_tools
from tools.investigation import register_investigation_tools
from tools.templates import register_template_tools
from tools.threat_modeling import register_threat_modeling_tools

# Module-level reference for gemini_client (set by register_all_tools)
_gemini_client = None

def register_all_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register all MCP tools with the server."""
    global _gemini_client
    _gemini_client = gemini_client
    
    register_navigation_tools(mcp, storage_client, get_bucket_func)
    register_search_tools(mcp, storage_client, get_bucket_func)
    register_analysis_tools(mcp, storage_client, gemini_client, get_bucket_func)
    register_investigation_tools(mcp, storage_client, gemini_client, get_bucket_func)
    register_template_tools(mcp, storage_client, gemini_client, get_bucket_func)
    register_threat_modeling_tools(mcp, storage_client, gemini_client, get_bucket_func)
