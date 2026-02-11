#!/usr/bin/env python3
"""
Event Mill - Event Record Analysis Platform
Supporting Security Operations & Detection Engineering
"""

import asyncio
import sys
import os
import re
import json
import random
from typing import Dict, Any, List, Tuple

# Ensure we can import mcp
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import google.genai as genai
from dotenv import load_dotenv
from system_context import get_conversational_prompt, get_final_analysis_prompt
from pattern_templates import get_event_classifications

# Load environment variables
load_dotenv()

# =============================================================================
# EVENT MILL ASCII ART BANNERS
# =============================================================================

# ANSI Color codes
class Colors:
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

BANNER_MILL = f"""
{Colors.CYAN}                    ⚙️  ⚙️  ⚙️{Colors.RESET}
{Colors.BLUE}              ╔═══════════════════════╗{Colors.RESET}
{Colors.BLUE}              ║{Colors.CYAN}   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}              ║{Colors.CYAN}   █ {Colors.WHITE}EVENT  MILL{Colors.CYAN} █   {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}              ║{Colors.CYAN}   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀   {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}              ╚═══════════════════════╝{Colors.RESET}
{Colors.DIM}        Grinding Events into Intelligence{Colors.RESET}
"""

BANNER_GEARS = f"""
{Colors.CYAN}            ⣀⣤⣤⣤⣤⣤⣤⣤⣤⣀
          ⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦
         ⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧
        ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿{Colors.RESET}
{Colors.BLUE}       ╔══════════════════════════════╗{Colors.RESET}
{Colors.BLUE}       ║  {Colors.WHITE}{Colors.BOLD}E V E N T   M I L L{Colors.RESET}{Colors.BLUE}        ║{Colors.RESET}
{Colors.BLUE}       ╚══════════════════════════════╝{Colors.RESET}
{Colors.GREEN}         Security Ops • Detection Eng{Colors.RESET}
{Colors.DIM}            Observability Lake Ready{Colors.RESET}
"""

BANNER_CLOUD = f"""
{Colors.CYAN}                  .-~~~-.
            .- ~ ~-(       )_ _
           /                     ~ -.
          |    {Colors.WHITE}EVENT MILL{Colors.CYAN}            \\
           \\                         .'
            ~- ._ _ _ _ _ _ _ _.-~{Colors.RESET}
{Colors.BLUE}       ════════════════════════════════{Colors.RESET}
{Colors.GREEN}        Grinding Logs Into Intelligence{Colors.RESET}
{Colors.DIM}          SecOps • DetEng • ObsLake{Colors.RESET}
"""

BANNER_SAWBLADE = f"""
{Colors.CYAN}              ╭─────────────────╮
           ╭──┤ {Colors.WHITE}⚙ EVENT MILL ⚙{Colors.CYAN} ├──╮
           │  ╰─────────────────╯  │
        ╭──┴──╮               ╭──┴──╮
        │{Colors.YELLOW}░░░░░{Colors.CYAN}│{Colors.WHITE}  v1.0.0-beta {Colors.CYAN}│{Colors.YELLOW}░░░░░{Colors.CYAN}│
        ╰──┬──╯               ╰──┬──╯
           │  ╭─────────────────╮  │
           ╰──┤{Colors.GREEN} GRIND • PARSE • {Colors.CYAN}├──╯
              ╰─────────────────╯{Colors.RESET}
{Colors.DIM}    Security Operations & Detection Engineering{Colors.RESET}
"""

BANNER_MINIMAL = f"""
{Colors.BLUE}╔══════════════════════════════════════════════════════════╗{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}                                                          {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.CYAN}{Colors.BOLD}███████╗██╗   ██╗███████╗███╗   ██╗████████╗{Colors.RESET}        {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.CYAN}{Colors.BOLD}██╔════╝██║   ██║██╔════╝████╗  ██║╚══██╔══╝{Colors.RESET}        {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.CYAN}{Colors.BOLD}█████╗  ██║   ██║█████╗  ██╔██╗ ██║   ██║{Colors.RESET}           {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.CYAN}{Colors.BOLD}██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ██║{Colors.RESET}           {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.CYAN}{Colors.BOLD}███████╗ ╚████╔╝ ███████╗██║ ╚████║   ██║{Colors.RESET}           {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.CYAN}{Colors.BOLD}╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝{Colors.RESET}           {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}                                                          {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.WHITE}{Colors.BOLD}███╗   ███╗██╗██╗     ██╗{Colors.RESET}     {Colors.DIM}v1.0.0-beta{Colors.RESET}         {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.WHITE}{Colors.BOLD}████╗ ████║██║██║     ██║{Colors.RESET}                         {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.WHITE}{Colors.BOLD}██╔████╔██║██║██║     ██║{Colors.RESET}                         {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.WHITE}{Colors.BOLD}██║╚██╔╝██║██║██║     ██║{Colors.RESET}                         {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.WHITE}{Colors.BOLD}██║ ╚═╝ ██║██║███████╗███████╗{Colors.RESET}                    {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}   {Colors.WHITE}{Colors.BOLD}╚═╝     ╚═╝╚═╝╚══════╝╚══════╝{Colors.RESET}                    {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}                                                          {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}╠══════════════════════════════════════════════════════════╣{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}  {Colors.GREEN}⚡ Security Operations{Colors.RESET}    {Colors.YELLOW}⚙ Detection Engineering{Colors.RESET}     {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}║{Colors.RESET}  {Colors.MAGENTA}☁ Observability Lake{Colors.RESET}     {Colors.CYAN}📊 ECS/OpenTelemetry{Colors.RESET}        {Colors.BLUE}║{Colors.RESET}
{Colors.BLUE}╚══════════════════════════════════════════════════════════╝{Colors.RESET}
"""

# Startup tips/quotes (like metasploit)
STARTUP_TIPS = [
    f"{Colors.DIM}💡 Tip: Use 'templates' to generate GROK patterns from any log format{Colors.RESET}",
    f"{Colors.DIM}💡 Tip: Use 'patterns' to see all available GROK patterns & OTel mappings{Colors.RESET}",
    f"{Colors.DIM}💡 Tip: Use 'scan --full' to analyze entire log files with AI{Colors.RESET}",
    f"{Colors.DIM}💡 Tip: Natural language queries work! Try 'show me top talkers'{Colors.RESET}",
    f"{Colors.DIM}💡 Tip: Detection engineers can export templates in GROK config format{Colors.RESET}",
    f"{Colors.DIM}💡 Tip: 20 ECS event categories supported for security & reliability{Colors.RESET}",
    f"{Colors.DIM}💡 Tip: OpenTelemetry semantic conventions built-in for observability{Colors.RESET}",
    f"{Colors.DIM}💡 Tip: Use 'analyze' with regex to extract specific patterns{Colors.RESET}",
    f"{Colors.DIM}🔒 Security: Analyzing exported logs - read-only, no live system access{Colors.RESET}",
    f"{Colors.DIM}⚙️  Mill Status: Ready to grind your events into intelligence{Colors.RESET}",
]

def print_banner():
    """Print a random startup banner with stats"""
    banners = [BANNER_MINIMAL, BANNER_SAWBLADE, BANNER_GEARS, BANNER_CLOUD, BANNER_MILL]
    print(random.choice(banners))
    
    # Print stats
    event_categories = get_event_classifications()
    print(f"{Colors.DIM}       [{Colors.GREEN}{len(event_categories)}{Colors.DIM} event categories] [{Colors.CYAN}GROK{Colors.DIM}+{Colors.CYAN}OTel{Colors.DIM} patterns] [{Colors.YELLOW}AI{Colors.DIM}-powered]{Colors.RESET}")
    print()
    print(random.choice(STARTUP_TIPS))
    print()

# =============================================================================
# EVENT MILL ASSISTANT
# =============================================================================

class EventMillAssistant:
    def __init__(self, session: ClientSession):
        self.session = session
        self.gemini_client = None
        
        # Initialize Gemini for conversation
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        if gemini_api_key:
            try:
                self.gemini_client = genai.Client()
                print(f"{Colors.GREEN}⚙️  AI Engine initialized{Colors.RESET}")
            except Exception as e:
                print(f"⚠️  Gemini initialization failed: {e}")
        else:
            print("⚠️  GEMINI_API_KEY not set - conversational features disabled")

    async def process_analyst_request(self, user_input: str) -> str:
        """Process natural language request from SOC analyst"""
        
        if not self.gemini_client:
            return "❌ Gemini AI not available. Please use manual commands."
        
        try:
            # Get available tools for context
            tools = await self.session.list_tools()
            tool_descriptions = []
            for tool in tools.tools:
                tool_descriptions.append(f"- {tool.name}: {tool.description}")
            
            # Get available files for context
            available_files = await self.get_available_files_context()
            
            # Construct prompt using the system context
            prompt = get_conversational_prompt(
                user_input=user_input,
                available_files=available_files,
                tool_descriptions=chr(10).join(tool_descriptions)
            )
            
            # Get AI response
            response = self.gemini_client.models.generate_content(
                model='gemini-3-flash-preview',
                contents=prompt
            )
            
            ai_response = response.text.strip()
            
            # Parse JSON response
            try:
                # Extract JSON from response (in case there's extra text)
                json_match = re.search(r'\\{.*\\}', ai_response, re.DOTALL)
                if json_match:
                    ai_json = json.loads(json_match.group())
                else:
                    ai_json = json.loads(ai_response)
            except json.JSONDecodeError as e:
                return f"❌ Failed to parse AI response: {e}\\nRaw response: {ai_response}"
            
            # Execute tool calls
            tool_results = await self.execute_tool_calls(ai_json.get("tool_calls", []))
            
            # Perform internet search if requested
            threat_intel = ""
            if ai_json.get("internet_search"):
                threat_intel = await self.internet_search(ai_json["internet_search"])
            
            # Get final analysis using system context
            final_prompt = get_final_analysis_prompt(
                user_input=user_input,
                analysis_plan=ai_json.get('analysis', 'No analysis provided'),
                tool_results=tool_results,
                threat_intel=threat_intel if threat_intel else "No threat intelligence search performed."
            )
            
            final_response = self.gemini_client.models.generate_content(
                model='gemini-3-flash-preview',
                contents=final_prompt
            )
            
            return final_response.text
            
        except Exception as e:
            return f"❌ Error processing request: {str(e)}"

    async def execute_tool_calls(self, tool_calls: List[Dict]) -> str:
        """Execute tool calls from AI response"""
        results = []
        
        for call in tool_calls:
            tool_name = call.get("tool")
            parameters = call.get("parameters", {})
            
            try:
                result = await self.session.call_tool(tool_name, parameters)
                tool_output = result.content[0].text
                results.append(f"🔧 {tool_name}:\\n{tool_output}")
            except Exception as e:
                results.append(f"❌ {tool_name} failed: {str(e)}")
        
        return "\\n\\n".join(results) if results else "No tools executed."

    async def internet_search(self, query: str) -> str:
        """Perform internet search for threat intelligence"""
        try:
            search_prompt = f"""
Search the internet for current threat intelligence about: {query}

Focus on:
1. Recent CVEs (last 6 months)
2. Active threat actor campaigns
3. MITRE ATT&CK techniques
4. Security advisories
5. IoCs (Indicators of Compromise)

Provide a concise summary relevant to SOC analysis.
"""
            
            response = self.gemini_client.models.generate_content(
                model='gemini-3-flash-preview',
                contents=search_prompt
            )
            
            return response.text
        except Exception as e:
            return f"Internet search failed: {str(e)}"

    async def get_available_files_context(self) -> str:
        """Get context about available files"""
        try:
            buckets_result = await self.session.call_tool("list_buckets", {})
            buckets_text = buckets_result.content[0].text
            
            if "Error" in buckets_text or "No buckets" in buckets_text:
                return "No accessible buckets found."
            
            # Get files from first bucket (simplified)
            bucket_lines = buckets_text.split('\\n')
            first_bucket = None
            for line in bucket_lines:
                if line.strip() and not line.startswith("Error") and not line.startswith("No"):
                    first_bucket = line.strip()
                    break
            
            if first_bucket:
                try:
                    logs_result = await self.session.call_tool("list_logs", {"bucket_name": first_bucket})
                    return f"Buckets: {buckets_text}\\n\\nFiles in {first_bucket}:\\n{logs_result.content[0].text}"
                except:
                    return f"Buckets: {buckets_text}\\n\\n(Unable to list files)"
            
            return buckets_text
            
        except Exception as e:
            return f"Unable to get file context: {str(e)}"

async def run_conversational_soc_client():
    server_script = os.path.join(os.path.dirname(__file__), "server.py")
    
    print(f"🔌 Connecting to MCP Server: {server_script}...")
    print("🤖 Conversational SOC Assistant starting...")

    server_params = StdioServerParameters(
        command="python",
        args=[server_script],
        env=os.environ.copy()
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # Print the Event Mill banner
            print_banner()
            
            # Initialize Event Mill assistant
            assistant = EventMillAssistant(session)
            
            print(f"{Colors.GREEN}✅ Connected to Event Store{Colors.RESET}")
            print()
            print(f"{Colors.CYAN}📋 Quick Commands:{Colors.RESET}")
            print(f"   {Colors.WHITE}buckets{Colors.RESET}              - List event stores")
            print(f"   {Colors.WHITE}ls{Colors.RESET} [path]           - Browse logs")
            print(f"   {Colors.WHITE}scan{Colors.RESET} <file>         - AI pattern analysis")
            print(f"   {Colors.WHITE}templates{Colors.RESET} <file>    - Generate GROK templates")
            print(f"   {Colors.WHITE}patterns{Colors.RESET}            - Show GROK/OTel reference")
            print()
            print(f"{Colors.YELLOW}🤖 Or use natural language:{Colors.RESET} {Colors.DIM}'show me top talkers'{Colors.RESET}")
            print(f"{Colors.DIM}Type 'help' for full command list, 'exit' to quit{Colors.RESET}")
            print(f"{Colors.BLUE}{'═'*60}{Colors.RESET}")
            
            while True:
                try:
                    user_input = input(f"\n{Colors.CYAN}⚙ mill>{Colors.RESET} ").strip()
                    if not user_input:
                        continue
                    if user_input.lower() == "exit":
                        break
                    if user_input.lower() == "help":
                        print_help()
                        continue
                    
                    # Check if it's a direct command
                    if await handle_direct_command(session, user_input):
                        continue
                    
                    # Otherwise, treat as conversational request
                    print(f"{Colors.YELLOW}⚙ Grinding...{Colors.RESET}")
                    response = await assistant.process_analyst_request(user_input)
                    
                    print(f"\n{Colors.BLUE}{'═'*60}{Colors.RESET}")
                    print(f"{Colors.GREEN}⚙ Mill Output:{Colors.RESET}")
                    print(response)
                    print(f"{Colors.BLUE}{'═'*60}{Colors.RESET}")
                    
                except KeyboardInterrupt:
                    print("\n👋 Goodbye!")
                    break
                except Exception as e:
                    print(f"❌ Error: {e}")

async def handle_direct_command(session: ClientSession, user_input: str) -> bool:
    """Handle direct commands like the original client"""
    
    parts = user_input.split()
    if not parts:
        return False
    
    cmd_name = parts[0].lower()
    
    # Helper to call a tool safely
    async def call_soc_tool(name, args):
        print(f"\n[Calling {name} with {args}...] ⏳")
        try:
            result = await session.call_tool(name, arguments=args)
            text = result.content[0].text
            print(f"\n📄 RESULT:\n{text}")
            return True
        except Exception as e:
            print(f"❌ Error: {e}")
            return False
    
    if cmd_name == "buckets":
        await call_soc_tool("list_buckets", {})
        return True
        
    elif cmd_name == "ls":
        # usage: ls [path]
        full_path = parts[1] if len(parts) > 1 else ""
        bucket = full_path
        prefix = ""
        
        if "/" in full_path:
            parts_path = full_path.split("/", 1)
            bucket = parts_path[0]
            prefix = parts_path[1]
        
        await call_soc_tool("list_logs", {"bucket_name": bucket, "prefix": prefix})
        return True
        
    elif cmd_name == "read":
        # usage: read <filename> [bucket]
        if len(parts) < 2:
            print("Usage: read <filename> [bucket]")
            return True
        file_name = parts[1]
        bucket = parts[2] if len(parts) > 2 else ""
        await call_soc_tool("read_log_segment", {"file_name": file_name, "bucket_name": bucket})
        return True
        
    elif cmd_name == "meta":
        # usage: meta <filename> [bucket]
        if len(parts) < 2:
            print("Usage: meta <filename> [bucket]")
            return True
        file_name = parts[1]
        bucket = parts[2] if len(parts) > 2 else ""
        await call_soc_tool("get_log_metadata", {"file_name": file_name, "bucket_name": bucket})
        return True
        
    elif cmd_name == "search":
        # usage: search <query> <filename> [bucket]
        if len(parts) < 3:
            print("Usage: search <query> <filename> [bucket]")
            return True
        query = parts[1]
        file_name = parts[2]
        bucket = parts[3] if len(parts) > 3 else ""
        await call_soc_tool("search_log", {"file_name": file_name, "query": query, "bucket_name": bucket})
        return True

    elif cmd_name == "analyze":
        # usage: analyze <GROK_PATTERN> <filename> [bucket] [--full]
        # User-friendly GROK pattern mode (e.g., IP, HTTPSTATUS, LOGLEVEL)
        if len(parts) < 3:
            print("Usage: analyze <GROK_PATTERN> <filename> [bucket] [--full]")
            print("  GROK patterns: IP, IPV4, IPV6, MAC, EMAIL, UUID, HTTPSTATUS,")
            print("                 HTTPMETHOD, LOGLEVEL, USER, PORT, PATH, TIMESTAMP")
            print("  For custom regex, use: analyze_rex <regex> <filename> [bucket] [--full]")
            return True
        grok_pattern = parts[1]
        file_name = parts[2]
        # Filter out --full from bucket detection
        remaining = [p for p in parts[3:] if p != "--full"]
        bucket = remaining[0] if remaining else ""
        full_log = "--full" in parts
        await call_soc_tool("analyze_log_grok", {"file_name": file_name, "grok_pattern": grok_pattern, "bucket_name": bucket, "full_log": full_log})
        return True

    elif cmd_name == "analyze_rex":
        # usage: analyze_rex <regex_pattern> <filename> [bucket] [--full]
        # Expert mode with raw regex patterns
        if len(parts) < 3:
            print("Usage: analyze_rex <regex_pattern> <filename> [bucket] [--full]")
            print("  Example: analyze_rex \"(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\" access.log")
            return True
        pattern = parts[1]
        file_name = parts[2]
        # Filter out --full from bucket detection
        remaining = [p for p in parts[3:] if p != "--full"]
        bucket = remaining[0] if remaining else ""
        full_log = "--full" in parts
        await call_soc_tool("analyze_log_regex", {"file_name": file_name, "pattern": pattern, "bucket_name": bucket, "full_log": full_log})
        return True

    elif cmd_name == "scan":
        # usage: scan <filename> [bucket] [--full]
        if len(parts) < 2:
            print("Usage: scan <filename> [bucket] [--full]")
            return True
        file_name = parts[1]
        bucket = parts[2] if len(parts) > 2 and parts[2] != "--full" else ""
        full_log = "--full" in parts
        await call_soc_tool("discover_log_patterns", {"file_name": file_name, "bucket_name": bucket, "full_log": full_log})
        return True

    elif cmd_name == "investigate":
        # usage: investigate <search_term> <filename> [bucket] [--full]
        # AI-powered investigation with threat intelligence
        if len(parts) < 3:
            print("Usage: investigate <search_term> <filename> [bucket] [--full]")
            print("  AI-powered investigation with threat intelligence context")
            print("  Example: investigate 192.168.1.100 access.log mybucket")
            return True
        search_term = parts[1]
        file_name = parts[2]
        # Filter out --full from bucket detection
        remaining = [p for p in parts[3:] if p != "--full"]
        bucket = remaining[0] if remaining else ""
        full_log = "--full" in parts
        await call_soc_tool("investigate_log", {"file_name": file_name, "search_term": search_term, "bucket_name": bucket, "full_log": full_log})
        return True

    elif cmd_name == "templates":
        # usage: templates <filename> [bucket] [--grok]
        if len(parts) < 2:
            print("Usage: templates <filename> [bucket] [--grok]")
            return True
        file_name = parts[1]
        bucket = parts[2] if len(parts) > 2 and parts[2] != "--grok" else ""
        output_format = "grok" if "--grok" in parts else "json"
        await call_soc_tool("generate_pattern_templates", {"file_name": file_name, "bucket_name": bucket, "output_format": output_format})
        return True

    elif cmd_name == "patterns":
        # usage: patterns (shows available GROK patterns and OpenTelemetry mappings)
        await call_soc_tool("get_parsing_patterns", {})
        return True

    elif cmd_name == "patterns_custom":
        # usage: patterns_custom (shows custom GROK patterns for analyze command)
        print(f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}")
        print(f"{Colors.WHITE}{Colors.BOLD}GROK PATTERNS FOR ANALYZE COMMAND{Colors.RESET}")
        print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")
        
        # Import patterns from server
        try:
            from server import BUILTIN_GROK_PATTERNS, ANALYZE_GROK_PATTERNS
            
            print(f"\n{Colors.GREEN}📦 Built-in Patterns ({len(BUILTIN_GROK_PATTERNS)}):{Colors.RESET}")
            for name in sorted(BUILTIN_GROK_PATTERNS.keys()):
                print(f"   {Colors.WHITE}{name}{Colors.RESET}")
            
            # Check for custom patterns
            custom_count = len(ANALYZE_GROK_PATTERNS) - len(BUILTIN_GROK_PATTERNS)
            if custom_count > 0:
                print(f"\n{Colors.YELLOW}🔧 Custom Patterns ({custom_count}):{Colors.RESET}")
                for name in sorted(ANALYZE_GROK_PATTERNS.keys()):
                    if name not in BUILTIN_GROK_PATTERNS:
                        regex = ANALYZE_GROK_PATTERNS[name]
                        print(f"   {Colors.WHITE}{name}{Colors.RESET}: {Colors.DIM}{regex}{Colors.RESET}")
            else:
                print(f"\n{Colors.DIM}No custom patterns defined.{Colors.RESET}")
                print(f"{Colors.DIM}Edit custom_patterns.py to add your own patterns.{Colors.RESET}")
            
            print(f"\n{Colors.BLUE}Usage:{Colors.RESET} analyze <PATTERN_NAME> <file> [bucket] [--full]")
            print(f"{Colors.DIM}See custom_patterns.py for adding organization-specific patterns.{Colors.RESET}")
            
        except ImportError as e:
            print(f"{Colors.RED}Error loading patterns: {e}{Colors.RESET}")
        
        print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")
        return True

    # =========================================================================
    # THREAT MODELING COMMANDS
    # =========================================================================
    
    elif cmd_name == "threat_intel":
        # usage: threat_intel [list|clear]
        subcommand = parts[1] if len(parts) > 1 else "list"
        if subcommand == "list":
            await call_soc_tool("list_threat_intel_context", {})
        elif subcommand == "clear":
            doc_id = parts[2] if len(parts) > 2 else ""
            await call_soc_tool("clear_threat_intel_context", {"document_id": doc_id})
        else:
            print("Usage: threat_intel [list|clear] [document_id]")
        return True

    elif cmd_name == "load_pdf":
        # usage: load_pdf <file_path> [document_name] [--gcs]
        if len(parts) < 2:
            print("Usage: load_pdf <blob_path> [document_name] [--gcs]")
            print("  Load a threat intel PDF as context for threat model analysis")
            print("  --gcs: Load from GCS bucket (uses GCS_LOG_BUCKET)")
            print("")
            print("  Examples:")
            print("    load_pdf /local/path/to/report.pdf")
            print("    load_pdf threatintel/m-trends-2025.pdf --gcs")
            print("    load_pdf threatintel/report.pdf \"Mandiant Report\" --gcs")
            return True
        file_path = parts[1]
        from_gcs = "--gcs" in parts
        # Filter out --gcs and True/False that might follow it
        remaining = [p for p in parts[2:] if p.lower() not in ("--gcs", "true", "false")]
        doc_name = remaining[0] if remaining else ""
        await call_soc_tool("load_threat_intel_pdf", {
            "file_path": file_path,
            "document_name": doc_name,
            "from_gcs": from_gcs
        })
        return True

    elif cmd_name == "threat_model":
        # usage: threat_model <file_path> [source_type] [--gcs] OR threat_model --text "<content>"
        if len(parts) < 2:
            print("Usage: threat_model <pdf_path> [source_type] [--gcs]")
            print("       threat_model --text \"<document_content>\" [source_type]")
            print("")
            print("  Analyze a threat model document to extract attack paths and controls")
            print("  source_type: threat_model, security_assessment, red_team_report")
            print("")
            print("  Examples:")
            print("    threat_model /path/to/threat-model.pdf")
            print("    threat_model threatmodels/app-threat-model.pdf --gcs")
            print("    threat_model --text \"Attack scenario: adversary gains access via...\"")
            print("")
            print("  Tip: Load threat intel PDFs first with 'load_pdf' for context")
            return True
        
        # Check if using --text mode for raw text input
        if parts[1] == "--text":
            doc_content = " ".join(parts[2:])
            await call_soc_tool("analyze_threat_model", {"document_content": doc_content})
        else:
            # PDF mode
            file_path = parts[1]
            from_gcs = "--gcs" in parts
            # Filter out --gcs and True/False
            remaining = [p for p in parts[2:] if p.lower() not in ("--gcs", "true", "false")]
            source_type = remaining[0] if remaining else "threat_model"
            await call_soc_tool("analyze_threat_model_pdf", {
                "file_path": file_path,
                "source_type": source_type,
                "from_gcs": from_gcs
            })
        return True

    elif cmd_name == "tabletop":
        # usage: tabletop <minutes_content> [exercise_name]
        if len(parts) < 2:
            print("Usage: tabletop \"<minutes_content>\" [exercise_name]")
            print("  Analyze tabletop exercise minutes for attack scenarios and control gaps")
            return True
        minutes_content = " ".join(parts[1:])
        await call_soc_tool("analyze_tabletop_minutes", {"minutes_content": minutes_content})
        return True

    elif cmd_name == "scenarios":
        # usage: scenarios [list|gaps <id>|export <id> [path]]
        subcommand = parts[1] if len(parts) > 1 else "list"
        if subcommand == "list":
            await call_soc_tool("list_threat_scenarios", {})
        elif subcommand == "gaps" and len(parts) > 2:
            await call_soc_tool("get_scenario_gaps", {"scenario_id": parts[2]})
        elif subcommand == "export" and len(parts) > 2:
            scenario_id = parts[2]
            output_path = parts[3] if len(parts) > 3 else ""
            await call_soc_tool("export_threat_scenario", {"scenario_id": scenario_id, "output_path": output_path})
        else:
            print("Usage: scenarios [list|gaps <id>|export <id> [path]]")
        return True

    elif cmd_name == "create_scenario":
        # usage: create_scenario <name> <description>
        if len(parts) < 3:
            print("Usage: create_scenario \"<name>\" \"<description>\"")
            print("  Create a new threat scenario for tracking attack paths")
            return True
        name = parts[1]
        description = " ".join(parts[2:])
        await call_soc_tool("create_threat_scenario", {"name": name, "description": description})
        return True
    
    return False  # Not a direct command

def print_help():
    """Print help information"""
    print(f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}")
    print(f"{Colors.WHITE}{Colors.BOLD}EVENT MILL - Command Reference{Colors.RESET}")
    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")
    
    print(f"\n{Colors.GREEN}📂 Navigation:{Colors.RESET}")
    print(f"   {Colors.WHITE}buckets{Colors.RESET}                        List available event stores")
    print(f"   {Colors.WHITE}ls{Colors.RESET} [bucket/prefix]             Browse logs in bucket or folder")
    print(f"   {Colors.WHITE}read{Colors.RESET} <file> [bucket]           Read log content (first 100 lines)")
    print(f"   {Colors.WHITE}meta{Colors.RESET} <file> [bucket]           Get file metadata")
    
    print(f"\n{Colors.YELLOW}🔍 Analysis:{Colors.RESET}")
    print(f"   {Colors.WHITE}search{Colors.RESET} <query> <file> [bucket]     Search for text in log file")
    print(f"   {Colors.WHITE}analyze{Colors.RESET} <GROK> <file> [bucket] [--full]  Extract using GROK patterns")
    print(f"   {Colors.DIM}   → Patterns: IP, HTTPSTATUS, LOGLEVEL, USER, UUID, PATH, etc.{Colors.RESET}")
    print(f"   {Colors.WHITE}analyze_rex{Colors.RESET} <regex> <file> [bucket] [--full]  Expert regex mode")
    print(f"   {Colors.DIM}   → Both include 3 sample records per match for context{Colors.RESET}")
    print(f"   {Colors.WHITE}scan{Colors.RESET} <file> [bucket] [--full]      AI-powered pattern discovery")
    
    print(f"\n{Colors.RED}🔎 Investigation (AI + Threat Intel):{Colors.RESET}")
    print(f"   {Colors.WHITE}investigate{Colors.RESET} <term> <file> [bucket] [--full]  Deep-dive analysis")
    print(f"   {Colors.DIM}   → AI-powered threat assessment with MITRE ATT&CK context{Colors.RESET}")
    print(f"   {Colors.DIM}   → Severity rating, IoCs, and recommended actions{Colors.RESET}")
    
    print(f"\n{Colors.MAGENTA}⚙ Detection Engineering:{Colors.RESET}")
    print(f"   {Colors.WHITE}templates{Colors.RESET} <file> [bucket] [--grok]  Generate GROK parsing templates")
    print(f"   {Colors.WHITE}patterns{Colors.RESET}                           Show GROK patterns & OTel mappings")
    print(f"   {Colors.WHITE}patterns_custom{Colors.RESET}                    List all analyze GROK patterns")
    print(f"   {Colors.DIM}   → Edit custom_patterns.py to add organization-specific patterns{Colors.RESET}")
    print(f"   {Colors.DIM}   → 20 ECS event categories (authentication, network, file, etc.){Colors.RESET}")
    print(f"   {Colors.DIM}   → OpenTelemetry semantic conventions for observability{Colors.RESET}")
    
    print(f"\n{Colors.RED}🎯 Threat Modeling & Attack Paths:{Colors.RESET}")
    print(f"   {Colors.WHITE}load_pdf{Colors.RESET} <path> [name] [--gcs]     Load threat intel PDF as context")
    print(f"   {Colors.WHITE}threat_intel{Colors.RESET} [list|clear]          Manage loaded threat intel context")
    print(f"   {Colors.WHITE}threat_model{Colors.RESET} <pdf> [type] [--gcs]  Analyze threat model PDF")
    print(f"   {Colors.WHITE}threat_model{Colors.RESET} --text \"<content>\"    Analyze threat model text")
    print(f"   {Colors.WHITE}tabletop{Colors.RESET} \"<minutes>\"               Analyze tabletop exercise minutes")
    print(f"   {Colors.WHITE}scenarios{Colors.RESET} [list|gaps|export]       Manage threat scenarios")
    print(f"   {Colors.WHITE}create_scenario{Colors.RESET} \"<name>\" \"<desc>\"  Create new threat scenario")
    print(f"   {Colors.DIM}   → Extract security controls that must be bypassed{Colors.RESET}")
    print(f"   {Colors.DIM}   → Map attack sequence events to defense-in-depth layers{Colors.RESET}")
    print(f"   {Colors.DIM}   → Identify gaps and weakest points in attack chain{Colors.RESET}")
    print(f"   {Colors.DIM}   → Export to markdown with control coverage matrix{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}🤖 Natural Language (AI-Powered):{Colors.RESET}")
    print(f"   {Colors.DIM}'Show me the top talkers from the web server logs'{Colors.RESET}")
    print(f"   {Colors.DIM}'Investigate suspicious activity from IP 192.168.1.100'{Colors.RESET}")
    print(f"   {Colors.DIM}'Find all authentication failures in the auth logs'{Colors.RESET}")
    print(f"   {Colors.DIM}'What are the most common HTTP 4xx errors?'{Colors.RESET}")
    print(f"   {Colors.DIM}'Generate parsing templates for this firewall log'{Colors.RESET}")
    
    print(f"\n{Colors.BLUE}💡 Examples:{Colors.RESET}")
    print(f"   {Colors.CYAN}⚙ mill>{Colors.RESET} buckets")
    print(f"   {Colors.CYAN}⚙ mill>{Colors.RESET} ls my-log-bucket/nginx")
    print(f"   {Colors.CYAN}⚙ mill>{Colors.RESET} scan access.log my-log-bucket")
    print(f"   {Colors.CYAN}⚙ mill>{Colors.RESET} templates access.log my-log-bucket --grok")
    print(f"   {Colors.CYAN}⚙ mill>{Colors.RESET} load_pdf /path/to/mandiant-report.pdf")
    print(f"   {Colors.CYAN}⚙ mill>{Colors.RESET} scenarios gaps TS-0001")
    print(f"   {Colors.CYAN}⚙ mill>{Colors.RESET} show me top talkers from access.log")
    
    print(f"\n{Colors.DIM}Type 'exit' to quit | Logs are read-only (exported data){Colors.RESET}")
    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")

if __name__ == "__main__":
    try:
        asyncio.run(run_conversational_soc_client())
    except KeyboardInterrupt:
        print("\\n👋 Goodbye!")
