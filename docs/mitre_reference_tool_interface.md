# mitre_reference_tool_interface.md
## Eventmill — MITRE Reference Tool Interface (On-Demand)

---

## 1. Purpose

This document specifies a deterministic tool interface for retrieving **current** MITRE ATT&CK / ATT&CK for ICS taxonomy data on demand.

The tool exists to:
- Avoid embedding the full MITRE taxonomy in LLM context (context efficiency + safety)
- Eliminate version drift by querying a local, versioned mirror
- Provide citation-grade traceability (IDs, URLs, and source metadata)

This tool is not responsible for scoring. It only resolves authoritative reference data.

---

## 2. Data Source Requirements

The implementation should support loading a **local mirror** of MITRE data, such as:
- MITRE ATT&CK STIX bundles (recommended)
- JSON exports derived from official sources

Recommended upstream source for mirroring:
- MITRE ATT&CK STIX Data repository (attack-stix-data)

The local mirror must record:
- framework: enterprise | ics
- version or snapshot timestamp
- source origin (URL or repository commit/tag)

---

## 3. Core Concepts

### 3.1 Frameworks
- `enterprise` → MITRE ATT&CK Enterprise
- `ics` → MITRE ATT&CK for ICS

### 3.2 Entities
- **Tactic** (e.g., TA0001) — high-level adversary objective
- **Technique** (e.g., T1059) — method used to achieve a tactic
- **Sub-technique** (e.g., T1059.001) — specific technique variant

---

## 4. Tool API (Proposed)

The tool can be implemented as an internal library module, CLI command, or MCP tool. The interface below is presented in a language-agnostic form.

### 4.1 `get_dataset_info()`
Returns metadata about the loaded local dataset(s).

**Inputs:** none

**Outputs:**
```json
{
  "datasets": [
    {
      "framework": "enterprise",
      "source": "local_mirror",
      "version": "vX.Y or snapshot",
      "updated_utc": "YYYY-MM-DDTHH:MM:SSZ",
      "origin": {
        "type": "git",
        "repo": "attack-stix-data",
        "ref": "tag/commit"
      }
    }
  ]
}
```

---

### 4.2 `lookup_tactic(tactic_id, framework="enterprise")`
Returns tactic metadata and citation information.

**Inputs:**
- `tactic_id`: string (e.g., "TA0001")
- `framework`: "enterprise" | "ics"

**Outputs:**
```json
{
  "tactic_id": "TA0001",
  "name": "Initial Access",
  "description": "…",
  "url": "https://attack.mitre.org/tactics/TA0001/",
  "framework": "enterprise",
  "citations": [
    { "type": "url", "ref": "https://attack.mitre.org/tactics/TA0001/" }
  ],
  "dataset": { "framework": "enterprise", "version": "…" }
}
```

---

### 4.3 `list_tactics(framework="enterprise")`
Returns all tactics in the selected framework.

**Outputs:**
```json
{
  "framework": "enterprise",
  "tactics": [
    { "tactic_id": "TA0001", "name": "Initial Access", "url": "…" }
  ],
  "dataset": { "framework": "enterprise", "version": "…" }
}
```

---

### 4.4 `lookup_technique(technique_id, framework="enterprise")`
Returns technique or sub-technique metadata with traceability.

**Inputs:**
- `technique_id`: string (e.g., "T1059" or "T1059.001")
- `framework`: "enterprise" | "ics"

**Outputs:**
```json
{
  "technique_id": "T1059",
  "name": "Command and Scripting Interpreter",
  "description": "…",
  "tactics": [
    { "tactic_id": "TA0002", "name": "Execution" }
  ],
  "url": "https://attack.mitre.org/techniques/T1059/",
  "framework": "enterprise",
  "data_sources": ["…"],
  "mitigations": [
    { "mitigation_id": "Mxxxx", "name": "…", "url": "…" }
  ],
  "citations": [
    { "type": "url", "ref": "https://attack.mitre.org/techniques/T1059/" }
  ],
  "dataset": { "framework": "enterprise", "version": "…" }
}
```

---

### 4.5 `list_techniques_for_tactic(tactic_id, framework="enterprise")`
Returns techniques associated with a tactic.

**Outputs:**
```json
{
  "tactic_id": "TA0001",
  "framework": "enterprise",
  "techniques": [
    { "technique_id": "T1566", "name": "Phishing", "url": "…" }
  ],
  "dataset": { "framework": "enterprise", "version": "…" }
}
```

---

### 4.6 `search(query, entity_types=["tactic","technique"], framework="enterprise")`
Searches by name/description.

**Outputs:**
```json
{
  "query": "phish",
  "framework": "enterprise",
  "results": [
    {
      "entity_type": "technique",
      "id": "T1566",
      "name": "Phishing",
      "url": "https://attack.mitre.org/techniques/T1566/"
    }
  ],
  "dataset": { "framework": "enterprise", "version": "…" }
}
```

---

## 5. Deterministic Behavior Requirements

- No LLM calls inside this tool.
- Results must be derived only from the local dataset(s).
- All outputs must include dataset version/snapshot metadata.
- If an ID is not found, return a structured “not found” response (no guessing).

---

## 6. Integration Guidance

Eventmill should:
- Keep `stage_catalog.json` minimal and stable (tactic ID + URL only)
- Call this tool only when technique-level traceability is required
- Store the dataset version in any exported report that includes MITRE references

---
