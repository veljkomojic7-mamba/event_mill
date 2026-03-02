# constraints.md
## Eventmill Attack Path Tools — Constraints, Guardrails, and Stage Catalog Usage

**Catalog version:** stage-catalog-1.0  
**Generated (UTC):** 2026-03-02T01:33:40Z

---

## 1. Purpose

This document defines non-negotiable constraints for Eventmill’s attack-path modeling tools.

It establishes:
- Safety and content boundaries for the LLM assistant
- Deterministic responsibilities vs LLM responsibilities
- How the stage catalog is used (and what is explicitly *not* embedded in LLM context)
- How MITRE ATT&CK traceability is provided without importing the full taxonomy into prompts

---

## 2. Determinism Boundary

### 2.1 Deterministic (code-enforced)
The application code must:
- Select the applicable stage(s) from the stage catalog
- Determine required/optional/not_applicable stages per attack type
- Validate analyst-provided control fragments using the strict 2020-12 schema
- Compute PreventionScore, DetectionScore, CompositeScore and ordinal ratings
- Apply weighting: prevention = 0.62, detection = 0.38
- Decide feasibility gates (e.g., infeasible / constrained / feasible thresholds)
- Maintain an audit record of inputs, outputs, and any evidence references

### 2.2 LLM-assisted (constrained)
The LLM assistant may:
- Propose *high-level* candidate procedure categories for a stage (no operational steps)
- Ask targeted clarification questions to obtain missing control facts
- Summarize why a stage is feasible or constrained based on deterministic outputs
- Suggest *defensive* control improvements in qualitative terms (no vendor sales pitch)

The LLM assistant must **not**:
- Assign control strength scores or modify deterministic scores
- Override analyst-provided control state
- Invent stages outside the stage catalog
- Provide weaponized exploitation instructions, payloads, commands, or evasion playbooks

---

## 3. Stage Catalog Usage

### 3.1 Minimal stable catalog
Eventmill uses a minimal stage catalog (`stage_catalog.json`) that:
- Defines 12 stable stages (aligned to ATT&CK tactic concepts)
- Defines scope-in / scope-out boundaries for each stage
- Includes MITRE tactic IDs and official URLs for traceability

This catalog is intended to be stable and version-controlled, changing rarely.

### 3.2 MITRE technique-level detail is not embedded
The full MITRE ATT&CK / ATT&CK for ICS technique taxonomy is **not** placed in LLM context.

Reasons:
- The taxonomy is large and would consume context window
- The taxonomy is periodically updated (version drift risk)
- Technique-level detail is only needed on demand (reporting, traceability, detection mapping)

### 3.3 On-demand taxonomy resolution
When detailed MITRE mapping is required, the application must call a separate deterministic tool:
- `mitre_reference_tool` (interface defined separately)

This tool is expected to query a **local mirror** of MITRE data (STIX/JSON), producing:
- Tactic/technique metadata
- IDs and URLs
- Version and source references

---

## 4. Safety Guardrails

### 4.1 Prohibited outputs
The assistant must not output:
- Exploit code or payloads
- Step-by-step instructions to compromise systems
- Command sequences for scanning, exploitation, credential theft, or exfiltration
- Evasion tactics described at an operational level
- Any instructions that meaningfully enable wrongdoing

### 4.2 Allowed abstraction level
The assistant may discuss:
- Procedure categories (e.g., “phishing”, “valid accounts”, “public-facing app exploit”) **without instructions**
- Preconditions and dependencies (e.g., “requires an internet-facing login and absence of phishing-resistant MFA”)
- Defensive telemetry and control considerations at a conceptual level

---

## 5. Sparse Control Submission Rules

Control input must:
- Validate against the strict 2020-12 schema
- Allow sparse submissions (only controls relevant to the stage need to be provided)

Missing relevant controls must be handled by application logic:
- Treat as `unknown` (default)
- Reduce confidence
- Trigger targeted analyst questions
- Never fail validation solely due to omission

---

## 6. Explainability and Traceability

For every stage evaluation, outputs must be explainable:
- What stage was evaluated
- Which controls were considered relevant
- Which controls constrained feasibility (qualitative narrative)
- What evidence references were supplied (if any)
- What MITRE tactic ID/URL applies (for traceability)
- What MITRE version applies (when resolved via mitre_reference_tool)

---

## 7. Files

- `stage_catalog.json` — minimal stage definitions and MITRE tactic references
- `prevention-controls-minimal-2020-12.json` — strict schema for sparse prevention control submissions
- `role.md` — LLM assistant role definition (behavioral constraints)
- `mitre_reference_tool_interface.md` — on-demand MITRE lookup tool interface definition

---
