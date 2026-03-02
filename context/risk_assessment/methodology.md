# Attack Path Generation & Control Strength Evaluation

**Eventmill – Stage-Constrained Analyst-Assisted Modeling**

---

## 1. Purpose

This methodology defines how the Attack Path tools within Eventmill:

- Assist analysts in evaluating how a specific threat would manifest technically.
- Generate plausible attacker options for each stage of an attack chain.
- Assess control strength per stage using structured prevention and detection inputs.
- Identify the weakest stage(s) in the chain.
- Recommend minimal control improvements that materially reduce risk.

This document is intended to guide refactoring and extension of the existing `risk_assessment.py` tool and related components.

---

## 2. Design Principles

### 2.1 Determinism Boundary

The system must separate:

**Deterministic (Code-Enforced)**

- Stage catalog (MITRE ICS aligned)
- Stage relevance by attack type
- Control strength scoring (prevention 0.62 / detection 0.38)
- Ordinal mapping (`none` | `low` | `medium` | `high`)
- Stage transition logic
- Missing control handling rules

**LLM-Assisted (Constrained)**

- Candidate stage procedures
- Analyst clarification questions
- Narrative justification
- Control improvement suggestions (based on deterministic deltas)

**The LLM must not:**

- Directly assign control strength scores.
- Override analyst-provided control states.
- Invent attack stages not present in the catalog.

---

## 3. High-Level Workflow

### 3.1 Inputs

For a given threat scenario:

**Threat Model Context**
- Business objectives
- Critical assets
- Adversary intent

**Organization-Specific Threat Intelligence**
- Known targeting patterns
- Observed TTPs
- Sector-relevant threats

**System Context**
- Architecture summary
- Identity model
- Network boundaries
- SaaS and cloud posture

**Analyst-Provided Control Fragments**
- Sparse JSON conforming to 2020-12 prevention schema

### 3.2 Core Loop (Per Stage)

For each stage:

1. LLM proposes candidate procedures constrained to the stage.
2. System identifies relevant prevention and detection control domains.
3. Analyst provides control state (sparse submission allowed).
4. System validates input against strict 2020-12 schema.
5. Deterministic scoring computes:
   - `PreventionScore`
   - `DetectionScore`
   - `CompositeScore`
   - `OrdinalRating`
6. System determines:
   - Is the stage feasible?
   - What attacker options remain plausible?

**Loop continues until:**
- Objective reached
- Feasibility collapses
- Risk acceptable

---

## 4. Attack Stage Model

Stages align with the existing MITRE ICS enumeration in `risk_assessment.py`:

1. Initial Access
2. Execution
3. Persistence
4. Privilege Escalation
5. Defense Evasion
6. Credential Access
7. Discovery
8. Lateral Movement
9. Collection
10. Command and Control
11. Exfiltration
12. Impact / Action on Objective

Attack types define `required` / `optional` / `not_applicable` stages (already implemented in code).

**This mapping must remain deterministic.**

---

## 5. Prevention & Detection Evaluation Model

### 5.1 Prevention Weighting

```
CompositeScore = (PreventionScore × 0.62) + (DetectionScore × 0.38)
```

- `PreventionScore` is derived from relevant control domains only.

**Control domains not relevant to the stage:**
- Are ignored.
- Are not penalized.

**Controls not provided:**
- Treated as unknown.
- Do not invalidate submission.
- Reduce confidence level but do not fail validation.

### 5.2 Prevention Control Schema (2020-12)

The application uses a JSON Schema (`prevention_control_2020-12.json`) to ensure normalized input when control strength must be assessed. This schema enforces consistent structure while allowing sparse submissions.

**Schema Location:** `tools/prevention_control_2020-12.json`

**Schema ID:** `https://eventmill.local/schemas/prevention-controls-minimal-2020-12.json`

#### Control Groups

The schema defines 11 prevention control groups:

| Control Group | Controls |
|---------------|----------|
| `authentication_controls` | `pwd_static`, `pwd_dynamic`, `mfa`, `attribute_constraints` |
| `identity_hygiene` | `legacy_auth_disabled`, `password_spray_resistance`, `guest_and_external_access`, `service_account_governance` |
| `authorization_controls` | `rbac_least_privilege`, `persistent_admin_roles`, `privilege_escalation_controls` |
| `network_and_access_surface_constraints` | `logical_access_constraint`, `network_segmentation`, `edge_protection` |
| `endpoint_and_execution_controls` | `process_access_constraint`, `endpoint_baseline_hardening` |
| `data_access_controls` | `data_access_constraint`, `secrets_management` |
| `runtime_and_platform_constraints` | `specialized_runtime`, `platform_guardrails` |
| `vulnerability_and_change_management` | `vulnerability_management`, `patch_management` |
| `email_security_controls` | `secure_email_gateway`, `email_domain_controls` |
| `cloud_and_saas_guardrails` | `cloud_posture_controls`, `saas_controls` |
| `backup_and_resilience_constraints` | `backup_resilience` |

#### Control State Values

Each control uses normalized enumerated values:

**State** (`required`):
- `absent` - Control not implemented
- `partial` - Control partially implemented
- `present` - Control fully implemented
- `unknown` - Control state not assessed

**Scope** (`optional`):
- `all` - Applies to all relevant assets
- `most` - Applies to most assets
- `some` - Applies to some assets
- `few` - Applies to few assets
- `unknown` - Scope not assessed

#### Evidence Tracking

Each control optionally includes evidence:

```json
{
  "state": "present",
  "scope": "most",
  "evidence": [
    {
      "type": "penetration_test",
      "ref": "PT-2024-Q3-001",
      "note": "Validated MFA bypass resistance",
      "timestamp": "2024-09-15T00:00:00Z"
    }
  ]
}
```

#### Sparse Submission Rules

The 2020-12 schema:

- Validates structure and allowed values.
- Does **NOT** require all control domains.
- Allows per-stage minimal control fragments.
- Application logic determines relevance, not the schema.

### 5.3 Stage-Relevant Control Mapping

Each stage maps to relevant prevention domains.

**Example:**

| Stage | Relevant Control Domains |
|-------|--------------------------|
| **Initial Access** | `authentication_controls`, `email_security_controls`, `edge_protection`, `vulnerability_management`, `network_access_constraints` |
| **Lateral Movement** | `network_segmentation`, `authorization_controls`, `endpoint_execution_controls` |
| **Exfiltration** | `data_access_controls`, `network_segmentation`, `cloud_guardrails` |

**This mapping is deterministic and must be codified in the engine.**

---

## 6. Stage Evaluation Object

Each evaluated stage produces:

```json
{
    "stage_id": "",
    "candidate_procedures": [],
    "prevention_score": 0.0,
    "detection_score": 0.0,
    "composite_score": 0.0,
    "ordinal_rating": "",
    "feasible": true,
    "relevant_controls": [],
    "missing_relevant_controls": [],
    "rationale_summary": ""
}
```

This replaces narrative-only extraction with structured evaluation.

---

## 7. Weakest-Link Identification

After evaluating all feasible paths:

1. Identify stage(s) with lowest `composite_score`.
2. Identify stages appearing in multiple plausible paths.
3. Prioritize controls whose improvement:
   - Increases `composite_score` above threshold.
   - Affects multiple stages.

**This is the Pareto risk reduction mechanism.**

---

## 8. Control Improvement Simulation

For each relevant control:

1. Simulate state change (e.g., `absent` → `present`).
2. Recalculate stage `composite_score`.
3. Compute delta.

**Output:**

```json
{
    "control_name": "",
    "current_state": "",
    "proposed_state": "",
    "score_delta": 0.0,
    "affected_stages": []
}
```

- LLM may narratively explain benefits.
- Code determines numeric delta.

---

## 9. Confidence Model

Confidence per stage is influenced by:

- Percentage of relevant controls assessed
- Evidence basis strength (`tested` > `benchmark` > `vendor_claim` > `assumption`)
- Assumption density

**Confidence is separate from feasibility.**

---

## 10. Guardrails

The system must:

- **Never** generate weaponized exploit steps.
- **Never** provide operational exploitation instructions.
- Only describe procedure categories.
- Require analyst confirmation for control assertions.
- Preserve explainability (explicit mapping from control to constraint).

---

## 11. Refactoring Guidance for `risk_assessment.py`

The current tool:

- Extracts stages from narrative.
- Flags missing required stages.
- Evaluates control independence.

**To extend into attack path modeling:**

1. Add `StageEvaluation` structure.
2. Integrate prevention schema validation step.
3. Add scoring engine module.
4. Add stage-control relevance mapping.
5. Replace purely narrative validation with:
   - Procedure generation
   - Constraint-based feasibility evaluation.

Existing MITRE stage enum remains valid.

---

## 12. Success Criteria

The tool successfully:

- Reduces analyst time spent on already strong stages.
- Identifies weakest feasible stage.
- Identifies minimal control improvements that materially change feasibility.
- Produces deterministic, explainable outputs.
- Maintains safe modeling boundaries.

---

## 13. Future Extensions (Not MVP)

- Monte Carlo likelihood modeling.
- Control cost modeling.
- Cross-path convergence detection.
- Automated confidence weighting.
- Integration with Eventmill telemetry ingestion.