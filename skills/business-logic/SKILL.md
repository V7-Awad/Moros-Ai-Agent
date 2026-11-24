# Business Logic Vulnerability Analyzer (`business-logic`)

**Category:** Logic & Workflow Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Agent-driven reasoning skill for identifying business logic flaws, multi-step workflow bypasses, price manipulation vectors, and state machine inconsistencies.

## Methodology & Objectives
1. Inspect discovered API documentation and workflow endpoints (checkout, coupon, payment, subscription, role change).
2. Use LLM reasoning to analyze business workflow assumptions.
3. Identify race conditions, negative number injections, discount stacking, and state transitions.
4. Record structured logic attack vectors with reproducible steps.

## Verification Checklist
- [ ] Map out multi-step business transactions
- [ ] Identify state machine assumptions and parameter tampering opportunities
- [ ] Formulate reproducible exploitation scenarios
