---
name: report-conglomeration
description: >
  Final skill that aggregates all findings from all skill runs and all model runs into a
  unified penetration testing report. Deduplicates findings, cross-references by endpoint
  and vulnerability class, and ensures every finding is tagged with AI-proposed severity
  pending human review. Produces the final deliverable report.
---

# Report Conglomeration — Final Report Assembly

## Purpose

Merge all findings from all skill runs (potentially across multiple models and multiple repetitions) into a single, unified, human-auditable penetration testing report. This is the last skill to run.

## Prerequisites

- All targeted skills have completed their runs
- All review-skill verifications are complete
- All findings are in `targets/<domain>/output/findings/`

## Inputs

- `TARGET_DOMAIN` — target domain
- `FINDINGS_DIR` — `targets/<domain>/output/findings/`
- `LOGS_DIR` — `targets/<domain>/output/logs/`
- `RECON_DIR` — `targets/<domain>/output/recon/`
- `JS_DIR` — `targets/<domain>/output/js/`
- `CONTENT_DISCOVERY_DIR` — `targets/<domain>/output/content-discovery/`

## Outputs

```
targets/<domain>/output/report/
  hackbot-report-<domain>-<date>.md         # full Markdown report
  hackbot-report-<domain>-<date>.json       # structured JSON (machine-readable)
  executive-summary.md                       # 1-page executive summary
  findings-by-severity.json                  # findings grouped by severity
  findings-by-endpoint.json                  # findings grouped by endpoint
  deduplication-log.json                     # log of merged/deduplicated findings
  coverage-matrix.md                         # what was tested, what wasn't
```

## Methodology Checklist

- [ ] Step 1: Collect all findings — scan `findings/` recursively for all `confirmed-*.json` and `*-summary.md` files from all skills.
  - Expected artifact: Collected findings inventory
  - Log file: `targets/<domain>/output/logs/report-conglomeration/step-01-collect.log`

- [ ] Step 2: Deduplicate — identify findings that describe the same vulnerability (same endpoint + same vuln class) found by different model runs. Merge them, keeping the most detailed evidence from each.
  - Expected artifact: `targets/<domain>/output/report/deduplication-log.json`
  - Log file: `targets/<domain>/output/logs/report-conglomeration/step-02-dedup.log`

- [ ] Step 3: Cross-reference by endpoint — group all findings by the endpoint they affect. This reveals endpoints with multiple vulnerability types.
  - Expected artifact: `targets/<domain>/output/report/findings-by-endpoint.json`
  - Log file: `targets/<domain>/output/logs/report-conglomeration/step-03-by-endpoint.log`

- [ ] Step 4: Group by severity — organize findings by severity level. Ensure EVERY finding has the `AI-proposed severity: <level> — pending human review` tag.
  - Expected artifact: `targets/<domain>/output/report/findings-by-severity.json`
  - Log file: `targets/<domain>/output/logs/report-conglomeration/step-04-by-severity.log`

- [ ] Step 5: Generate coverage matrix — document what was tested and what wasn't. For each skill, record: ran or skipped, number of runs, models used, review status.
  - Expected artifact: `targets/<domain>/output/report/coverage-matrix.md`
  - Log file: `targets/<domain>/output/logs/report-conglomeration/step-05-coverage.log`

- [ ] Step 6: Generate executive summary — 1-page summary: target, scope, testing period, total findings by severity, critical highlights, recommended immediate actions.
  - Expected artifact: `targets/<domain>/output/report/executive-summary.md`
  - Log file: `targets/<domain>/output/logs/report-conglomeration/step-06-executive.log`

- [ ] Step 7: Generate full report — comprehensive Markdown report with all sections: executive summary, methodology, findings (detailed, with reproduction steps), coverage, limitations, recommendations.
  - Expected artifact: `targets/<domain>/output/report/hackbot-report-<domain>-<date>.md`
  - Log file: `targets/<domain>/output/logs/report-conglomeration/step-07-full-report.log`

- [ ] Step 8: Generate structured JSON report — machine-readable version of the full report
  - Expected artifact: `targets/<domain>/output/report/hackbot-report-<domain>-<date>.json`
  - Log file: `targets/<domain>/output/logs/report-conglomeration/step-08-json-report.log`

## Report Template Structure

```markdown
# Penetration Test Report — <domain>

## Executive Summary
...

## Scope & Authorization
- Target: ...
- Authorization: scope-of-work.pdf (SHA256: ...)
- Testing Period: ...
- Skills Executed: ...
- Models Used: ...

## Methodology
- Skill-based automated testing with human-in-the-loop verification
- Multi-model execution for coverage
- Review-skill completion verification after each skill

## Findings

### Critical (AI-Proposed — Pending Human Review)
#### Finding C-1: ...

### High (AI-Proposed — Pending Human Review)
#### Finding H-1: ...

### Medium (AI-Proposed — Pending Human Review)
...

### Low (AI-Proposed — Pending Human Review)
...

### Informational
...

## Coverage Matrix
| Skill | Status | Runs | Models | Review |
...

## Limitations
- AI-proposed severities are provisional
- Automated testing may miss logic vulnerabilities
- Coverage depends on JS discovery completeness

## Recommendations
1. ...
2. ...
```

## Important Notes

- **NEVER remove the "pending human review" tag.** Even in the final report, all severities remain provisional.
- **Don't auto-chain findings into higher severity.** If multiple low findings could form a chain, present the chain as a **candidate** with "requires human validation."
- **Include what WASN'T found.** Negative results (tested but no vulnerability found) are valuable for the report consumer.
