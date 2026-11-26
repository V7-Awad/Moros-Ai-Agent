# Completion Checklist Format — Standard for All Skills

Every skill's SKILL.md should include a **Verification Checklist** section (matching `skill_registry.py` and `CONTRIBUTING.md`; legacy skills may use `## Methodology Checklist`) using this exact format:

```markdown
## Verification Checklist

- [ ] Step 1: <description>
  - Expected artifact: `<path/to/output/file>`
  - Log file: `<path/to/log/file>`
- [ ] Step 2: <description>
  - Expected artifact: `<path/to/output/file>`
  - Log file: `<path/to/log/file>`
...
```

## Rules

1. **Every checklist item must map to exactly one log file** in `targets/<domain>/output/logs/<skill>/`.
2. **A step is "done" only when:**
   - The checkbox is marked `[x]`
   - The expected artifact file exists AND is non-zero bytes
   - The corresponding log file exists AND is non-zero bytes
3. **The review-skill verifies all three conditions.** If any condition fails, the step is marked FAILED.
4. **On failure**, the review-skill issues a retry directive and re-invokes the skill runner (bounded retries).
5. **Log files must contain:**
   - Timestamp of execution
   - Command or action performed
   - Exit code or result status
   - Any errors or warnings
   - Byte count of output generated

## Example Checklist Item (completed)

```markdown
- [x] Step 3: Extract API endpoints from beautified JS files
  - Expected artifact: `targets/example.com/output/js/endpoints.json`
  - Log file: `targets/example.com/output/logs/js-analyze/step-03-extract-endpoints.log`
```

## Example Log File Content

```
[2024-01-15T14:32:01Z] Starting endpoint extraction
[2024-01-15T14:32:01Z] Processing 47 beautified JS files from targets/example.com/output/js/beautified/
[2024-01-15T14:32:03Z] Found 142 unique endpoints across 47 files
[2024-01-15T14:32:03Z] Output written to targets/example.com/output/js/endpoints.json (23,891 bytes)
[2024-01-15T14:32:03Z] Exit code: 0
```
