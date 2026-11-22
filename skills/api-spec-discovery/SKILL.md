---
name: api-spec-discovery
description: Imports an authorized, locally supplied OpenAPI or Swagger specification and maps routes, parameters, request body types, and declared security requirements for follow-up review.
---

# API Specification Discovery

## Purpose

Build a reviewable API attack-surface inventory from a specification the assessor already has. This skill only reads local files; it does not fetch a specification or send requests to the target.

## Inputs

- `SPEC_FILE` — local OpenAPI 3.x or Swagger 2.0 JSON/YAML file supplied for this engagement.
- `TARGET_DIR` — authorized engagement directory.

## Procedure

1. Confirm the specification belongs to this engagement and is within the authorized scope.
2. Run `python tools/openapi_import.py --spec <SPEC_FILE> --output <TARGET_DIR>/output/api/openapi-endpoints.json --target <TARGET>`.
3. Review the output for route, HTTP method, operation ID, tags, parameters, request body content types, and declared security.
4. Compare routes with observed endpoints and flag undocumented or stale entries for human review.
5. Do not treat a declared security scheme as proof that an endpoint is protected. Validate access controls only under the engagement authorization and its rules.

## Output

- `targets/<target>/output/api/openapi-endpoints.json`
- `targets/<target>/output/logs/api-spec-discovery/import.log`

## Completion Checklist

- [ ] Input is a local OpenAPI/Swagger JSON or YAML document.
- [ ] Import command completed successfully and endpoint count was recorded.
- [ ] Inventory was saved under the target output directory.
- [ ] Findings remain hypotheses until independently validated and reviewed.
