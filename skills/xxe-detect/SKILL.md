# XML External Entity (XXE) Detector (`xxe-detect`)

**Category:** Parsing & Serialization Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Detects XML External Entity (XXE) injection vulnerabilities in XML-accepting endpoints, SOAP services, SVG upload handlers, and SAML consumers.

## Methodology & Objectives
1. Identify XML endpoints, SOAP APIs, and XML-content-type consumers.
2. Submit safe inline entity test payloads to check entity parsing.
3. Detect entity resolution and server configuration disclosures.

## Verification Checklist
- [ ] Scan endpoints for XML input parsers
- [ ] Inject non-destructive XML entity probes
- [ ] Record candidate findings with exact evidence
