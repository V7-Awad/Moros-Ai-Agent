# CRLF Injection Auditor (`crlf-injection`)

**Category:** Network & Protocol Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Tests for Carriage Return Line Feed (CRLF / `%0d%0a`) injection in HTTP parameters and headers to detect HTTP Response Splitting and header poisoning.

## Methodology & Objectives
1. Inject `%0d%0aSet-Cookie:%20moros_test=1` into redirection parameters and path components.
2. Check response headers for newly injected HTTP headers.
3. Detect header injection and HTTP response splitting vulnerabilities.

## Verification Checklist
- [ ] Inject CRLF sequences in query parameters and paths
- [ ] Check HTTP response headers for injected headers
- [ ] Record candidate findings with exact evidence
