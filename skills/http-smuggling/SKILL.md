# HTTP Request Smuggling Detector (`http-smuggling`)

**Category:** Network & Protocol Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Tests for HTTP Request Smuggling vulnerabilities (CWE-444) by probing for Content-Length / Transfer-Encoding desynchronization between front-end proxies and back-end servers. All tests are non-destructive timing-based differential probes.

## Methodology & Objectives
1. Send CL.TE probe: a request with both `Content-Length` and `Transfer-Encoding: chunked` headers where CL wins on front-end but TE wins on back-end.
2. Send TE.CL probe: the inverse desync where TE wins on front-end but CL on back-end.
3. Send CL.CL probe: conflicting Content-Length values to detect which server processes which.
4. Measure differential response times and status codes to identify desync without causing harm.
5. Check for HTTP/2 downgrade smuggling indicators.

## Dependencies
- recon-subdomain

## Verification Checklist
- [ ] Probe CL.TE desynchronization with timing differential
- [ ] Probe TE.CL desynchronization with timing differential
- [ ] Check for conflicting Content-Length handling
- [ ] Record candidate findings with response timing evidence
- [ ] Strictly non-destructive — no request prefix injection
