# WebSocket Security Auditor (`websocket-audit`)

**Category:** Real-Time & Network Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Discovers WebSocket endpoints (`ws://`, `wss://`) and audits handshake configurations for Cross-Site WebSocket Hijacking (CSWSH) and missing origin validation.

## Methodology & Objectives
1. Inspect JavaScript codebases, network requests, and configuration files for WebSocket URLs.
2. Identify handshake protocols and endpoints.
3. Check if Origin header validation is enforced during upgrade request.
4. Flag unauthenticated or cross-origin WebSocket endpoints.

## Verification Checklist
- [ ] Extract `wss://` and `ws://` schemes from client assets
- [ ] Analyze handshake authentication tokens
- [ ] Record candidate findings with code references
