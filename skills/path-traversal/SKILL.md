# Path Traversal & LFI Auditor (`path-traversal`)

**Category:** File System & Access Control  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Detects Local File Inclusion (LFI) and Directory Path Traversal vulnerabilities in file-retrieval, document download, and template inclusion parameters.

## Methodology & Objectives
1. Inspect endpoints for file, path, page, doc, and template query parameters (`?file=`, `?page=`, `?doc=`, `?path=`).
2. Test relative traversal sequences (`../../../../etc/passwd`, `..\\..\\windows\\win.ini`).
3. Test URL-encoded and double-encoded traversal patterns (`%2e%2e%2f`, `..%252f`).
4. Identify Unix root files or Windows system markers in returned responses.

## Verification Checklist
- [ ] Scan endpoints for file path parameters
- [ ] Test path traversal sequence injection
- [ ] Verify root file / system markers in response body
