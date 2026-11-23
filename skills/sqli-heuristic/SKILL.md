# SQL Injection Heuristic Auditor (`sqli-heuristic`)

**Category:** Database Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Performs passive and benign heuristic analysis to detect SQL syntax anomalies, database error signatures, and parameter reflection behavior.

## Methodology & Objectives
1. Identify parameterized endpoints and queries from discovered routes.
2. Probe parameters with single-character benign syntax anomaly tokens: `'`, `"`, `\`
3. Analyze HTTP responses for known database error strings:
   - MySQL: `You have an error in your SQL syntax`
   - PostgreSQL: `pg_query()`, `syntax error at or near`
   - SQLite: `unrecognized token`, `OperationalError`
   - MSSQL: `Unclosed quotation mark before the character string`
   - Oracle: `ORA-00933`, `ORA-01756`
4. Flag endpoints exhibiting SQL error disclosures as high-confidence candidate findings.

## Verification Checklist
- [ ] Parse query parameters from observed routes
- [ ] Inspect error reflections for DB signatures
- [ ] Ensure requests remain bounded and non-destructive
