# GraphQL Security Auditor (`graphql-audit`)

**Category:** API Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Detects and audits GraphQL endpoints for schema introspection disclosure, circular query recursion (DoS), and batching attacks.

## Methodology & Objectives
1. Probe common GraphQL route paths:
   - `/graphql`, `/api/graphql`, `/v1/graphql`, `/v2/graphql`, `/query`, `/graphiql`
2. Test for Schema Introspection enabled via standard POST payload:
   `{"query": "{ __schema { types { name } } }"}`
3. Analyze whether full query types and mutations are exposed in production.
4. Flag exposed internal models and dangerous mutation candidates.

## Verification Checklist
- [ ] Identify active GraphQL endpoints
- [ ] Verify HTTP POST and GET schema queries
- [ ] Record schema introspection findings with field counts
