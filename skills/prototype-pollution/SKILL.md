# Prototype Pollution Hunter (`prototype-pollution`)

**Category:** Client-Side & DOM Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Detects Object Prototype Pollution vulnerabilities in client-side JavaScript libraries and query parameter parsing routines.

## Methodology & Objectives
1. Inspect beautified JavaScript files for recursive object merging, deep cloning, and query parsing gadgets:
   - `merge(`, `deepMerge(`, `extend(`, `clone(`
2. Look for dangerous assignments to `__proto__`, `constructor.prototype`, and `Object.prototype`.
3. Check URL query parameters handling for `__proto__[isAdmin]=true` style injections.
4. Flag vulnerable gadgets that could escalate to client-side DOM XSS or state hijacking.

## Verification Checklist
- [ ] Scan JS bundles for prototype modification gadgets
- [ ] Inspect query parameter and JSON recursive parsing routines
- [ ] Record candidate findings with exact file and line references
