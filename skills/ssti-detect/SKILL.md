# Server-Side Template Injection Detector (`ssti-detect`)

**Category:** Injection & Execution Security  
**Author:** Moros AI Core  
**Type:** Advanced Offensive Skill  

## Description
Detects Server-Side Template Injection (SSTI) in template rendering engines (Jinja2, Twig, Freemarker, Smarty, Handlebars, ERB).

## Methodology & Objectives
1. Identify input vectors, reflected parameters, search inputs, and template parameters.
2. Inject polyglot math evaluation payloads: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`.
3. Observe responses for computed arithmetic value (`49`) rather than literal string reflection.
4. Distinguish between server-side evaluation and client-side browser evaluation.

## Verification Checklist
- [ ] Inject mathematical expression payloads into input vectors
- [ ] Check HTTP responses for computed arithmetic evaluation (`49`)
- [ ] Record candidate findings with reproducible curl and payload evidence
