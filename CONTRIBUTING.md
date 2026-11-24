# Contributing to Moros AI

Thank you for your interest in contributing to Moros AI!

## Code of Conduct & Scope Rules
- Moros AI is an offensive security assessment tool built exclusively for authorized testing under signed agreements and approved bug bounty programs.
- All contributions must enforce safety constraints: same-host bounded checks, non-destructive payloads, rate limits, and cryptographic evidence hashes.

## Development Workflow
1. Clone the repository and install dependencies:
   ```bash
   pip install -r requirements.txt
   playwright install chromium
   ```
2. Verify all tests pass before making changes:
   ```bash
   python -m pytest tests/
   ```

## Adding a New Security Skill
To add a new skill to Moros AI:
1. Create a directory under `skills/<skill-id>/`.
2. Create `SKILL.md` with:
   - `# Skill Name (\`<skill-id>\`)`
   - `**Category:** <Category Name>`
   - `## Description`
   - `## Methodology & Objectives`
   - `## Verification Checklist`
3. (Optional) Provide a `run.py` executable runner implementing CLI flags `--target`, `--target-dir`, `--output-dir`. Output candidate findings to `candidates-<skill-id>.json`.
4. Run `python run.py --list-skills` to ensure dynamic auto-discovery registers your skill.
5. Add unit tests in `tests/`.

## Running Tests
Run the test suite:
```bash
python -m pytest tests/ -v
```
All tests must pass before submitting a pull request.
