# VerdictLab MVP Implementation Plan

## Goal
Build a public portfolio app that turns file-reputation signals into an explainable security verdict from a **SHA-256 hash input only**, using **bundled synthetic data** (no external API in MVP).

## Scope for MVP
1. Input: SHA-256 hash string only (no file upload support).
2. Data source: local synthetic dataset bundled in the repository.
3. Output data: file metadata and detection counts.
4. Verdict engine: transparent, rule-based scoring with visible reasons.
5. Recommendation: one of Allow, Block, Rescan, Detonate, or Human Review.
6. UX safety: clearly label all displayed results as synthetic.
7. Trust disclaimer: never imply that zero detections means a file is safe.

## Implementation Steps (Short Plan)
1. Initialize mono-repo structure with separate `frontend` and `backend` directories.
2. Backend first:
   - Create FastAPI service with a single hash lookup endpoint.
   - Add SHA-256 validation and structured error responses.
   - Load bundled synthetic records from local JSON file.
   - Implement explainable verdict function that returns:
     - verdict label
     - recommendation action
     - contributing rule explanations
   - Add pytest unit tests for validation, rules, and endpoint behavior.
3. Frontend next:
   - Create React + TypeScript + Vite app.
   - Build a simple hash input form and result panel.
   - Display metadata, detection counts, verdict, recommendation, and explanation.
   - Add persistent synthetic-data badge/warning and safe-language disclaimer.
4. Integration:
   - Connect frontend to backend local endpoint.
   - Handle loading, empty, invalid-hash, and not-found states.
5. Quality checks:
   - Run backend tests (pytest).
   - Smoke test frontend flow manually.
   - Confirm wording does not claim zero detections equals safety.

## Initial Rule Framework (Transparent and Explainable)
- Use deterministic rules based on synthetic attributes (example signals: detection ratio, prevalence, first-seen recency, signature state, suspicious flags).
- Compute a simple risk score and map to recommendation bands.
- Return machine-readable `rules_triggered` array so UI can explain why a result was produced.

## Proposed Initial Directory Structure
```text
VerdictLab/
  PLAN.md
  README.md
  .gitignore

  frontend/
    package.json
    tsconfig.json
    vite.config.ts
    index.html
    src/
      main.tsx
      App.tsx
      api/
        client.ts
      components/
        HashForm.tsx
        VerdictCard.tsx
        MetadataPanel.tsx
        SyntheticBanner.tsx
      types/
        verdict.ts
      styles/
        app.css

  backend/
    pyproject.toml
    requirements.txt
    app/
      main.py
      api/
        routes.py
      core/
        verdict_engine.py
        validators.py
      data/
        synthetic_samples.json
      models/
        schemas.py
    tests/
      test_validators.py
      test_verdict_engine.py
      test_api_lookup.py
```

## Notes for Repository Setup
- Create a new public GitHub repository named `VerdictLab`.
- Push this single repository containing both `frontend` and `backend`.
- Keep synthetic dataset and labels explicit in README and UI copy.
