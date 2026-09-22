# Copilot Instructions for VerdictLab

These are permanent project rules. Follow them in all future changes unless explicitly overridden by the user.

## Engineering Style
- Use clear, beginner-readable code.
- Keep business logic separate from API and UI code.
- Use TypeScript types and Python type hints.
- Do not add dependencies without explaining why they are needed.

## Security and Data Safety
- Never add real malware samples.
- Never implement executable file uploads.
- Use synthetic fixtures for the MVP.
- Never hard-code API keys or credentials.

## Verdict Behavior
- Explain security verdicts rather than returning only a label.
- Treat unknown and insufficient evidence conservatively.

## Testing and Architecture Constraints
- Add tests whenever verdict logic changes.
- Do not introduce a database unless explicitly requested.
