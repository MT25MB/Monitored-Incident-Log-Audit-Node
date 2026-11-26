## What changed

Describe the change in a few sentences.

## Why

Link the issue or state the problem this solves.

## Test plan

- [ ] `python -m pytest -v` passes.
- [ ] The CI JSONL dry-run passes if `evals/datasets/` changed.
- [ ] New tests use synthetic data only.
- [ ] No real logs, secrets, API keys, tokens, or sensitive telemetry appear in the diff, screenshots, or test fixtures.
- [ ] Paths and commands in `README.md` and `docs/` still match the code.

## Checklist

- [ ] Commit title follows Conventional Commits.
- [ ] Documentation and benchmark numbers updated if behaviour changed.
- [ ] No unrelated files or generated databases staged.
