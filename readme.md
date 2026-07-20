# CODEX4PPT

`CODEX4PPT` is a batch runner for binary patch-presence detection. It
launches `codex exec` tasks over target binaries and asks an LLM agent to decide
whether the patch-relevant security behavior for each CVE/binary testcase is:

- `present`
- `absent`
- `not_affected`
- `inconclusive`
- `not_found`
- `error`

The repository code does not perform the binary reasoning directly. Its job is
to prepare the agent environment, pass patch-focused metadata into prompts,
invoke `codex exec`, capture raw logs, parse the model's JSON answer, merge
per-task results, and compute evaluation metrics.

## Repository Components

- `codex_patch_presence_batch.py`: main CLI entry point.
- `codex_batch/`: batch orchestration, target anonymization, prompt rendering,
  result parsing, model/profile handling, and metric computation.
- `prompts/`: prompt templates for different binary settings.
- `utils/safe_objdump.py`: bounded helper exposed to the agent for local binary
  inspection.
- `metadata/`: offline scripts for constructing patch-focused metadata used by
  detection prompts.
- `AGENTS.md`: operational handoff guide for running experiments on another
  machine.
- `CLAUDE.md`: implementation notes and developer-facing architecture details.

## Detection Contract

The prompt contract requires the agent to base decisions on local binary
evidence, not on release/version strings or source-file inspection. Ground truth
is used only by the wrapper after model execution to score results; it is not
made visible to the agent during detection.

## Results

Current summarized experiment results are recorded in:

```text
results.md
```

That file is the place to look for reported metrics and run-summary tables.
