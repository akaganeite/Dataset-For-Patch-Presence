# Artifact Status

## Badges requested

- **Available**
- **Reusable**

## Why Available

The artifact is author-created and will be placed on a public archival repository
with a DOI:

- Compiled binary corpus (already archived):
  https://doi.org/10.5281/zenodo.18382612
- This repository snapshot (metadata, diffs, results, RQ data, scripts): archived
  on Zenodo with a permanent DOI:

  https://doi.org/10.5281/zenodo.21004672

Both records are hosted on Zenodo, which provides permanent, citable archival
storage and does not track reviewer IP addresses.

## Why Reusable

The artifact meets the Functional criteria (documented, consistent, complete,
exercisable, with verification evidence) and is structured to facilitate reuse:

- **Documented:** `README.md` has a Getting Started part (offline smoke test with
  expected output) and a Step-by-step part that maps every paper claim to the
  backing data and states what is / isn't reproducible. The construction pipeline
  is documented stage-by-stage in `scripts/README.md`; data formats in
  `results/README.md` and `RQs/README.md`; a full container tutorial in
  `scripts/demo/DOCKER.md`.
- **Consistent & complete:** `scripts/smoke_test.py` validates the snapshot
  (10 projects, 562 testset / 559 reference entries, 41 result pickles, 12 RQ
  data files) entirely offline.
- **Exercisable:** `scripts/demo/` runs the *real* construction scripts on a
  reduced, self-validating slice (5 curl CVEs) across all six pipeline stages
  (diff -> source analysis -> reference compile -> ghidriff binary diff -> target
  compile -> dataset generation).
- **Reusable / repurposable:** the pipeline is config-driven
  (`scripts/config.json` per-project rules) so new projects or CVEs can be added
  with the existing stage scripts; result/RQ formats are documented for
  downstream analyses.

## Verification & validation evidence

- Getting Started gate — `python3 scripts/smoke_test.py` ends with
  `Artifact smoke test passed.` (also via the provided Docker image).
- Reduced pipeline — `python3 scripts/demo/run_demo.py --full` runs end-to-end
  and prints `Construction demo passed.`

## Claims supported

- The dataset (metadata, patch diffs, reference/test-set mappings, target
  functions) in `Dataset/`.
- Per-tool detection results for the five evaluated tools in `results/`.
- Per-RQ analysis data (Figures 3/5/6/7, Tables 6/7, robustness, backport) in
  `RQs/` and `results/` — see the mapping table in `README.md`.

## Claims outside the badge scope

Fully rebuilding the entire compiled binary corpus and re-running all five tools
within the review period is not claimed: it requires ~43 GB of binaries, network
access, and historical build toolchains. The compiled corpus is archived on
Zenodo, the pipeline is documented in `scripts/README.md`, and a reduced runnable
slice is provided under `scripts/demo/`.
