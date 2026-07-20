# Dataset for Patch Presence Testing — ISSTA 2026 Artifact

Public artifact for the ISSTA 2026 paper:

**A Comprehensive Empirical Analysis of Patch Presence Testing: Capabilities,
Limitations, and Paths Forward**

This is a **data artifact and replication package** for an empirical study of
patch presence testing. It contains dataset metadata, vulnerability patch diffs,
reference/test-set mappings, target functions, experimental results for five
patch presence testing tools (BinXray, PatchDiscovery, PS3, React, Robin),
per-research-question analysis data, and the construction-pipeline scripts.

We apply for the **Available** and **Reusable** badges (see `STATUS.md`).

## Artifact archives

- **This repository** (metadata, diffs, results, RQ data, scripts): ~43 MB.
  Archived snapshot DOI: https://doi.org/10.5281/zenodo.21004672
- **Compiled binary corpus** (43.08 GB compressed; 73.17 GB as unpacked
  binaries; stored separately due to size):
  https://doi.org/10.5281/zenodo.18382612

---

# Part 1 — Getting Started

This part can be completed in well under 30 minutes and is **fully offline**: it
downloads nothing and does not rebuild the dataset.

## Requirements

- Python 3.10+ (standard library only), **or** Docker / Podman.
- ~100 MB free disk for this repository snapshot.
- Architecture: any (x86_64, ARM64) — the smoke test is pure Python.

See `REQUIREMENTS.md` for the full environment details.

## Smoke test

The smoke test loads and validates the released metadata and results, confirming
the snapshot is complete and consistent.

```bash
python3 scripts/smoke_test.py
```

Expected output ends with:

```text
Artifact smoke test summary:
- projects: 10
- testset CVE entries: 562
- reference CVE entries: 559
- result pickle files: 41
- RQ data files checked: 12
Artifact smoke test passed.
```

Equivalent containerized run (same expected final line). Two options:

**(a) Load the prebuilt offline image** — no internet, no build, recommended.
The image archive `patch-presence-artifact-image.tar.gz` ships with the artifact:

```bash
docker load < patch-presence-artifact-image.tar.gz
docker run --rm patch-presence-artifact
```

**(b) Build it yourself** (needs network to pull the base image):

```bash
docker build -t patch-presence-artifact .
docker run --rm patch-presence-artifact
```

If you see `Artifact smoke test passed.`, the getting-started setup is working.

---

# Part 2 — Step-by-Step Instructions

## Artifact layout

- `Dataset/` — dataset metadata.
  - `Dataset/Diffs/` — patch diffs collected per CVE.
  - `Dataset/reference/` — reference-binary metadata (vuln/patch + target functions) per project.
  - `Dataset/testset/` — vulnerable/patched target-version metadata per CVE.
  - `Dataset/target_functions.json` — target functions associated with CVE fixes.
- `results/` — per-tool detection results (BinXray, PatchDiscovery, PS3, React, Robin) and `backport_summary.json`.
- `RQs/` — analysis data backing the paper's research questions.
- `scripts/` — the construction pipeline (`scripts/README.md`) and the reduced demo (`scripts/demo/`).

## Mapping: paper claims → artifact data

Every claim below can be inspected directly in the archived data. See
`results/README.md` and `RQs/README.md` for the exact file formats.

| Paper element | Artifact data |
|---|---|
| Per-tool detection results (V/P; TP/TN/FP/FN) | `results/{BinXray,PatchDiscovery,PS3,React,Robin}/*.pkl` |
| Figure 3 — accuracy across function & patch size | `RQs/function_size.pkl`, `RQs/patch_size.pkl` |
| Figure 5 — failure-pattern classification & distribution | `RQs/common_failure_patterns.json` |
| Figure 6 — impact of patch evolution | `RQs/patch_evolution.json` |
| Figure 7 — real-world deployment scenarios | `RQs/deployed_binaries/*.json` |
| Table 5 — accuracy across semantic complexity & categories | `RQs/semantic_patterns.json` |
| Table 6 — accuracy on CWE categories | `RQs/cwe_mapping.json` |
| Robustness of chronological test-set selection | `RQs/extended_testset.json` |
| Backport-fix analysis | `results/backport_summary.json` |
| Dataset (562 testset / 559 reference / diffs / target functions) | `Dataset/` |

### How to read the result data

`results/*/*.pkl` are nested dictionaries: `project → CVE ID → version → function
→ result object`, where each result object has `result` (tool output, e.g. `V`,
`P`, or a failure message), `truth` (ground truth: `-1` vulnerable, `1`
patched), and `status` (`TP`/`TN`/`FP`/`FN`/`fail test`/`fail gen`). A worked
example is in `results/README.md`; the RQ file formats are documented in
`RQs/README.md`.

## Claims supported / not supported by this repository

**Supported (inspectable offline in this snapshot):**

- The dataset (metadata, diffs, reference/test-set mappings, target functions).
- The per-tool detection results for the five evaluated tools.
- The per-RQ analysis data behind the figures/tables listed above.
- `scripts/smoke_test.py` verifies the snapshot is complete and loadable.

**Not in the review path (deliberately out of scope):**

- Re-compiling the full binary corpus and re-running all five tools end-to-end.
  This needs ~43 GB of binaries, network access, and historical build
  toolchains, so it is not feasible within the review window. The compiled
  corpus is archived on Zenodo, and the pipeline is documented in
  `scripts/README.md`. A **reduced, runnable** slice of the construction pipeline
  is provided as the optional demo below.

## Data provenance

The dataset was constructed from public sources only:

- **CVE / NVD metadata** (vulnerability records, affected CPE version ranges).
- **Upstream open-source git repositories** of the 10 projects (source, tags,
  fix commits).
- **Public CVE references** (commit/advisory links) used to locate fix commits.

The end-to-end construction process — CVE selection, diff acquisition,
source-function analysis, reference/target compilation, binary diffing, and final
dataset generation — is documented stage by stage in `scripts/README.md`.

## Ethical and legal considerations

- Only publicly available data and open-source software are used; no private,
  personal, or sensitive data is involved.
- Author-created dataset metadata, analysis data, and result metadata are
  released under **CC BY 4.0**; author-created scripts under the **MIT License**.
- Third-party source code, patches, and compiled binaries remain subject to their
  respective **upstream licenses**. See `LICENSE`.

## Storage requirements

- This repository snapshot: **~43 MB**.
- Compiled binary corpus (optional, Zenodo): **43.08 GB compressed** and
  **73.17 GB** as unpacked binaries after removing intermediate archives. A
  straightforward in-place extraction that keeps the compressed archives during
  unpacking may temporarily use about **160.66 GB**; reserve **at least 170 GB
  of free disk space**.
- Optional construction demo output: a few hundred MB (clone + compiled binaries).

## Reuse guide (Reusable badge)

The artifact is designed to be extended and repurposed:

- **Add a project or CVEs:** the pipeline is driven by `scripts/config.json`
  (per-project build/tag/vendor rules) plus the stage scripts in `scripts/`.
  `scripts/README.md` documents each stage and its inputs/outputs.
- **Run a self-contained slice:** `scripts/demo/` runs the real pipeline on 5
  curl CVEs across all six stages; see `scripts/demo/README.md` and the full
  Docker tutorial in `scripts/demo/DOCKER.md`.
- **Result/RQ formats** are documented in `results/README.md` and `RQs/README.md`
  so the data can be consumed by other analyses.

## Optional construction demo

`scripts/demo/` exercises the construction scripts on a small, real selection (5
curl CVEs) through the six pipeline stages:

1. diff acquisition (`scripts/cve2diff.py`)
2. source-function analysis (`scripts/source_analyzer.py`)
3. reference compilation (`scripts/compile_ref.py`, `--compile`)
4. binary diffing via ghidriff (`scripts/bin_diff.py`, `--bindiff`)
5. target compilation (`scripts/compile_target.py`, `--target-build`)
6. dataset generation (`scripts/gen_test_ref.py`, `--gen-dataset`)

```bash
# default: diff acquisition + source-function analysis (stages 1–2)
python3 scripts/demo/run_demo.py --output /tmp/patch-presence-demo

# full pipeline (stages 1–6; slow, best-effort)
python3 scripts/demo/run_demo.py --full --output /tmp/patch-presence-demo
```

The demo is **optional** and, unlike the smoke test, **needs network access**
(to clone curl and query NVD) and Docker for the ghidriff stage. It is a reduced
demonstration, not part of the offline getting-started path. Stages 3–6 are
best-effort. See `scripts/demo/README.md` and `scripts/demo/DOCKER.md`.

---

## Dataset summary

The released metadata covers 10 open-source projects: `binutils`, `curl`,
`ffmpeg`, `freetype`, `imagemagick`, `libxml2`, `openjpeg`, `openssl`, `sqlite`,
`tcpdump`. `Dataset/testset/` holds 562 CVE entries and `Dataset/reference/`
holds 559 reference entries in total.

## Licensing

See `LICENSE`. In brief: author-created dataset metadata, analysis data, and
experimental-result metadata are released under CC BY 4.0; author-created scripts
under the MIT License; third-party source code, patches, and compiled binaries
remain subject to their upstream licenses.

## Citation

If you use this artifact, please cite the paper and the archived Zenodo records:

- Repository snapshot: https://doi.org/10.5281/zenodo.21004672
- Compiled binary corpus: https://doi.org/10.5281/zenodo.18382612
