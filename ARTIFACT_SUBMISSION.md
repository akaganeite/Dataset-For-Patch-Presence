# ISSTA 2026 Artifact Submission Checklist

Submission for the **Available** and **Reusable** badges.

## Required files (present in this repository)

- `README.md` — Getting Started + Step-by-step (claim→data mapping, provenance,
  ethical/legal, storage, reuse guide).
- `REQUIREMENTS.md` — architecture and software/hardware needs.
- `STATUS.md` — badges requested + justification.
- `LICENSE` — terms of use.

All are plain Markdown and must be included in the archived artifact.

## Local validation (reviewer getting-started, offline)

```bash
python3 scripts/smoke_test.py
```

Expected final line:

```text
Artifact smoke test passed.
```

Containerized equivalent (CfA requires container/VM packaging). A prebuilt,
fully offline image archive `patch-presence-artifact-image.tar.gz` is provided
with the submission so reviewers need no network or build:

```bash
docker load < patch-presence-artifact-image.tar.gz   # offline, prebuilt
docker run --rm patch-presence-artifact

# or build it yourself (needs network for the base image):
docker build -t patch-presence-artifact . && docker run --rm patch-presence-artifact
```

Optional, exercisable evidence for Reusable (needs network/Docker):

```bash
python3 scripts/demo/run_demo.py --full --output /tmp/patch-presence-demo
# ends with: Construction demo passed.
```

## Packaging notes

- The getting-started path is **self-contained / offline** (smoke test downloads
  nothing). The optional construction demo is the only part that needs network.
- Provide the artifact as a container image (the `Dockerfile` smoke-test image)
  and/or the archived snapshot below.
- **Exclude `demo-output/` and `.git/`** from the archive so it stays ~43 MB
  (they are listed in `.dockerignore` / `.gitignore`).

## Zenodo archiving (for the Available badge)

1. Create a clean archive of this repository snapshot (exclude `demo-output/`,
   `.git/`).
2. Upload to Zenodo with a title such as:
   `Dataset and Results for "A Comprehensive Empirical Analysis of Patch Presence Testing"`
3. Add the paper authors as creators; license `CC-BY-4.0` for the data/results.
4. Add the related identifier `10.5281/zenodo.18382612` (compiled binary corpus).
5. The reserved DOI `10.5281/zenodo.21004672` is already recorded in `README.md`
   and `STATUS.md`; publish the record under that DOI.
6. Host only on Zenodo (does not track reviewer IPs).

## HotCRP submission

Submit at https://issta2026-ae.hotcrp.com/.

Badges: `Available`, `Reusable`.

Suggested summary:

```text
A data artifact and replication package for an empirical study of patch presence
testing. It contains dataset metadata, CVE patch diffs, reference/test-set
mappings, target functions, detection results for five tools (BinXray,
PatchDiscovery, PS3, React, Robin), per-RQ analysis data, and the construction
pipeline. An offline smoke test validates the snapshot; a reduced, runnable demo
(5 curl CVEs, six stages) exercises the real pipeline. The ~43 GB compiled
binary corpus is archived separately on Zenodo.
```

Suggested scope note:

```text
Getting started (the offline smoke test) is self-contained. Full corpus rebuild
and rerunning all five tools are out of the review path (~43 GB + network +
historical toolchains); the corpus is on Zenodo and a reduced runnable slice is
included under scripts/demo/.
```
