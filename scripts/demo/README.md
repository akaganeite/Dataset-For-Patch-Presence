# Construction Demo (curl)

This directory contains a reduced dataset-construction demo for artifact
reviewers who want to exercise the construction scripts on a small, real
selection of curl CVEs.

The demo runs **5 curl CVEs** through the existing scripts in this repository,
following the pipeline in `../README.md`:

| Stage | Script | Flag | Output |
|-------|--------|------|--------|
| 1. Diff acquisition | `scripts/cve2diff.py` | default | downloaded/cached diffs |
| 2. Source analysis | `scripts/source_analyzer.py` | default | changed functions (`source_diff.json`) |
| 3. Reference compile | `scripts/compile_ref.py` | `--compile` | `CVE-*-patch-*` / `CVE-*-vuln-*` binaries |
| 4. Binary diff (ghidriff) | `scripts/bin_diff.py` | `--bindiff` | `curl_bin_diff.json` |
| 5. Target build | `scripts/compile_target.py` | `--target-build` | release-tag target binaries |
| 6. Dataset generation | `scripts/gen_test_ref.py` | `--gen-dataset` | `reference.json` / `testset.json` / `versions.json` |

`--bindiff` and `--gen-dataset` imply `--compile`. `--full` enables stages 3–6.

CVEs exercised (in `curl_cves.txt`):

`CVE-2013-1944`, `CVE-2016-8617`, `CVE-2016-8624`, `CVE-2018-1000007`,
`CVE-2022-42916`.

The two larger patches (`CVE-2018-1000007`, `CVE-2022-42916`) are included so
that `--bindiff` produces non-empty binary-diff function results
(`Curl_add_custom_headers`; `parseurlandfillconn` + `create_conn`); the smaller
patches mainly exercise stages 1–2.

## What the demo validates

The **default** path (stages 1–2, diff acquisition + source-function analysis)
is the reliable getting-started path and gates the result. For every CVE it
checks that a diff is available (downloaded or cached) and that
`source_analyzer.py` reports at least one changed function. A compact
`work/demo_summary.json` is written under the output directory and the run ends
with:

```text
Construction demo passed.
```

**Stages 3–5 are opt-in and best-effort.** Building old sources on a modern
toolchain and running ghidriff are slow and can fail, so per-item failures are
reported as warnings and do not fail the demo (use `--strict-compile` to make
missing reference binaries fatal).

- `--compile` runs `compile_ref.py` to build the patched/vulnerable reference
  binary pairs.
- `--bindiff` runs `bin_diff.py`, which drives the **ghidriff** Docker image
  over those pairs and records the binary-diff function map. **Requires Docker.**
  The image is pinned to `ghcr.io/clearbluejar/ghidriff:0.5.2` because the
  published `:latest` and `:0.6.0` tags currently ship a Ghidra/pyhidra version
  mismatch and fail to launch. Override it with `--ghidriff-image <ref>` (or the
  `GHIDRIFF_IMAGE` env var). ghidriff reports added/deleted/modified functions
  plus string/symbol changes; for very small `-O0` patches it may report only
  string/symbol differences.
- `--target-build` synthesizes a small `versions.json` from
  `Dataset/testset/curl.json` (a few release versions for the demo CVEs, mapped
  to git tags via `scripts/config.json` `tag_rules`) and runs
  `compile_target.py` to build those release tags into the target-binary pool.
- `--gen-dataset` runs `gen_test_ref.py` (stage 6) to produce
  `reference.json` / `testset.json` / `versions.json` under `work/dataset/curl/`,
  in the same format as the published `Dataset/` metadata. It assembles the
  inputs itself: `valid` from the source analysis, the reference binaries from
  `--compile`, the release list from `tag_parser.py` when `GITHUB_TOKEN` is set
  (otherwise from the local git tags), and the vulnerable version ranges from the
  **NVD REST API** (so no CVE-Search database is required). Needs network for
  NVD; results are best-effort per CVE.

## Requirements

- Network access to clone curl, unless `--repo-curl` points at an existing local
  checkout. The clone is `--filter=blob:none` by default.
- Universal Ctags (stage 2).
- GNU build tools + curl build dependencies for stages 3 and 5.
- Docker for stage 4 (`--bindiff`); the first run pulls the multi-GB ghidriff
  image (`ghcr.io/clearbluejar/ghidriff:0.5.2` by default) and analysis takes
  minutes per pair.

## Docker

See **[DOCKER.md](DOCKER.md)** for the full tutorial (all stages, output
layout, restricted-network/proxy setup, and offline use).

Build from the repository root:

```bash
docker build -f scripts/demo/Dockerfile -t patch-presence-demo .
```

Run the default path (stages 1–2, no compilation):

```bash
docker run --rm -v "$PWD/demo-output:/demo-output" patch-presence-demo
```

Add heavier stages:

```bash
docker run --rm patch-presence-demo --compile
docker run --rm patch-presence-demo --target-build
```

`--bindiff` launches ghidriff as a sibling container, so run it on the host (or
mount the Docker socket and provide a docker client):

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  patch-presence-demo --bindiff
```

The expected final line is `Construction demo passed.`

## Local run

Install the dependencies listed in `Dockerfile`, then run from the repository
root:

```bash
# default: stages 1-2
python3 scripts/demo/run_demo.py --output /tmp/patch-presence-demo

# reuse an existing local checkout instead of cloning
python3 scripts/demo/run_demo.py --repo-curl /path/to/curl --output /tmp/patch-presence-demo

# full pipeline (compile + ghidriff bindiff + target build); slow, best-effort
python3 scripts/demo/run_demo.py --full --output /tmp/patch-presence-demo
```
