# Requirements

This artifact is submitted for the **Available** and **Reusable** badges. The
getting-started path (the smoke test) uses only the Python standard library and
runs fully offline. Machine-readable dependency specifications are provided as
`Dockerfile` (smoke-test image) and `scripts/demo/Dockerfile` (demo image).

## Smoke Test Environment

- Architecture: x86_64
- Operating system: Linux
- Python: 3.10 or newer
- Disk space: about 100 MB for this repository snapshot
- Optional container runtime: Docker or Podman. A prebuilt, fully offline image
  archive (`patch-presence-artifact-image.tar.gz`, ~46 MB) ships with the
  artifact; `docker load` it to run the smoke test with no network or build.

Run:

```bash
python3 scripts/smoke_test.py
```

or:

```bash
docker build -t patch-presence-artifact .
docker run --rm patch-presence-artifact
```

## Full Binary Corpus

The compiled binary corpus is archived separately on Zenodo:

https://doi.org/10.5281/zenodo.18382612

Downloading the full corpus requires about 43 GB for the compressed archives and
substantially more disk space after extraction.

## Construction Pipeline Requirements

The scripts in `scripts/` document the construction pipeline used for the
dataset. Full reconstruction is not required for the Available badge and is not
part of the smoke test. A full reconstruction may require:

- Git and local clones of the target projects
- C/C++ build toolchains, such as GCC or Clang
- project-specific build tools, such as Make, Autoconf, Automake, Libtool, CMake,
  Ninja, and pkg-config
- Python packages used by construction scripts, including `requests` and
  `python-dateutil`
- NVD/CVE metadata access and, for some steps, GitHub API access
- binary-analysis tooling used by the original study

These requirements are intentionally separated from the lightweight archival
validation path.

## Optional Construction Demo

The optional demo is a **reduced, runnable slice** of the construction pipeline
(5 curl CVEs, all six stages) — a scope validatable in well under a day, versus
the full corpus. It targets **x86_64 Linux** (it compiles native x86 binaries;
the demo image is `ubuntu:24.04` amd64). It additionally requires:

- Git network access to clone curl, unless `--repo-curl` points to an existing
  local checkout
- Universal Ctags
- For the opt-in `--compile` / `--target-build` steps: GNU build tools and
  curl's build dependencies such as Autoconf, Automake, Libtool, pkg-config,
  OpenSSL development headers, and zlib development headers
- For the opt-in `--bindiff` step: Docker, used to run the ghidriff image
  `ghcr.io/clearbluejar/ghidriff:0.5.2`
- For the opt-in `--gen-dataset` step: network access to the NVD REST API
  (`services.nvd.nist.gov`); a `GITHUB_TOKEN` is optional (used by
  `tag_parser.py`, otherwise releases come from the local git tags)

The demo Dockerfile installs the build/analysis dependencies (Docker for
`--bindiff` is provided by the host):

```bash
docker build -f scripts/demo/Dockerfile -t patch-presence-demo .
docker run --rm -v "$PWD/demo-output:/demo-output" patch-presence-demo
```

See `scripts/demo/README.md` for the full list of stages and flags.
