# Running the Demo with Docker — Full Tutorial

This walks through building and running the curl construction demo
(`scripts/demo/run_demo.py`) entirely inside Docker, including all optional
pipeline stages. Every command below has been run end-to-end.

- **Image base:** `ubuntu:24.04`, x86-64 (~555 MB built).
- **What runs by default:** stages 1–2 (diff acquisition + source-function
  analysis) over 5 curl CVEs. The container clones curl itself, so it needs
  network access.
- **Output:** written inside the container at `/demo-output`; mount a host
  directory there to keep it.

---

## 1. Prerequisites

- Docker installed, on an **x86-64 Linux** host.
- Network access to GitHub (to clone curl) and, for `--gen-dataset`, to the NVD
  API. If your host can only reach the internet through a proxy, see
  [§6 Restricted networks](#6-restricted-networks-proxy).

A `.dockerignore` at the repo root keeps the build context small (it excludes
`.git/` and `demo-output/`).

---

## 2. Build the image

Run from the **repository root** (the build context must include `scripts/` and
`Dataset/`):

```bash
docker build -f scripts/demo/Dockerfile -t patch-presence-demo .
```

This installs git, gcc/g++, make, autotools, OpenSSL/zlib headers, Universal
Ctags and Python, then copies the repository into `/artifact`.

---

## 3. Run the default demo (stages 1–2)

```bash
docker run --rm -v "$PWD/demo-output:/demo-output" patch-presence-demo
```

- `--rm` removes the container afterwards.
- `-v "$PWD/demo-output:/demo-output"` keeps the output on the host under
  `./demo-output` (without it the output is lost when the container exits).

The container clones curl, runs `cve2diff.py` and `source_analyzer.py`, and ends
with:

```text
Construction demo passed.
```

Expected summary line:

```text
- curl         5 CVEs | 5 diffs | 8 changed functions
```

---

## 4. Optional stages

Arguments after the image name are appended to the entrypoint
(`run_demo.py --output /demo-output ...`). All heavier stages are best-effort.

```bash
# Stage 3 — compile reference patch/vuln binary pairs
docker run --rm -v "$PWD/demo-output:/demo-output" patch-presence-demo --compile

# Stage 5 — build a few release-tag target binaries
docker run --rm -v "$PWD/demo-output:/demo-output" patch-presence-demo --target-build

# Stage 6 — generate reference.json / testset.json / versions.json
docker run --rm -v "$PWD/demo-output:/demo-output" patch-presence-demo --gen-dataset

# Everything (stages 3–6)
docker run --rm -v "$PWD/demo-output:/demo-output" patch-presence-demo --full
```

Notes:

- `--compile`, `--target-build`, `--gen-dataset` all run inside the container
  (build tools are in the image). They are slow and may fail on individual
  CVEs; failures are reported as warnings, not fatal.
- **`--gen-dataset` without a token:** with no `GITHUB_TOKEN` it derives the
  release list from the cloned repo's local git tags (no token needed) and pulls
  vulnerable version ranges from the **NVD API** (so the container needs network
  for NVD). Output lands in `/demo-output/work/dataset/curl/`.
- **`--bindiff` is special** — it launches ghidriff as a *sibling* Docker
  container, which requires access to a Docker daemon. Run it with the host's
  Docker socket mounted:

  ```bash
  docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$PWD/demo-output:/demo-output" \
    patch-presence-demo --bindiff
  ```

  The first `--bindiff` pulls the multi-GB `ghcr.io/clearbluejar/ghidriff:0.5.2`
  image and analysis takes minutes per pair.

---

## 5. Where the output goes

With `-v "$PWD/demo-output:/demo-output"`, the host sees:

```
demo-output/
├── repos/curl/                      # curl repo the container cloned
└── work/
    ├── demo_summary.json            # summary of every stage's results
    ├── Diff/curl/source_diff.json   # changed functions per CVE (stage 2)
    ├── binaries/reference/curl/     # patch/vuln pairs        (--compile)
    ├── binaries/target/curl/        # release-tag binaries    (--target-build)
    ├── curl/curl_bin_diff.json      # ghidriff binary diff    (--bindiff)
    └── dataset/curl/                # reference/testset/versions.json (--gen-dataset)
```

Do **not** commit `demo-output/` — it contains the cloned repo and compiled
binaries and is large.

**Ownership:** the container runs as root, so files under `demo-output/` are
owned by `root` on the host. To delete them without `sudo`, remove them via a
container, or run the demo as your own user:

```bash
# remove root-owned output via a throwaway container
docker run --rm -v "$PWD/demo-output:/out" --entrypoint rm patch-presence-demo -rf /out

# or run the demo as your user so output is owned by you
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/demo-output:/demo-output" patch-presence-demo
```

---

## 6. Restricted networks (proxy)

Only needed if your host **cannot reach GitHub/NVD directly** and must use a
local proxy (e.g. `http://127.0.0.1:7890`). On a normal machine, skip this
section and use the commands above as-is.

The trick is `--network host` (so the container's `localhost` is the host's,
reaching a proxy bound to `127.0.0.1`) plus passing the proxy via env/build-args.

```bash
# Build through the proxy
docker build --network host \
  --build-arg http_proxy=http://127.0.0.1:7890 \
  --build-arg https_proxy=http://127.0.0.1:7890 \
  -f scripts/demo/Dockerfile -t patch-presence-demo .

# Run through the proxy
docker run --rm --network host \
  -e http_proxy=http://127.0.0.1:7890 \
  -e https_proxy=http://127.0.0.1:7890 \
  -v "$PWD/demo-output:/demo-output" \
  patch-presence-demo
```

Replace `127.0.0.1:7890` with your proxy. The proxy build-args are Docker's
predefined ones, so they do not need to be declared in the Dockerfile and are
not baked into the image.

---

## 7. Offline / pre-cloned curl

To avoid cloning inside the container (e.g. fully offline after a one-time
clone), mount a local curl checkout and point `--repo-curl` at it:

```bash
docker run --rm \
  -v /path/to/curl:/curl \
  -v "$PWD/demo-output:/demo-output" \
  patch-presence-demo --repo-curl /curl
```

(Use a full clone for offline source analysis; a `--filter=blob:none` clone
still fetches file blobs on demand.)

---

## 8. Quick reference

| Goal | Command (append after the image name) |
|------|----------------------------------------|
| Default (stages 1–2) | *(none)* |
| + reference compile | `--compile` |
| + target build | `--target-build` |
| + dataset generation | `--gen-dataset` |
| Full pipeline (3–6) | `--full` |
| Binary diff (needs docker.sock) | `--bindiff` |
| Use local curl | `--repo-curl /curl` |

Final line on success is always `Construction demo passed.`
