#!/usr/bin/env python3
"""Reduced dataset-construction demo (curl).

This demo exercises the real construction scripts shipped in ``scripts/`` on a
small set of 5 curl CVEs. It mirrors the construction pipeline documented in
``scripts/README.md`` and runs:

1. ``scripts/cve2diff.py``        -- diff acquisition (live download, falling
                                     back to the diffs cached under
                                     ``Dataset/Diffs/<project>/``).
2. ``scripts/source_analyzer.py`` -- per-CVE added/deleted/modified function
                                     analysis over the project's git history.
3. ``scripts/compile_ref.py``     -- reference patched/vulnerable binary
                                     compilation                (OPT-IN: --compile).
4. ``scripts/bin_diff.py``        -- ghidriff binary diffing of the patch/vuln
                                     pairs                       (OPT-IN: --bindiff).
5. ``scripts/compile_target.py``  -- target-pool compilation of release tags
                                     from a synthesized versions.json
                                                                 (OPT-IN: --target-build).
6. ``scripts/gen_test_ref.py``    -- final dataset generation: reference.json /
                                     testset.json / versions.json
                                                                 (OPT-IN: --gen-dataset).

Steps 1-2 are the reliable "getting-started" path and gate the demo result. The
opt-in stages are best-effort: building old sources on a modern toolchain and
running ghidriff are slow and can fail, so their failures are reported as
warnings and do not fail the demo (unless ``--strict-compile`` is given).

``--bindiff`` requires Docker (ghidriff runs as the sibling container
``ghcr.io/clearbluejar/ghidriff:0.5.2``) and implies ``--compile``.
``--gen-dataset`` implies ``--compile`` (it needs the reference binaries) and
fetches release/NVD metadata: it runs ``tag_parser.py`` when ``GITHUB_TOKEN`` is
set, otherwise derives releases from the local git tags, and pulls vulnerable
version ranges from the NVD REST API (no CVE-Search DB needed).
``--full`` enables ``--compile``, ``--bindiff``, ``--target-build`` and ``--gen-dataset``.

The demo needs network access to clone each project unless ``--repo-<project>``
points at an existing local checkout. See ``scripts/demo/README.md``.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEMO_DIR = ROOT / "scripts" / "demo"
CONFIG = json.loads((ROOT / "scripts" / "config.json").read_text(encoding="utf-8"))

# How many distinct release tags to build per project in the target-build stage.
MAX_TARGET_TAGS = 3

# Per-project configuration. The project key matches the directory name used in
# Dataset/, the product name expected by the construction scripts, and the
# compile_rule / tag_rules keys in scripts/config.json. The demo ships curl
# only; the per-project structure is kept so further projects can be added back.
PROJECTS: dict[str, dict] = {
    "curl": {
        "repo_url": "https://github.com/curl/curl.git",
        "repo_dir": "curl",
        "cve_file": DEMO_DIR / "curl_cves.txt",
    },
}


def run(cmd: list, *, cwd: Path | None = None, env: dict | None = None) -> None:
    print(f"$ {' '.join(str(c) for c in cmd)}", flush=True)
    subprocess.run([str(c) for c in cmd], cwd=str(cwd) if cwd else None, env=env, check=True)


def git_output(repo: Path, args: list[str]) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def tag_exists(repo: Path, tag: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def read_cves(path: Path) -> list[str]:
    cves: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", line):
            raise SystemExit(f"invalid CVE id in {path}: {line}")
        cves.append(line)
    if not cves:
        raise SystemExit(f"no CVEs found in {path}")
    return cves


def binary_names(project: str) -> list[str]:
    """Binary identifiers compile_ref/compile_target collect, from config.json."""
    rules = CONFIG.get("compile_rule", {}).get(project, {}).get("binary", [])
    return [rule[1] for rule in rules if len(rule) >= 2]


def vendor_product(project: str) -> tuple[str, str]:
    """CPE (vendor, product) for the project, from config.json vendor_map."""
    vp = CONFIG.get("vendor_map", {}).get(project, [project, project])
    return vp[0], vp[1]


def tag_to_version(project: str, tag: str) -> str | None:
    """Parse a git tag into a normalized version via config.json tag_rules (same as tag_parser.py)."""
    rule = CONFIG.get("tag_rules", {}).get(project, {})
    pattern = rule.get("tag_pattern")
    if not pattern:
        return tag
    match = re.match(pattern, tag)
    if not match:
        return None
    version = next((g for g in match.groups() if g is not None), None)
    if version is None:
        return None
    for old, new in rule.get("replace", {}).items():
        version = version.replace(old, new)
    return version


def version_to_tag(project: str, version: str) -> str:
    """Reverse the config.json tag_rules (tag -> version) to map a version to its git tag."""
    rule = CONFIG.get("tag_rules", {}).get(project, {})
    pattern = rule.get("tag_pattern", "(.+)")
    # Literal prefix = text before the first capture group, minus the leading anchor.
    head = pattern[1:] if pattern.startswith("^") else pattern
    prefix = head[: head.index("(")] if "(" in head else ""
    # tag->version applies replace as {old: new}; invert it for version->tag.
    inverted = {new: old for old, new in rule.get("replace", {}).items()}
    transformed = version
    for new, old in inverted.items():
        transformed = transformed.replace(new, old)
    return f"{prefix}{transformed}"


def is_git_worktree(repo: Path) -> bool:
    """True if ``repo`` is a git work tree (``.git`` may be a dir, a file, or a worktree)."""
    if not repo.exists():
        return False
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def ensure_repo(repo: Path, repo_url: str, *, external: bool, full_clone: bool) -> None:
    """Clone the project repo (blob-filtered by default) or refresh an existing one."""
    if is_git_worktree(repo):
        try:
            if external:
                run(["git", "fetch", "--tags"], cwd=repo)
            else:
                run(["git", "fetch", "--all", "--tags", "--prune"], cwd=repo)
        except subprocess.CalledProcessError:
            print(f"  [warn] could not refresh {repo} (offline?); using existing checkout")
        return
    if external:
        raise SystemExit(f"--repo does not point to a git checkout: {repo}")
    repo.parent.mkdir(parents=True, exist_ok=True)
    clone_cmd = ["git", "clone"]
    if not full_clone:
        clone_cmd += ["--filter=blob:none"]
    clone_cmd += [repo_url, str(repo)]
    try:
        run(clone_cmd)
    except subprocess.CalledProcessError as exc:
        if repo.exists():
            shutil.rmtree(repo)
        raise SystemExit(
            f"failed to clone {repo_url}. Re-run with --repo-<project> /path/to/checkout "
            "if a local clone is available."
        ) from exc


def write_cve_inputs(work: Path, project: str, cves: list[str]) -> Path:
    """Write the cveinfo/parsed.json and CVE list that cve2diff.py consumes."""
    cveinfo = work / "cveinfo" / project
    cveinfo.mkdir(parents=True, exist_ok=True)
    # References are left empty: live downloads are attempted where the handler
    # derives URLs on its own (e.g. curl), otherwise the cached-diff fallback
    # below supplies the diff. This keeps the demo runnable offline.
    parsed = [{"id": cve, "references": []} for cve in cves]
    (cveinfo / "parsed.json").write_text(json.dumps(parsed, indent=2), encoding="utf-8")
    cve_list = work / f"{project}_demo_cves.txt"
    cve_list.write_text("\n".join(cves) + "\n", encoding="utf-8")
    return cve_list


def run_cve2diff(work: Path, project: str, cve_list: Path, github_token: str) -> None:
    cmd = [sys.executable, str(ROOT / "scripts" / "cve2diff.py"), "-p", project, "-l", str(cve_list)]
    if github_token:
        cmd += ["-t", github_token]
    try:
        run(cmd, cwd=work)
    except subprocess.CalledProcessError:
        # cve2diff is best-effort; the cached-diff fallback below covers offline runs.
        print(f"  [warn] cve2diff.py reported an error for {project}; relying on cached diffs")


def cached_diff_for_cve(project: str, cve: str) -> Path | None:
    candidates = sorted((ROOT / "Dataset" / "Diffs" / project).glob(f"{project}_{cve}_*.diff"))
    return candidates[0] if candidates else None


def ensure_diff_available(work: Path, project: str, cve: str) -> Path:
    """Return a diff for the CVE: prefer a freshly downloaded one, else the cached artifact diff."""
    diff_dir = work / "Diff" / project / "diff_files"
    diff_dir.mkdir(parents=True, exist_ok=True)
    matches = sorted(diff_dir.glob(f"{project}_{cve}_*.diff"))
    if matches:
        return matches[0]
    cached = cached_diff_for_cve(project, cve)
    if not cached:
        raise SystemExit(f"no downloaded or cached diff found for {project} {cve}")
    dest = diff_dir / cached.name
    shutil.copy2(cached, dest)
    print(f"  using cached artifact diff for {cve}: {cached.relative_to(ROOT)}")
    return dest


def write_details(work: Path, project: str, repo: Path, cves: list[str]) -> Path:
    """Build Diff/<project>/details.json (cve -> resolved commit + date) for source_analyzer."""
    details = []
    for cve in cves:
        match = ensure_diff_available(work, project, cve)
        commit = match.stem.split("_")[-1]
        try:
            full_commit = git_output(repo, ["rev-parse", commit])
            date = git_output(repo, ["show", "-s", "--format=%cs", full_commit])
        except subprocess.CalledProcessError as exc:
            raise SystemExit(
                f"commit {commit} for {project} {cve} is not present in {repo.name}; "
                "is the clone complete?"
            ) from exc
        details.append({"cve": cve, "commit": full_commit, "date": date})
    details_path = work / "Diff" / project / "details.json"
    details_path.parent.mkdir(parents=True, exist_ok=True)
    details_path.write_text(json.dumps(details, indent=2), encoding="utf-8")
    return details_path


def run_source_analyzer(work: Path, project: str, repo: Path) -> Path:
    run(
        [sys.executable, str(ROOT / "scripts" / "source_analyzer.py"), "-p", project, "-r", str(repo)],
        cwd=work,
    )
    source_diff = work / "Diff" / project / "source_diff.json"
    if not source_diff.exists():
        raise SystemExit(f"source analyzer did not produce {source_diff.relative_to(work)}")
    return source_diff


def run_compile(work: Path, project: str, repo: Path, source_diff: Path, compiler: str, opt: str) -> Path:
    out_dir = work / "binaries" / "reference" / project
    run(
        [
            sys.executable,
            str(ROOT / "scripts" / "compile_ref.py"),
            "-p", project,
            "--repo", str(repo),
            "--json", str(source_diff),
            "--compiler", compiler,
            f"--opt={opt}",
            "--output", str(out_dir),
        ],
        cwd=work,
    )
    return out_dir


def run_bindiff(work: Path, project: str, reference_dir: Path) -> Path | None:
    """Run ghidriff binary diffing over the compiled patch/vuln pairs (best-effort).

    bin_diff.py drives the ghidriff Docker image and writes, relative to cwd:
      work/<project>/bin_diff_raw/<cve>-ghidriff.json
      work/<project>/<project>_bin_diff.json    (cve -> [{function, type}, ...])
    """
    pairs = [p for p in reference_dir.glob("CVE-*") if p.is_file()]
    if not pairs:
        print(f"  [warn] no compiled binaries in {reference_dir}; skipping bindiff for {project}")
        return None
    try:
        run(
            [sys.executable, str(ROOT / "scripts" / "bin_diff.py"), "-p", project, "-d", str(reference_dir)],
            cwd=work,
        )
    except subprocess.CalledProcessError:
        print(f"  [warn] bin_diff.py (ghidriff) failed for {project}; is Docker available?")
        return None
    bindiff_path = work / project / f"{project}_bin_diff.json"
    return bindiff_path if bindiff_path.exists() else None


def synthesize_versions(work: Path, project: str, cves: list[str], repo: Path) -> tuple[Path | None, list[str]]:
    """Build a small versions.json ({binary: [tags]}) for the target-build stage.

    Versions come from Dataset/testset/<project>.json for the demo CVEs, mapped to
    git tags via config.json tag_rules and kept only if the tag resolves in the repo.
    """
    testset_path = ROOT / "Dataset" / "testset" / f"{project}.json"
    testset = json.loads(testset_path.read_text(encoding="utf-8")) if testset_path.exists() else {}

    versions: list[str] = []
    for cve in cves:
        entry = testset.get(cve, {})
        for key in ("patch", "vuln"):
            vals = entry.get(key, [])
            if vals:
                versions.append(vals[0])  # one representative version per side

    tags: list[str] = []
    for version in versions:
        tag = version_to_tag(project, version)
        if tag not in tags and tag_exists(repo, tag):
            tags.append(tag)
        if len(tags) >= MAX_TARGET_TAGS:
            break

    if not tags:
        print(f"  [warn] no resolvable release tags for {project}; skipping target build")
        return None, []

    names = binary_names(project) or [project]
    versions_json = {name: list(tags) for name in names}
    versions_path = work / f"{project}_versions.json"
    versions_path.write_text(json.dumps(versions_json, indent=2), encoding="utf-8")
    print(f"  target tags for {project}: {', '.join(tags)}")
    return versions_path, tags


def run_target_build(work: Path, project: str, repo: Path, versions_path: Path, compiler: str, opt: str) -> Path:
    out_dir = work / "binaries" / "target" / project
    try:
        run(
            [
                sys.executable,
                str(ROOT / "scripts" / "compile_target.py"),
                "-p", project,
                "--repo", str(repo),
                "--versions", str(versions_path),
                "--compiler", compiler,
                f"--opt={opt}",
                "--output", str(out_dir),
            ],
            cwd=work,
        )
    except subprocess.CalledProcessError:
        print(f"  [warn] compile_target.py failed for {project}")
    return out_dir


# --- Stage 6: final dataset generation (gen_test_ref.py) -------------------

def generate_releases(work: Path, project: str, repo: Path, token: str) -> Path:
    """Release list [{tag, version, date}] for gen_test_ref.

    Prefers the real tag_parser.py (GitHub GraphQL, needs GITHUB_TOKEN); falls
    back to the local git tags when no token is available, so the stage still
    runs offline-ish without credentials.
    """
    releases_path = work / f"{project}_releases.json"
    if token:
        try:
            run(
                [sys.executable, str(ROOT / "scripts" / "tag_parser.py"),
                 "-p", project, "-t", token, "-o", str(releases_path)],
                cwd=work,
            )
            if releases_path.exists() and releases_path.stat().st_size > 2:
                print(f"  releases via tag_parser.py: {releases_path.name}")
                return releases_path
        except subprocess.CalledProcessError:
            print("  [warn] tag_parser.py failed; deriving releases from local git tags")
    # Fallback: derive from local git tags.
    out = git_output(repo, ["for-each-ref", "--format", "%(refname:short)\t%(creatordate:short)", "refs/tags/"])
    releases = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        tag, date = line.split("\t", 1)
        version = tag_to_version(project, tag)
        if version:
            releases.append({"tag": tag, "version": version, "date": date})
    releases_path.write_text(json.dumps(releases, indent=2), encoding="utf-8")
    print(f"  releases from local git tags: {len(releases)} versions")
    return releases_path


def _nvd_fetch(cve: str, retries: int = 3) -> dict | None:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=40) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - best-effort network
            print(f"  [warn] NVD fetch {cve} attempt {attempt + 1} failed: {exc}")
            time.sleep(8)
    return None


def fetch_nvd_raw(work: Path, project: str, cves: list[str], release_versions: set[str]) -> Path:
    """Build a CVE-Search-style raw.json by expanding NVD version ranges.

    NVD 2.0 expresses affected versions as ranges (versionEndExcluding, ...);
    gen_test_ref expects enumerated cpe:2.3 entries, so we enumerate every known
    release version that falls in the affected range. Replaces the CVE-Search /
    project2cve.py path, which needs a local database.
    """
    from packaging.version import parse as vparse

    vendor, product = vendor_product(project)

    def in_range(version: str, match: dict) -> bool:
        try:
            pv = vparse(version)
        except Exception:  # noqa: BLE001
            return False
        try:
            if match.get("versionStartIncluding") and pv < vparse(match["versionStartIncluding"]):
                return False
            if match.get("versionStartExcluding") and pv <= vparse(match["versionStartExcluding"]):
                return False
            if match.get("versionEndIncluding") and pv > vparse(match["versionEndIncluding"]):
                return False
            if match.get("versionEndExcluding") and pv >= vparse(match["versionEndExcluding"]):
                return False
        except Exception:  # noqa: BLE001
            return False
        return True

    raw_items = []
    for cve in cves:
        data = _nvd_fetch(cve)
        cpes: set[str] = set()
        if data and data.get("vulnerabilities"):
            cve_obj = data["vulnerabilities"][0]["cve"]
            for config in cve_obj.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable"):
                            continue
                        parts = match.get("criteria", "").split(":")
                        if len(parts) < 6 or parts[4] != product:
                            continue
                        vfield = parts[5]
                        if vfield not in ("*", "-"):
                            cpes.add(f"cpe:2.3:a:{vendor}:{product}:{vfield}:*:*:*:*:*:*:*")
                        else:
                            for rv in release_versions:
                                if in_range(rv, match):
                                    cpes.add(f"cpe:2.3:a:{vendor}:{product}:{rv}:*:*:*:*:*:*:*")
        raw_items.append({"id": cve, "vulnerable_configuration": sorted(cpes)})
        print(f"  NVD {cve}: {len(cpes)} enumerated vulnerable versions")
        time.sleep(6)  # NVD public rate limit (no API key)
    raw_path = work / f"{project}_nvd_raw.json"
    raw_path.write_text(json.dumps(raw_items, indent=2), encoding="utf-8")
    return raw_path


def build_valid(work: Path, project: str, source_diff: Path, details_path: Path) -> Path:
    """valid.json [{cve, functions, date}] from source analysis + commit dates."""
    source = load_json(source_diff)
    details = {d["cve"]: d for d in load_json(details_path)} if details_path.exists() else {}
    valid = [
        {
            "cve": cve,
            "functions": [a["function"] for a in entry.get("analysis", []) if "function" in a],
            "date": details.get(cve, {}).get("date", ""),
        }
        for cve, entry in source.items()
    ]
    valid_path = work / f"{project}_valid.json"
    valid_path.write_text(json.dumps(valid, indent=2), encoding="utf-8")
    return valid_path


def run_gen_dataset(work: Path, project: str, repo: Path, source_diff: Path,
                    reference_dir: Path, cves: list[str], token: str) -> Path | None:
    """Stage 6: assemble inputs and run gen_test_ref.py -> reference/testset/versions."""
    if not reference_dir or not reference_dir.exists():
        print(f"  [warn] no reference binaries for {project}; skipping dataset generation")
        return None
    try:
        releases_path = generate_releases(work, project, repo, token)
        release_versions = {r["version"] for r in load_json(releases_path)}
        raw_path = fetch_nvd_raw(work, project, cves, release_versions)
        valid_path = build_valid(work, project, source_diff, work / "Diff" / project / "details.json")
        dataset_dir = work / "dataset" / project
        dataset_dir.mkdir(parents=True, exist_ok=True)
        run(
            [sys.executable, str(ROOT / "scripts" / "gen_test_ref.py"),
             "-p", project,
             "-v", str(valid_path),
             "-r", str(raw_path),
             "--releases", str(releases_path),
             "-d", str(reference_dir),
             "-o", str(dataset_dir)],
            cwd=work,
        )
        return dataset_dir
    except Exception as exc:  # noqa: BLE001 - stage 6 is best-effort, never fatal
        print(f"  [warn] dataset generation failed for {project}: {exc}")
        return None


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def build_project_summary(
    work: Path,
    project: str,
    cves: list[str],
    source_diff: Path,
    reference_dir: Path | None,
    bindiff_path: Path | None,
    target_dir: Path | None,
    dataset_dir: Path | None = None,
) -> dict:
    source = load_json(source_diff)
    diff_files = sorted(
        str(p.relative_to(work)) for p in (work / "Diff" / project / "diff_files").glob("*.diff")
    )
    bindiff_map = load_json(bindiff_path) if bindiff_path and bindiff_path.exists() else {}

    per_cve = {}
    for cve in cves:
        entry = source.get(cve, {})
        funcs = [a["function"] for a in entry.get("analysis", []) if "function" in a]
        binaries = []
        if reference_dir and reference_dir.exists():
            binaries = sorted(p.name for p in reference_dir.glob(f"{cve}-*"))
        bindiff_funcs = [b.get("function") for b in bindiff_map.get(cve, []) if b.get("function")]
        per_cve[cve] = {
            "commit": entry.get("commit"),
            "functions": funcs,
            "reference_binaries": binaries,
            "bindiff_functions": bindiff_funcs,
        }

    target_binaries = []
    if target_dir and target_dir.exists():
        target_binaries = sorted(p.name for p in target_dir.glob("*") if p.is_file())

    dataset = {}
    if dataset_dir and dataset_dir.exists():
        for name in ("reference", "testset", "versions"):
            path = dataset_dir / f"{name}.json"
            if path.exists():
                data = load_json(path)
                dataset[name] = len(data)

    return {
        "project": project,
        "cves": cves,
        "diff_files": diff_files,
        "source_analysis_cves": sorted(source.keys()),
        "per_cve": per_cve,
        "target_binaries": target_binaries,
        "dataset": dataset,
    }


def validate_project(summary: dict, cves: list[str], *, compiled: bool, strict_compile: bool) -> list[str]:
    """Hard-validate diff + source analysis; report (and optionally enforce) compile coverage."""
    project = summary["project"]
    warnings: list[str] = []

    missing_source = sorted(set(cves) - set(summary.get("source_analysis_cves", [])))
    if missing_source:
        raise SystemExit(f"[{project}] source analysis missing CVEs: {missing_source}")
    for cve in cves:
        if not any(cve in p for p in summary.get("diff_files", [])):
            raise SystemExit(f"[{project}] diff file missing for {cve}")
        if not summary["per_cve"][cve]["functions"]:
            raise SystemExit(f"[{project}] no changed functions found for {cve}")

    if compiled:
        for cve in cves:
            binaries = summary["per_cve"][cve]["reference_binaries"]
            if len(binaries) < 2:
                msg = f"[{project}] {cve}: expected patched+vulnerable binaries, found {len(binaries)}"
                if strict_compile:
                    raise SystemExit(msg)
                warnings.append(msg)
    return warnings


def process_project(project: str, args: argparse.Namespace, work: Path, output: Path) -> dict:
    cfg = PROJECTS[project]
    cve_file = Path(getattr(args, f"cve_file_{project}") or cfg["cve_file"]).expanduser().resolve()
    cves = read_cves(cve_file)

    external_repo = getattr(args, f"repo_{project}")
    if external_repo:
        repo = Path(external_repo).expanduser().resolve()
    else:
        repo = output / "repos" / cfg["repo_dir"]

    print(f"\n{'=' * 70}")
    print(f"Project: {project}  ({len(cves)} CVEs: {', '.join(cves)})")
    print(f"  repo: {repo}")
    print(f"{'=' * 70}")

    ensure_repo(repo, cfg["repo_url"], external=external_repo is not None, full_clone=args.full_clone)
    cve_list = write_cve_inputs(work, project, cves)
    run_cve2diff(work, project, cve_list, args.github_token)
    write_details(work, project, repo, cves)
    source_diff = run_source_analyzer(work, project, repo)

    reference_dir = None
    bindiff_path = None
    if args.compile:
        reference_dir = run_compile(work, project, repo, source_diff, args.compiler, args.opt)
        if args.bindiff:
            bindiff_path = run_bindiff(work, project, reference_dir)

    target_dir = None
    if args.target_build:
        versions_path, tags = synthesize_versions(work, project, cves, repo)
        if versions_path:
            target_dir = run_target_build(work, project, repo, versions_path, args.compiler, args.opt)

    dataset_dir = None
    if args.gen_dataset:
        dataset_dir = run_gen_dataset(work, project, repo, source_diff, reference_dir, cves, args.github_token)

    summary = build_project_summary(
        work, project, cves, source_diff, reference_dir, bindiff_path, target_dir, dataset_dir
    )
    summary["warnings"] = validate_project(
        summary, cves, compiled=args.compile, strict_compile=args.strict_compile
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reduced curl dataset-construction demo.")
    parser.add_argument("--output", type=Path, default=Path("/tmp/patch-presence-demo"))
    parser.add_argument(
        "--compile",
        action="store_true",
        help="Run compile_ref.py to build reference patch/vuln binaries (slow, best-effort).",
    )
    parser.add_argument(
        "--bindiff",
        action="store_true",
        help="Run bin_diff.py (ghidriff via Docker) on the compiled pairs. Implies --compile.",
    )
    parser.add_argument(
        "--target-build",
        dest="target_build",
        action="store_true",
        help="Run compile_target.py to build a few release-tag target binaries (best-effort).",
    )
    parser.add_argument(
        "--gen-dataset",
        dest="gen_dataset",
        action="store_true",
        help="Run gen_test_ref.py to build reference/testset/versions.json. Implies --compile.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Enable --compile, --bindiff, --target-build and --gen-dataset.",
    )
    parser.add_argument(
        "--strict-compile",
        action="store_true",
        help="With --compile, treat any missing reference binary as a hard failure.",
    )
    parser.add_argument("--compiler", default="gcc")
    parser.add_argument("--opt", default="-O0")
    parser.add_argument(
        "--ghidriff-image",
        dest="ghidriff_image",
        default=None,
        help="Override the ghidriff Docker image used by --bindiff "
        "(default: bin_diff.py's pinned ghcr.io/clearbluejar/ghidriff:0.5.2).",
    )
    parser.add_argument(
        "--full-clone",
        action="store_true",
        help="Clone full blobs instead of a blob:none partial clone (larger, fully offline analysis).",
    )
    parser.add_argument("--no-clean", action="store_true", help="Reuse the output directory.")
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""))
    for project, cfg in PROJECTS.items():
        parser.add_argument(
            f"--repo-{project}",
            dest=f"repo_{project}",
            default=None,
            help=f"Use an existing local {project} checkout instead of cloning.",
        )
        parser.add_argument(
            f"--cve-file-{project}",
            dest=f"cve_file_{project}",
            default=None,
            help=f"Override the CVE list for {project} (default: {cfg['cve_file'].name}).",
        )
    args = parser.parse_args()
    if args.full:
        args.compile = args.bindiff = args.target_build = args.gen_dataset = True
    if args.bindiff or args.gen_dataset:
        args.compile = True
    return args


def main() -> int:
    args = parse_args()
    projects = list(PROJECTS)

    if args.ghidriff_image:
        os.environ["GHIDRIFF_IMAGE"] = args.ghidriff_image  # inherited by bin_diff.py subprocess

    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    if not args.no_clean:
        # Clear the contents rather than the directory itself: --output may be a
        # bind mount (docker -v), and removing the mount point raises EBUSY.
        for child in output.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
    work = output / "work"
    work.mkdir(parents=True, exist_ok=True)

    stages = ["cve2diff", "source_analyzer"]
    if args.compile:
        stages.append("compile_ref")
    if args.bindiff:
        stages.append("bin_diff/ghidriff")
    if args.target_build:
        stages.append("compile_target")
    if args.gen_dataset:
        stages.append("gen_test_ref")

    print("Reduced curl construction demo")
    print(f"- projects: {', '.join(projects)}")
    print(f"- output:   {output}")
    print(f"- stages:   {' -> '.join(stages)}")

    summaries = [process_project(project, args, work, output) for project in projects]

    overall = {"projects": summaries}
    summary_path = work / "demo_summary.json"
    summary_path.write_text(json.dumps(overall, indent=2), encoding="utf-8")

    print(f"\n{'=' * 70}\nDEMO SUMMARY\n{'=' * 70}")
    all_warnings: list[str] = []
    for summary in summaries:
        project = summary["project"]
        n_funcs = sum(len(v["functions"]) for v in summary["per_cve"].values())
        line = (
            f"- {project:<12} {len(summary['cves'])} CVEs | "
            f"{len(summary['diff_files'])} diffs | {n_funcs} changed functions"
        )
        if args.compile:
            n_bins = sum(len(v["reference_binaries"]) for v in summary["per_cve"].values())
            line += f" | {n_bins} ref binaries"
        if args.bindiff:
            n_bd = sum(len(v["bindiff_functions"]) for v in summary["per_cve"].values())
            line += f" | {n_bd} bindiff funcs"
        if args.target_build:
            line += f" | {len(summary['target_binaries'])} target binaries"
        if args.gen_dataset:
            ds = summary.get("dataset", {})
            line += f" | dataset ref={ds.get('reference', 0)} testset={ds.get('testset', 0)}"
        print(line)
        all_warnings += summary.get("warnings", [])

    if all_warnings:
        print("\nWarnings (non-fatal):")
        for warning in all_warnings:
            print(f"  ! {warning}")

    print(f"\nSummary written to {summary_path}")
    print("Construction demo passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
