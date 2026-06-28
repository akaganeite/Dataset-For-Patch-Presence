#!/usr/bin/env python3
from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECTS = {
    "binutils",
    "curl",
    "ffmpeg",
    "freetype",
    "imagemagick",
    "libxml2",
    "openjpeg",
    "openssl",
    "sqlite",
    "tcpdump",
}
TOOLS = {"BinXray", "PatchDiscovery", "PS3", "React", "Robin"}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        fail(f"failed to load JSON {path.relative_to(ROOT)}: {exc}")


def load_pickle(path: Path):
    try:
        with path.open("rb") as handle:
            return pickle.load(handle)
    except Exception as exc:
        fail(f"failed to load pickle {path.relative_to(ROOT)}: {exc}")


def check_required_paths() -> None:
    required = [
        "Dataset/Diffs",
        "Dataset/reference",
        "Dataset/testset",
        "Dataset/target_functions.json",
        "RQs",
        "results",
        "scripts",
        "README.md",
        "REQUIREMENTS.md",
        "STATUS.md",
        "LICENSE",
    ]
    for rel in required:
        path = ROOT / rel
        if not path.exists():
            fail(f"missing required path: {rel}")


def check_dataset_metadata() -> tuple[int, int]:
    testset_total = 0
    reference_total = 0
    for project in sorted(PROJECTS):
        testset_path = ROOT / "Dataset" / "testset" / f"{project}.json"
        reference_path = ROOT / "Dataset" / "reference" / f"{project}.json"
        if not testset_path.exists():
            fail(f"missing testset metadata for {project}")
        if not reference_path.exists():
            fail(f"missing reference metadata for {project}")
        testset = load_json(testset_path)
        reference = load_json(reference_path)
        if not isinstance(testset, dict):
            fail(f"{testset_path.relative_to(ROOT)} must be a JSON object")
        if not isinstance(reference, list):
            fail(f"{reference_path.relative_to(ROOT)} must be a JSON array")
        testset_total += len(testset)
        reference_total += len(reference)

    targets = load_json(ROOT / "Dataset" / "target_functions.json")
    if not isinstance(targets, dict):
        fail("Dataset/target_functions.json must be a JSON object")

    if testset_total != 562:
        fail(f"unexpected testset CVE count: {testset_total}, expected 562")
    if reference_total != 559:
        fail(f"unexpected reference CVE count: {reference_total}, expected 559")
    return testset_total, reference_total


def check_results() -> int:
    result_files = 0
    for tool in sorted(TOOLS):
        tool_dir = ROOT / "results" / tool
        if not tool_dir.is_dir():
            fail(f"missing result directory for {tool}")
        files = sorted(tool_dir.glob("*.pkl"))
        if not files:
            fail(f"no result pickle files found for {tool}")
        for path in files:
            data = load_pickle(path)
            if not isinstance(data, (dict, list)):
                fail(f"{path.relative_to(ROOT)} should contain a dict or list")
            result_files += 1
    summary = load_json(ROOT / "results" / "backport_summary.json")
    if not isinstance(summary, (dict, list)):
        fail("results/backport_summary.json should contain a JSON object or list")
    return result_files


def check_rq_data() -> int:
    required = [
        "extended_testset.json",
        "common_failure_patterns.json",
        "cwe_mapping.json",
        "semantic_patterns.json",
        "patch_evolution.json",
        "function_size.pkl",
        "patch_size.pkl",
    ]
    count = 0
    for name in required:
        path = ROOT / "RQs" / name
        if not path.exists():
            fail(f"missing RQ data file: {name}")
        if path.suffix == ".json":
            load_json(path)
        elif path.suffix == ".pkl":
            load_pickle(path)
        count += 1
    deployed = ROOT / "RQs" / "deployed_binaries"
    if not deployed.is_dir():
        fail("missing RQs/deployed_binaries")
    for path in sorted(deployed.glob("*.json")):
        load_json(path)
        count += 1
    return count


def main() -> int:
    check_required_paths()
    testset_total, reference_total = check_dataset_metadata()
    result_files = check_results()
    rq_files = check_rq_data()

    print("Artifact smoke test summary:")
    print(f"- projects: {len(PROJECTS)}")
    print(f"- testset CVE entries: {testset_total}")
    print(f"- reference CVE entries: {reference_total}")
    print(f"- result pickle files: {result_files}")
    print(f"- RQ data files checked: {rq_files}")
    print("Artifact smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
