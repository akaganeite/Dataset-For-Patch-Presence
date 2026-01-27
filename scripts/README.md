# Dataset Construction Pipeline

This document outlines the multi-stage pipeline used to collect vulnerability data, analyze source code differences, compile binaries, and generate a validated ground truth dataset for patch presence testing.

## 1. CVE Data Collection

The initial phase involves acquiring and filtering vulnerability data for a specific `vendor:product`.

* **Database Initialization:**
* Backend: [CVE-Search](https://cve-search.github.io/cve-search/index.html).
* Update: The database is updated using `db_updater.py` with an NVD NIST API key.


* **Selection & Filtering:**
* **Script:** `project2cve.py`
* **Input:** `vendor:product` (e.g., `gnu:binutils`)
* **Process:** Fetch raw data -> Filter based on reference rules in `config.json` -> Ensure at least one affected version exists.
* **Output:** `raw.json` (Raw data)  `parsed.json` (Filtered list).



## 2. Diff Acquisition and Source Analysis

Retrieves specific code changes and identifies modified functions.

* **Selection:**
* **Script:** `select.py`
* **Action:** Selects the most recent  CVEs, saving the list to `chosen.txt`.


* **Diff Extraction:**
* **Script:** `cve2diff.py` (Requires GitHub API Token)
* **Action:** Incrementally retrieves remediation diff files, commit hashes, and timestamps.
* **Output:**
* Diff files: `Diff/{product}/diff_files/cve.diff`
* Metadata: `Diff/{product}/details.json` (Appends `{CVE_ID, commit, date}`).



* **Source Analysis:**
* **Script:** `source_analyzer.py`
* **Action:** Analyzes the repo to find functions changed by the diff.
* **Output:** Appends results to `source_diff.json`.



## 3. Reference Compilation and Binary Analysis

Generates and analyzes the ground truth binaries (Patch/Vuln pairs).

* **Reference Compilation:**
* **Script:** `compile_ref.py`
* **Action:** Compiles the repository based on `config.json` rules. It uses `source_diff.json` to verify that the target binaries actually correspond to the modified source files.
* **Output:** Reference binaries in the specified output directory.


* **Binary Analysis (Diffing):**
* **Tooling:** Uses **Ghidriff** (based on  Ghidra) to compare the compiled patch/vuln pairs.
* **Script:** `parse.py`
* **Output:**
* `bin_diff_raw/`: Raw JSON output from Ghidriff.
* `full_analysis.json`: Detailed statistics of binary differences.
* `bin_diff.json`: Consolidated difference data for the next step.





## 4. Binary Validation

Strict validation ensures the quality of the dataset.

* **Script:** `validate_bin.py`
* **Inputs:** `source_diff.json`, `bin_diff.json`, `details.json`.
* **Logic:** Merges source and binary difference data. It filters for cases where:
1. Both patch and vulnerable binaries exist.
2. All necessary function symbols are present.


* **Output:**
* `valid.json`: The strictly validated security dataset.
* `non-sec.json`: Non-security related changes (excluded, used for debugging).



## 5. Release Parsing & Target Compilation

Mapping CVEs to specific release versions and compiling target binaries.

* **Release Parsing:**
* **Script:** `tag_parser.py`
* **Action:** Parses repository tags (e.g., `binutils-2_10`) into normalized version numbers and dates.
* **Output:** `product_release.json`.


* **Target Compilation:**
* **Script:** `compile_target.py`
* **Action:** Compiles target binaries based on `versions.json`. Unlike reference compilation, this step does not verify specific symbols, as it generates the target pool.



## 6. Final Dataset Generation

Constructs the final JSON metadata files used for evaluation.

* **Script:** `gen_test_ref.py`
* **Inputs:** `valid.json`, `raw.json`, `product_release.json`.
* **Outputs:**
* **`testset.json`**: Maps CVEs to Ground Truth Vulnerable versions (`gt_vuln`), Patch versions (`gt_patch`), and the patch date.
* **`reference.json`**: Maps CVEs to specific reference binary filenames and the list of target functions.
* **`versions.json`**: Maps binaries to their specific version tags.



### Summary

The pipeline is now complete. It produces:

1. **Metadata:** `valid.json` (CVE info), `testset.json`, `reference.json`, `versions.json`.
2. **Artifacts:** Validated **Reference Binaries** (Ground Truth) and **Target Binaries** (Test Pool).