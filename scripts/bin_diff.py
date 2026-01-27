import json
import os
from pprint import pprint
import argparse
import subprocess
from collections import defaultdict
import shutil
import glob

ROOT_DIR = "/data/zhangxb"

def cleanup_binary_dir(binary_dir):
    """
    Cleanup binary directory:
    1. Delete all .md files
    2. Delete ghidra_projects, gzfs, symbols directories
    3. Rename json directory to bin_diff_raw
    """
    if not os.path.exists(binary_dir):
        return

    print(f"\n--- Starting cleanup of directory '{binary_dir}' ---")

    # 1. Delete .md files
    md_files = glob.glob(os.path.join(binary_dir, "*.md"))
    for f in md_files:
        try:
            os.remove(f)
            print(f"  Deleted: {f}")
        except OSError as e:
            print(f"  Deletion failed: {f}, {e}")

    # 2. Delete directories
    dirs_to_remove = ["ghidra_projects", "gzfs", "symbols"]
    for d in dirs_to_remove:
        dir_path = os.path.join(binary_dir, d)
        if os.path.exists(dir_path):
            try:
                shutil.rmtree(dir_path)
                print(f"  Deleted directory: {dir_path}")
            except OSError as e:
                print(f"  Directory deletion failed: {dir_path}, {e}")

    # 3. Rename json directory
    json_path = os.path.join(binary_dir, "json")
    bin_diff_raw_path = os.path.join(binary_dir, "bin_diff_raw")
    if os.path.exists(json_path):
        try:
            if os.path.exists(bin_diff_raw_path):
                # If target exists, merge or overwrite? Here we choose to remove target (or merge) before rename
                # For simplicity, if target exists, remove it first
                # Assuming rename is sufficient
                shutil.rmtree(bin_diff_raw_path) 
            os.rename(json_path, bin_diff_raw_path)
            print(f"  Renamed: '{json_path}' -> '{bin_diff_raw_path}'")
        except OSError as e:
            print(f"  Rename failed: {json_path}, {e}")

def run_ghidriff_analysis(project_name, binary_dir):
    """
    Run ghidriff analysis on the specified project and generate JSON result files.
    """
    base_dir = binary_dir
    # Save results to bin_diff_raw subdirectory
    project_dest_dir = f"./{project_name}-test/bin_diff_raw"
    log_dir = f"./{project_name}-test/logs"
    if not os.path.isdir(base_dir):
        print(f"Error: Project directory '{base_dir}' does not exist.")
        return
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(project_dest_dir, exist_ok=True)
    print(f"--- Starting Ghidriff analysis for project '{project_name}' ---")
    
    try:
        all_files = os.listdir(base_dir)
        filtered_files = [f for f in all_files if f.startswith("CVE") and not f.endswith(".i64")]
    except FileNotFoundError:
        print(f"Error: Cannot access directory '{base_dir}'.")
        return

    # Classify files by CVE-ID
    cve_pairs = defaultdict(dict)
    for filename in filtered_files:
        parts = filename.split('-')
        if len(parts) >= 3:
            cve_id = f"{parts[0]}-{parts[1]}-{parts[2]}"
            full_path = os.path.join(base_dir, filename)
            if 'vuln' in filename:
                cve_pairs[cve_id]['vuln'] = full_path
            elif 'patch' in filename:
                cve_pairs[cve_id]['patch'] = full_path

    print(f"Found {len(cve_pairs)} CVEs, preparing for pair analysis...")

    # Run ghidriff for each file pair
    for cve_id, files in sorted(cve_pairs.items()):
        if 'vuln' in files and 'patch' in files:
            dest_filename = f"{cve_id}-ghidriff.json"
            dest_filepath = os.path.join(project_dest_dir, dest_filename)
            
            if os.path.exists(dest_filepath):
                print(f"Skipping CVE: {cve_id} (result file '{dest_filepath}' already exists)")
                continue

            vuln_path = files['vuln']
            patch_path = files['patch']
            
            print(f"\nProcessing CVE: {cve_id}")
            print(f"  VULN: {os.path.basename(vuln_path)}")
            print(f"  PATCH: {os.path.basename(patch_path)}")

            vuln_filename = os.path.basename(vuln_path)
            patch_filename = os.path.basename(patch_path)

            # Get absolute path for Docker volume mount
            abs_base_dir = os.path.abspath(base_dir)
            print(abs_base_dir,vuln_filename,patch_filename)
            # Create Docker command
            command = [
                "docker", "run","--rm",
                "-v", f"{abs_base_dir}:/ghidriffs",
                "ghcr.io/clearbluejar/ghidriff:latest",
                # "ghidriff",
                f"ghidriffs/{vuln_filename}",
                f"ghidriffs/{patch_filename}"
            ]
            print(command)
            try:
                # 2. Run the command without shell=True
                #    text=True decodes stdout/stderr as text (recommended)
                result = subprocess.run(
                    command,
                    capture_output=True, # A convenient way to set stdout=PIPE and stderr=PIPE
                    text=True,
                    check=True, # Raises CalledProcessError on non-zero exit codes
                    env=os.environ.copy()
                )
                
                with open(f"{log_dir}/{cve_id}.log", 'w', encoding='utf-8') as f:
                    f.write(result.stdout)
                
                print(f"  Success: Analysis result saved to '{log_dir}/{cve_id}.log'")

                if result.stderr:
                    print("STDERR:")
                    print(result.stderr)
            except subprocess.CalledProcessError as e:
                print(f"Command failed with exit code {e.returncode}")
                print("STDERR:")
                print(e.stderr)
                print("STDOUT:")
                print(e.stdout)
            except FileNotFoundError:
                print("Error: 'docker' command not found. Is Docker installed and in your PATH?")
            # Verify if JSON file is generated and copy/rename it
            ghidriff_json_dir = os.path.join(base_dir, "json")
            try:
                source_json_files = [f for f in os.listdir(ghidriff_json_dir) if f.startswith(cve_id) and f.endswith(".ghidriff.json")]
                if source_json_files:
                    source_filename = source_json_files[0]
                    source_filepath = os.path.join(ghidriff_json_dir, source_filename)
                    
                    dest_filename = f"{cve_id}-ghidriff.json"
                    dest_filepath = os.path.join(project_dest_dir, dest_filename)
                    
                    shutil.copyfile(source_filepath, dest_filepath)
                    print(f"  Success: Copied and renamed '{source_filename}' to '{dest_filepath}'")
                else:
                    print(f"  Failure: No JSON file starting with '{cve_id}' found in '{ghidriff_json_dir}'.")
            except FileNotFoundError:
                print(f"  Failure: JSON output directory '{ghidriff_json_dir}' does not exist.")
        else:
            print(f"\nSkipping CVE: {cve_id} (missing vuln or patch file)")

    print("\n--- Ghidriff analysis completed ---")


def parse_ghidriff_json(filepath):
    """
    Parse Ghidriff JSON file to extract function change information.

    Args:
        filepath (str): Path to the JSON file.

    Returns:
        list: List of dictionaries containing all function change information.
    """
    if not os.path.exists(filepath):
        print(f"Error: File not found '{filepath}'")
        return []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"Error: File '{filepath}' is not valid JSON format.")
        return []


    results = []
    functions_data = data.get("functions", {})

    # 1. Process "added" functions
    for func in functions_data.get("added", []):
        results.append({
            "type": "added",
            "old_name": None,
            "new_name": func.get("name"),
            "diff_type": [],
            "has_diff": True, # Added functions always have a diff
            "old_length": None,
            "new_length": func.get("length")
        })

    # 2. Process "deleted" functions
    for func in functions_data.get("deleted", []):
        results.append({
            "type": "deleted",
            "old_name": func.get("name"),
            "new_name": None,
            "diff_type": [],
            "has_diff": True, # Deleted functions always have a diff
            "old_length": func.get("length"),
            "new_length": None
        })

    # 3. Process "modified" functions
    for func in functions_data.get("modified", []):
        old_func = func.get("old", {})
        new_func = func.get("new", {})
        
        # Check if 'diff' field has data
        has_diff_data = bool(func.get("diff", "").strip())

        results.append({
            "type": "modified",
            "old_name": old_func.get("name"),
            "new_name": new_func.get("name"),
            "diff_type": func.get("diff_type", []),
            "has_diff": has_diff_data,
            "old_length": old_func.get("length"),
            "new_length": new_func.get("length")
        })

    return results

def get_cve_id_from_filename(filename):
    """
    Extract CVE ID from filename.
    Filename format: CVE-YYYY-NNNNN-....
    CVE ID is the part before the third '-'.
    """
    parts = filename.split('-')
    if len(parts) >= 3:
        return f"{parts[0]}-{parts[1]}-{parts[2]}"
    return None

def create_cve_function_map(all_results):
    """
    Convert full analysis results into a concise CVE-function map.
    Entries with has_diff as False will be filtered out.
    """
    cve_map = defaultdict(list)
    for cve_id, functions in all_results.items():
        for func_info in functions:
            # Filter out functions with no actual differences
            if not func_info.get("has_diff"):
                continue

            change_type = func_info["type"]
            func_name = None
            if change_type == "added":
                func_name = func_info["new_name"]
            elif change_type == "deleted":
                func_name = func_info["old_name"]
            elif change_type == "modified":
                func_name = func_info["new_name"] # Prefer using new name

            if func_name:
                cve_map[cve_id].append({
                    "function": func_name,
                    "type": change_type
                })
    return cve_map


def main():
    """
    Main function, executes Ghidriff analysis (if project name provided), then parses all ghidriff files and outputs results.
    """
    parser = argparse.ArgumentParser(description="Run Ghidriff analysis and parse its JSON output.")
    parser.add_argument("-p", "--project", type=str, help="Project name to run Ghidriff analysis on.")
    parser.add_argument("-d", "--binary_dir", type=str, help="Directory where binary files exist.")
    args = parser.parse_args()

    # If project name provided, run Ghidriff analysis first
    if args.project:
        if args.binary_dir:
            run_ghidriff_analysis(args.project, args.binary_dir)
        else:
            print("Please provide binary file directory (-d/--binary_dir).")
            return
    else:
        print("Please provide a project name for analysis and parsing. Example: python parse.py -p tcpdump -d /***/binaries/reference/tcpdump")
        return

    # --- Continue with existing JSON parsing logic ---
    print("\n--- Starting to parse Ghidriff JSON output ---")
    json_dir = f"./{args.project}/bin_diff_raw" # Update to directory containing raw json
    if not os.path.isdir(json_dir):
        print(f"Error: Directory '{json_dir}' does not exist.")
        return
    all_results = {}    
    # Iterate over all files in the directory
    for filename in sorted(os.listdir(json_dir)):
        # Check if filename matches new pattern
        if filename.endswith("-ghidriff.json"):
            cve_id = get_cve_id_from_filename(filename)
            if not cve_id:
                print(f"Warning: Cannot extract CVE ID from '{filename}', skipped.")
                continue

            filepath = os.path.join(json_dir, filename)
            parsed_data = parse_ghidriff_json(filepath)
            
            # If parsing successful, store result keyed by CVE ID
            if parsed_data:
                if cve_id in all_results:
                    all_results[cve_id].extend(parsed_data)
                else:
                    all_results[cve_id] = parsed_data

    # Output directory (placed in project root, not inside bin_diff_raw)
    output_dir = f"./{args.project}"
    
    if all_results:
        # 1. Save full analysis results
        full_analysis_filename = f"{output_dir}/{args.project}_full_analysis.json"
        with open(full_analysis_filename, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=4, ensure_ascii=False)
        print(f"\nFull analysis results saved to: {full_analysis_filename}")

        # 2. Create and save CVE-function map
        cve_function_map = create_cve_function_map(all_results)
        map_filename = f"{output_dir}/{args.project}_bin_diff.json"
        with open(map_filename, 'w', encoding='utf-8') as f:
            json.dump(cve_function_map, f, indent=4, ensure_ascii=False)
        print(f"CVE-function map saved to: {map_filename}")

        # 3. Print final concise map to console
        print("\n--- Final CVE-function map results ---")
        print(json.dumps(cve_function_map, indent=4, ensure_ascii=False))
    else:
        print(f"No matching JSON files found or successfully parsed in directory '{json_dir}'.")
    
    # Finally execute cleanup work
    if args.binary_dir:
        cleanup_binary_dir(args.binary_dir)

if __name__ == "__main__":
    main()
