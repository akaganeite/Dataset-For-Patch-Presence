import json
import re
import argparse
from pathlib import Path
import os
import subprocess

def get_symbols(bin_path):
    """Run nm on binary to get list of symbols."""
    try:
        # -P: portable output
        # -t d: decimal radix (optional)
        # We just want the names.
        cmd = ["nm", str(bin_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return set()
            
        symbols = set()
        for line in result.stdout.splitlines():
            # Typical nm output: "address type name" or "type name"
            parts = line.split()
            if len(parts) >= 3:
                symbols.add(parts[2])
            elif len(parts) == 2:
                symbols.add(parts[1])
        return symbols
    except Exception as e:
        print(f"Error running nm on {bin_path}: {e}")
        return set()

def parse_details_file(filepath):
    """
    解析 details.json 文件，返回 CVE 到 详细信息(commit, date) 的映射。
    """
    cve_details = {}
    if not filepath.exists():
        print(f"错误: 未找到 details 文件: {filepath}")
        return cve_details
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        for item in data:
            cve = item.get("cve")
            commit = item.get("commit")
            date = item.get("date")
            if cve and commit:
                cve_details[cve] = {"commit": commit, "date": date}
    except json.JSONDecodeError:
        print(f"错误: 无法解析 JSON 文件: {filepath}")
    except Exception as e:
        print(f"错误: 读取 details 文件时发生错误: {e}")

    return cve_details

def normalize_code_line(line):
    """移除行中的空格和圆括号"""
    return line.replace(" ", "").replace("(", "").replace(")", "")

def analyze_diff(diff_content, function_name):
    """
    在 diff 内容中找到指定函数的 hunk，并比较其 +/- 行。
    如果标准化后的 +/- 行完全一致，返回 True (no code changes)，否则返回 False。
    """
    # 正则表达式匹配 hunk header，可能包含函数上下文
    hunk_header_pattern = re.compile(r'@@ .*? @@.*?' + re.escape(function_name), re.DOTALL)
    hunks = diff_content.split('@@')
    
    relevant_hunk = ""
    # 找到包含函数名的 hunk
    for i in range(1, len(hunks), 2):
        header_and_body = hunks[i] + hunks[i+1] if i+1 < len(hunks) else hunks[i]
        if function_name in header_and_body:
            relevant_hunk = "@@" + header_and_body
            break

    if not relevant_hunk:
        return False # 无法确认，保守地认为有变化

    plus_lines = []
    minus_lines = []
    for line in relevant_hunk.splitlines():
        if line.startswith('+'):
            line_content = line[1:]
            if line_content.strip():
                plus_lines.append(line_content)
        elif line.startswith('-'):
            line_content = line[1:]
            if line_content.strip():
                minus_lines.append(line_content)

    # 如果过滤后没有 +/- 行，说明变化只是空行，我们认为这不算实质性变更
    if not plus_lines and not minus_lines:
        return True

    normalized_plus = normalize_code_line("".join(plus_lines))
    normalized_minus = normalize_code_line("".join(minus_lines))

    return normalized_plus == normalized_minus

def parse_source_diff(filepath, project):
    """Reads source_diff.json."""
    if not filepath.exists():
        print(f"警告: 未找到源码 diff 文件: {filepath}")
        return {}, {}
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Try getting project data directly or keys might be CVEs directly if format varies
    # Based on provided source_diff.json, the root object has keys like "CVE-2014-8484".
    # It does NOT have a project key wrapping them.
    
    if project in data:
        project_data = data[project]
    else:
        # Assume the file content IS the project data
        project_data = data
        
    source_funcs = {}
    cve_dates = {}
    
    for cve, cve_data in project_data.items():
        functions = set()
        analysis_list = cve_data.get("analysis", [])
        for item in analysis_list:
            if "function" in item:
                functions.add(item["function"])
        source_funcs[cve] = functions
        
        # Capture date if available in source_diff metadata
        # assuming it might be in 'date' or not present
        if 'date' in cve_data:
            cve_dates[cve] = cve_data['date']
            
    return source_funcs, cve_dates

def parse_bin_diff(filepath):
    """Reads bin_diff.json."""
    if not filepath.exists():
        print(f"警告: 未找到二进制 diff 文件: {filepath}")
        return {}
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    bin_funcs = {}
    for cve, analysis_list in data.items():
        functions = set()
        for item in analysis_list:
            if "function" in item:
                functions.add(item["function"])
        bin_funcs[cve] = functions
    return bin_funcs

def main():
    parser = argparse.ArgumentParser(description="Merge diff analysis results.")
    parser.add_argument("-p", "--project", required=True, help="Project name (e.g. binutils)")
    parser.add_argument("-b", "--base-dir", default=".", help="Base directory for project files")
    parser.add_argument("-d", "--diff-dir", help="Directory containing .diff files (default: base-dir/project/diff_files)")
    parser.add_argument("--bin-dir", help="Directory containing compiled binaries (to filter valid CVEs)")
    parser.add_argument("-o", "--output-dir", help="Output directory")
    
    args = parser.parse_args()
    
    base_path = Path(args.base_dir)
    project = args.project
    project_path = base_path / project
    
    source_diff_file = project_path / 'source_diff.json'
    bin_diff_file = project_path / 'bin_diff.json'
    details_file = project_path / 'details.json'
    diff_dir = Path(args.diff_dir) if args.diff_dir else project_path / 'diff_files'
    
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = project_path
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Parse Input Files
    print("[*] Parsing source_diff.json...")
    source_funcs, cve_dates = parse_source_diff(source_diff_file, project)
    
    print("[*] Parsing bin_diff.json...")
    bin_funcs = parse_bin_diff(bin_diff_file)
    
    print("[*] Parsing details file...")
    cve_details = parse_details_file(details_file)

    bin_files = set()
    if args.bin_dir:
        bin_dir_path = Path(args.bin_dir)
        if bin_dir_path.exists():
            print(f"[*] Scanning binary directory: {bin_dir_path}")
            bin_files = set(os.listdir(bin_dir_path))
        else:
            print(f"Warning: Binary directory {bin_dir_path} does not exist. No CVEs will be filtered by binary existence.")

    valid_cves = set(source_funcs.keys())
    
    final_valid_list = []
    final_non_sec_map = {}

    print("[*] Processing CVEs...")
    print("Valid CVEs:", valid_cves)
    for cve in valid_cves:
        # Check if binaries exist (if bin_dir provided)
        if args.bin_dir:
            has_vuln = any(f.startswith(f"{cve}-vuln") for f in bin_files)
            has_patch = any(f.startswith(f"{cve}-patch") for f in bin_files)
            if not (has_vuln and has_patch):
                # Only consider CVEs with both patch and vuln binaries
                continue

        s_source = source_funcs.get(cve, set())
        s_bin = bin_funcs.get(cve, set())

        # Logic:
        # 1. Intersection (Common functions): keep
        common_funcs = s_source.intersection(s_bin)
        
        # 2. Only in bin_diff: discard (implied by taking intersection as base)
        
        # 3. Only in source_diff: Check non-sec status
        only_source_funcs = s_source - s_bin
        
        kept_source_only_funcs = set()
        non_sec_funcs = []
        
        if only_source_funcs:
            cve_info = cve_details.get(cve)
            commit_hash = cve_info["commit"] if cve_info else None
            if commit_hash:
                diff_filename = f"{project}_{cve}_{commit_hash}.diff"
                diff_file = diff_dir / diff_filename
                
                if diff_file.exists():
                    with open(diff_file, 'r', encoding='utf-8', errors='ignore') as f:
                        diff_content = f.read()
                    
                    for func in only_source_funcs:
                        # Check if diff is substantial
                        is_signature_only = analyze_diff(diff_content, func)
                        if is_signature_only:
                            # If no code change, it's non-sec, discard it (don't add to valid)
                            # But add to non-sec report? 
                            # User said: "non_sec_parsed中的不要，其余的留下"
                            # "其余的" means if it HAS changes (is_signature_only=False), we KEEP it.
                            non_sec_funcs.append(func) # Report as discarded non-sec
                        else:
                            kept_source_only_funcs.add(func)
                else:
                    # Missing diff file, conservative approach: keep them? Or discard?
                    # Let's keep them and maybe warn.
                    print(f"Warning: Diff file missing for {cve}, keeping {len(only_source_funcs)} extra source functions.")
                    kept_source_only_funcs.update(only_source_funcs)
            else:
                 print(f"Warning: No hash for {cve}, skipping source-only functions check.")
        
        # Combine common and kept source-only functions
        final_funcs = list(common_funcs.union(kept_source_only_funcs))
        
        # Verify symbols in binaries if bin-dir is provided
        if final_funcs and args.bin_dir:
            # Locate clean binaries (no extensions)
            vuln_bin_name = next((f for f in bin_files if f.startswith(f"{cve}-vuln") and "." not in f), None)
            patch_bin_name = next((f for f in bin_files if f.startswith(f"{cve}-patch") and "." not in f), None)
            
            if vuln_bin_name and patch_bin_name:
                vuln_path = bin_dir_path / vuln_bin_name
                patch_path = bin_dir_path / patch_bin_name
                
                v_syms = get_symbols(vuln_path)
                p_syms = get_symbols(patch_path)
                
                # Check each function
                valid_funcs = []
                for func in final_funcs:
                    if func in v_syms and func in p_syms:
                        valid_funcs.append(func)
                    else:
                        print(f"Warning: Function '{func}' missing in binary symbols for {cve} (Vuln: {func in v_syms}, Patch: {func in p_syms}). Removing from valid list.")
                
                if len(valid_funcs) != len(final_funcs):
                    final_funcs = valid_funcs
            else:
                # If we can't find the binary files to check, standard check previously filtered them, 
                # but maybe the extension check here is stricter.
                # If not found, effectively we can't verify. 
                # User asked to "ensure", so maybe we should warn?
                print(f"Warning: Could not find clean binary files for {cve} to verify symbols. Skipping verification.")

        if final_funcs:
            # We have valid functions for this CVE
            cve_info = cve_details.get(cve)
            commit_hash = cve_info.get("commit", "") if cve_info else ""
            date_val = cve_info.get("date", "") if cve_info else cve_dates.get(cve, "")
            
            entry = {
                "cve": cve,
                "patch-commit": commit_hash,
                "vuln-commit": commit_hash,
                "functions": final_funcs,
                "date": date_val
            }
            final_valid_list.append(entry)
            
        if non_sec_funcs:
            final_non_sec_map[cve] = non_sec_funcs

    # Write Output
    valid_json_path = output_dir / "valid.json"
    non_sec_json_path = output_dir / "non-sec.json"
    
    print(f"[*] Writing valid.json to {valid_json_path} with {len(final_valid_list)} entries.")
    with open(valid_json_path, 'w', encoding='utf-8') as f:
        json.dump(final_valid_list, f, indent=2)
        
    print(f"[*] Writing non-sec.json to {non_sec_json_path} with {len(final_non_sec_map)} entries.")
    with open(non_sec_json_path, 'w', encoding='utf-8') as f:
        json.dump(final_non_sec_map, f, indent=2)

    print("[*] Done.")

if __name__ == "__main__":
    main()
