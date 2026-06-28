import os
import sys
import json
import argparse
import datetime
from collections import defaultdict
from datetime import datetime as dt

def parse_args():
    parser = argparse.ArgumentParser(description='Generate testset.json and reference.json')
    parser.add_argument('-p', '--project', required=True, help='Project name')
    parser.add_argument('-v', '--valid', required=True, help='Path to valid.json')
    parser.add_argument('-r', '--raw', required=True, help='Path to raw NVD json')
    parser.add_argument('--releases', required=True, help='Path to releases json (e.g., binutils.json)')
    parser.add_argument('-d', '--bin-dir', required=True, help='Directory containing binaries')
    parser.add_argument('-o', '--output-dir', required=True, help='Output directory')
    return parser.parse_args()

def load_json(path):
    if not os.path.exists(path):
        print(f"Error: File not found {path}")
        return None
    with open(path, 'r') as f:
        return json.load(f)

def load_release_map(path):
    data = load_json(path)
    if not data:
        return {}, {}
    
    release_map = {}
    version_tag_map = {}
    # Supports list format from binutils.json: [{"version": "2.10", "date": "..."}]
    if isinstance(data, list):
        for item in data:
            v = item.get('norm_tag', item.get('version'))
            d_str = item.get('date')
            tag = item.get('tag')
            if v and d_str:
                try:
                    # Try full timestamp first
                    date_obj = dt.strptime(d_str, "%Y-%m-%d %H:%M:%S").date()
                except ValueError:
                    try:
                        # Try only date
                        date_obj = dt.strptime(d_str, "%Y-%m-%d").date()
                    except ValueError:
                        continue
                release_map[v] = date_obj
                if tag:
                    version_tag_map[v] = tag
    print(f"DEBUG: Loaded {len(release_map)} releases.")
    return release_map, version_tag_map

def find_cpe_vendor_product(project):
    """Define CPE vendor and product mapping"""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    if not os.path.exists(config_path):
        # Fallback if config not found (or raise error)
        print(f"Warning: config.json not found at {config_path}")
        return [project, project]

    with open(config_path, 'r') as f:
        config = json.load(f)
    
    vendor_map = config.get("vendor_map", {})
    return vendor_map.get(project.lower(), [project, project])

def parse_nvd_vuln_versions(raw_data, cve_id, project, vendor, product):
    """Extract vulnerable versions from NVD raw item"""
    vuln_versions = set()
    
    # scan raw_data list for this cve
    # Optimize: outside call should probably build a map cve->item first if calling many times
    # But here we loop CVEs in calling function, so let's pass the specific item or find it.
    
    item = next((x for x in raw_data if x.get("id") == cve_id), None)
    if not item:
        print(f"DEBUG: {cve_id} not found in raw NVD data.")
        return set()
    
    vulnerable_configs = item.get("vulnerable_configuration", [])
    for config in vulnerable_configs:
        # cpe:2.3:a:vendor:product:version:update
        parts = config.split(':')
        if len(parts) < 5:
            continue
        
        c_vendor = parts[3]
        c_product = parts[4]
        
        if c_vendor != vendor or c_product != product:
            continue
        
        version_part = parts[5]
        update_part = parts[6] if len(parts) > 6 else None
        
        if version_part in ['*', '-']:
            continue
            
        if update_part and update_part not in ['*', '-']:
            full_version = f"{version_part}:{update_part}"
        else:
            full_version = version_part
            
        vuln_versions.add(full_version)
        
    return vuln_versions

def generate_reference_data(valid_list, bin_dir):
    references = []
    cve_tool_map = {}
    
    if not os.path.exists(bin_dir):
        print(f"Warning: Bin dir {bin_dir} does not exist.")
        return [], {}
        
    bin_files = [f for f in os.listdir(bin_dir) if '.' not in f]
    
    for item in valid_list:
        cve = item.get('cve')
        if not cve: 
            continue
            
        # Match files: CVE-ID-vuln..., CVE-ID-patch...
        # Need to be careful about substrings.
        # e.g., CVE-2014-8738-vuln...
        
        vuln_f = None
        patch_f = None
        tool_name = None
        
        for f in bin_files:
            if f.startswith(cve + "-vuln"):
                vuln_f = f
                # Extract tool name: CVE-ID-vuln-hash-toolname
                # User request: "read the part after the last -" and "filter out . and suffixes"
                try:
                    # Take the last part after splitting by '-'
                    raw_tool = f.split('-')[-1]
                    # Filter out suffixes (e.g. .i64)
                    tool_name = raw_tool.split('.')[0]
                except ValueError:
                    pass
            elif f.startswith(cve + "-patch"):
                patch_f = f
                
        if vuln_f and patch_f and tool_name:
            ref_entry = {
                "CVE": cve,
                "vuln": vuln_f,
                "patch": patch_f,
                "functions": item.get("functions", [])
            }
            references.append(ref_entry)
            cve_tool_map[cve] = tool_name
        else:
            pass 
            # print(f"Skipping {cve} for reference.json: binaries not found in {bin_dir}")
            
    return references, cve_tool_map

def create_testset_entry(cve_id, target_date_str, vuln_versions, release_map):
    if not target_date_str:
        # Default to today if missing? Or skip?
        # target_version.py uses today
        target_date = datetime.date.today()
    else:
        try:
            target_date = dt.strptime(target_date_str, "%Y-%m-%d").date()
        except ValueError:
             target_date = datetime.date.today()
             
    # Sort all known versions by date
    sorted_versions = sorted(
        release_map.keys(),
        key=lambda v: release_map.get(v, datetime.date.min)
    )
    
    # Identify patch versions: versions > max(vuln_version_indices)
    # This logic matches target_version.py for identifying "patch" set from NVD data.
    # Logic: 
    # 1. Mapped vuln versions (from NVD) to sorted index.
    # 2. Find max index.
    # 3. All versions after max index are candidates for patch.
    
    known_vuln_indices = []
    for v in vuln_versions:
        if v in sorted_versions:
            known_vuln_indices.append(sorted_versions.index(v))
            
    if not known_vuln_indices:
        print(f"DEBUG: {cve_id} - None of {vuln_versions} found in release map keys.")
        # Heuristic failed or no vuln versions found in releases
        return None

    max_idx = max(known_vuln_indices)
    
    # Candidates
    # Vulnerable candidates: items in vuln_versions that typically appear before target date
    # Actually target_version.py filters differently in `create_testset`:
    # vuln_versions = [v for v in vuln_versions if date < target_date] -- commented out in original code!
    # current active code in attachment: `# vuln_versions = ...` commented out.
    # But it does sort by date diff.
    
    potential_patches = sorted_versions[max_idx+1:]
    
    # Filter by date relative to target_date (which is convert_date/commit_date)
    # vuln versions: pick closest to date
    # patch versions: pick closest to date (must be AFTER target_date)
    
    real_patch_candidates = [v for v in potential_patches if release_map.get(v) and release_map.get(v) > target_date]
    if not real_patch_candidates:
        print(f"DEBUG: {cve_id} - No patch candidates found after {target_date}.")
        return None
        
    # Pick top 3 closest vuln
    # We want vuln versions that are released *before* the patch date (target date).
    # Since we didn't strictly filter valid vuln versions by date in ground truth, let's just pick from the set.
    # target_version.py actually just takes the NVD 'vuln' set and sorts by abs(date_diff).
    
    vuln_list = []
    for v in vuln_versions:
        d = release_map.get(v)
        if d:
            time_diff = abs((target_date - d).days)
            # Only consider if date <= target_date? Usually yes.
            # But let's follow date_diff sort.
            vuln_list.append((v, time_diff))
    
    vuln_list.sort(key=lambda x: x[1])
    selected_vuln = [x[0] for x in vuln_list[:3]]
    
    # Pick top 3 closest patch
    patch_list = []
    for v in real_patch_candidates:
        d = release_map.get(v)
        time_diff = abs((target_date - d).days)
        patch_list.append((v, time_diff))
        
    patch_list.sort(key=lambda x: x[1])
    selected_patch = [x[0] for x in patch_list[:3]]
    
    if not selected_vuln or not selected_patch:
        return None
        
    return {
        "vuln": selected_vuln,
        "patch": selected_patch,
        "target_date": target_date_str
    }

def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Load Data
    valid_data = load_json(args.valid)
    if not valid_data:
        print("Failed to load valid.json")
        sys.exit(1)
        
    release_map, version_tag_map = load_release_map(args.releases)
    raw_data = load_json(args.raw)
    vendor, product = find_cpe_vendor_product(args.project)
    print(f"DEBUG: Project={args.project}, Vendor={vendor}, Product={product}")
    
    # 1. Generate reference.json
    print("Generating reference.json...")
    references, cve_tool_map = generate_reference_data(valid_data, args.bin_dir)
    ref_path = os.path.join(args.output_dir, "reference.json")
    with open(ref_path, 'w') as f:
        json.dump(references, f, indent=2)
    print(f"Saved {len(references)} items to {ref_path}")
    
    # 2. Generate testset.json (Incremental)
    print("Generating testset.json...")
    testset_path = os.path.join(args.output_dir, "testset.json")
    existing_testset = {}
    if os.path.exists(testset_path):
        existing_testset = load_json(testset_path)
    
    current_testset = existing_testset.copy()
    
    count_added = 0
    
    for item in valid_data:
        cve_id = item.get('cve')
        if cve_id in current_testset:
            continue
            
        target_date_str = item.get('date')
        
        # Get vuln versions from NVD logic
        vuln_versions = parse_nvd_vuln_versions(raw_data, cve_id, args.project, vendor, product)
        
        if not vuln_versions:
             print(f"DEBUG: {cve_id} - No NVD vuln configurations matching {vendor}:{product}")
             continue

            
        entry = create_testset_entry(cve_id, target_date_str, vuln_versions, release_map)
        
        if entry:
            current_testset[cve_id] = entry
            count_added += 1
            print(f"Added {cve_id} to testset.")
        else:
             print(f"DEBUG: {cve_id} - Could not determine valid testset versions")
             # print(f"Could not determine valid testset versions for {cve_id}")
             
    with open(testset_path, 'w') as f:
        json.dump(current_testset, f, indent=2)
        
    print(f"Updated testset.json with {count_added} new entries.")

    # 3. Generate versions.json
    print("Generating versions.json...")
    
    # Structure: { "binary_name": [ "tag1", "tag2", ... ], ... }
    tool_versions = defaultdict(set)
    
    for cve_id, cve_data in current_testset.items():
        tool = cve_tool_map.get(cve_id)
        # If tool is not found in cve_tool_map, it might be because the binary
        # was not found in bin_dir, BUT we might have loaded this CVE from 
        # existing testset.json or valid.json (where it passed before).
        # OR it is a new CVE that we just added but didn't find binary for?
        # NOTE: current logic allows adding to testset even if generate_reference_data didn't find binary,
        # provided valid_data had it. 
        # However, generate_reference_data checks binary existence to add to 'references'.
        # If we want to strictly enforce binaries, we should only process cve_ids that have tools.
        
        if not tool:
            # Try to infer or skip?
            # For now, if we can't determine tool, we can't assign versions to a tool.
            # print(f"Warning: No binary tool identified for {cve_id}")
            continue
            
        relevant_versions = []
        relevant_versions.extend(cve_data.get("vuln", []))
        relevant_versions.extend(cve_data.get("patch", []))
        
        for v in relevant_versions:
            tag = version_tag_map.get(v)
            if tag:
                tool_versions[tool].add(tag)

    # Convert sets to sorted lists
    final_versions = {
        tool: sorted(list(tags))
        for tool, tags in tool_versions.items()
    }
    
    versions_path = os.path.join(args.output_dir, "versions.json")
    with open(versions_path, 'w') as f:
        json.dump(final_versions, f, indent=2)
    print(f"Saved versions for {len(final_versions)} tools to {versions_path}")

if __name__ == "__main__":
    main()
