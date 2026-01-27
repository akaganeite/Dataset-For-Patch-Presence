import json
import requests
import subprocess
import os
import shlex
import time
import argparse
import re
import urllib.parse
from datetime import datetime

# Global configuration dictionary for product-specific handling
PRODUCT_CONFIG = {
    "tcpdump": {
        "type": "github_direct",
        "keywords": ["github.com/the-tcpdump-group/tcpdump"],
        "target_template": "https://github.com/the-tcpdump-group/tcpdump/commit/{}.diff",
        "repo": "the-tcpdump-group/tcpdump"
    },
    "openjpeg": {
        "type": "github_direct",
        "keywords": ["github.com/uclouvain/openjpeg"],
        "target_template": "https://github.com/uclouvain/openjpeg/commit/{}.diff",
        "repo": "uclouvain/openjpeg"
    },
    "imagemagick": {
        "type": "github_direct",
        "keywords": ["github.com/ImageMagick/ImageMagick"],
        "target_template": "https://github.com/ImageMagick/ImageMagick/commit/{}.diff",
        "repo": "ImageMagick/ImageMagick"
    },
    "curl": {
        "type": "curl_custom",
        "repo": "curl/curl"
    },
    "openssl": {
        "type": "regex_extract",
        "keywords": ["git.openssl.org", "github.com/openssl/openssl"],
        "patterns": [r'commit/([a-f0-9]{7,40})', r'[?&;]h=([a-f0-9]{7,40})'],
        "target_template": "https://github.com/openssl/openssl/commit/{}.diff",
        "repo": "openssl/openssl"
    },
    "binutils": {
        "type": "regex_extract",
        "keywords": ["sourceware.org/git"],
        "patterns": [r'h=([0-9a-f]{40})'],
        "target_template": "https://github.com/bminor/binutils-gdb/commit/{}.diff",
        "repo": "bminor/binutils-gdb"
    },
    "ffmpeg": {
        "type": "regex_extract",
        "keywords": ["git.ffmpeg.org", "github.com/FFmpeg/FFmpeg"],
        "patterns": [r'h=([0-9a-f]{40})', r'commit/([0-9a-f]{40})'],
        "target_template": "https://github.com/FFmpeg/FFmpeg/commit/{}.diff",
        "repo": "FFmpeg/FFmpeg"
    },
    "libxml2": {
        "type": "libxml2_custom",
        "keywords": ["gitlab.gnome.org/GNOME/libxml2"],
        "repo": "GNOME/libxml2"
    },
    "freetype": {
        "type": "freetype_custom",
        "keywords": ["gitlab.freedesktop.org/freetype", "savannah.nongnu.org/freetype"],
        "repo": "freetype/freetype"
    },
    "sqlite": {
        "type": "sqlite_custom",
        "keywords": ["sqlite.org"],
        "repo": "sqlite/sqlite"
    }
}

def fetch_commit_date(repo, commit_hash, token=None):
    """Fetch commit date from GitHub API"""
    if not repo or not commit_hash:
        return None
    
    url = f"https://api.github.com/repos/{repo}/commits/{commit_hash}"
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
        
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            # Return YYYY-MM-DD
            return response.json()["commit"]["committer"]["date"][:10]
        elif response.status_code == 403:
            print("  [Warn] GitHub API rate limit exceeded")
    except Exception as e:
        print(f"  [Warn] Failed to fetch date: {e}")
    return None

def update_details_json(project_name, new_entries):
    """Update details.json with new entries, avoiding duplicates"""
    details_path = f"./Diff/{project_name}/details.json"
    
    existing_data = []
    if os.path.exists(details_path):
        try:
            with open(details_path, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except Exception as e:
            print(f"Error reading existing details.json: {e}")
            existing_data = []

    # Create a set of (cve, commit) for quick lookup
    existing_keys = set((item.get("cve"), item.get("commit")) for item in existing_data)
    
    added_count = 0
    for entry in new_entries:
        key = (entry["cve"], entry["commit"])
        if key not in existing_keys:
            existing_data.append(entry)
            existing_keys.add(key)
            added_count += 1
            
    # Sort by CVE ID
    existing_data.sort(key=lambda x: x.get("cve", ""))

    try:
        os.makedirs(os.path.dirname(details_path), exist_ok=True)
        with open(details_path, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2)
        if added_count > 0:
            print(f"Updated details.json with {added_count} new entries")
    except Exception as e:
        print(f"Error writing details.json: {e}")

def download_file(url, output_path):
    """Generic file downloader using wget"""
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        # Skip if file exists and has size
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            print(f"  [Skip] File exists: {output_path}")
            return True

        cmd = f"wget -q --timeout=10 -O {shlex.quote(output_path)} {shlex.quote(url)}"
        
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            timeout=15,
            universal_newlines=True
        )
        
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            return True
            
        # Clean up empty file
        if os.path.exists(output_path):
            os.remove(output_path)
        return False
    except Exception as e:
        print(f"  [Error] Download failed: {e}")
        return False

# --- Specific Handling Logic ---

def get_git_commit_hashes_from_curl_json(url: str) -> tuple[str | None, str | None]:
    """Specific logic for curl to extract hashes from their JSON docs"""
    introduced_hash = None
    fixed_hash = None
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        affected_list = data.get("affected", [])
        for affected_item in affected_list:
            ranges_list = affected_item.get("ranges", [])
            for range_item in ranges_list:
                if range_item.get("type") == "GIT":
                    events_list = range_item.get("events", [])
                    for event in events_list:
                        if "introduced" in event:
                            introduced_hash = event["introduced"]
                        if "fixed" in event:
                            fixed_hash = event["fixed"]
                    if introduced_hash or fixed_hash:
                        return introduced_hash, fixed_hash
    except Exception as e:
        print(f"Error fetching/parsing curl JSON from {url}: {e}")
        return None, None
    return None, None

def extract_hash_from_url(url, patterns):
    try:
        decoded_url = urllib.parse.unquote(url)
    except:
        decoded_url = url
    
    for pattern in patterns:
        match = re.search(pattern, decoded_url)
        if match:
            return match.group(1)
    return None

def process_github_direct(cve_entry, project_name, config, token=None):
    results = []
    cve_id = cve_entry["id"]
    keywords = config.get("keywords", [])
    target_template = config.get("target_template")
    
    found_hashes = set()
    for ref in cve_entry.get("references", []):
        if any(k in ref for k in keywords):
            # Try to extract commit hash from standard github url
            # Format: .../commit/HASH...
            match = re.search(r'commit/([0-9a-f]{7,40})', ref)
            if match:
                found_hashes.add(match.group(1))

    for git_hash in found_hashes:
        diff_url = target_template.format(git_hash)
        filename = f"./Diff/{project_name}/diff_files/{project_name}_{cve_id}_{git_hash[:12]}.diff"
        
        repo = config.get("repo")
        date_str = fetch_commit_date(repo, git_hash, token)

        # Check if file already exists
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            print(f"  ✅ [Skip] File exists: {filename}")
            results.append({
                "cve": cve_id, 
                "hash": git_hash, 
                "status": "success",
                "date": date_str
            })
            continue

        if download_file(diff_url, filename):
             print(f"  ✅ Downloaded {git_hash[:12]}")
             results.append({
                 "cve": cve_id, 
                 "hash": git_hash, 
                 "status": "success",
                 "date": date_str
             })
        else:
             print(f"  ❌ Failed to download {git_hash[:12]}")
             results.append({
                 "cve": cve_id, 
                 "hash": git_hash, 
                 "status": "failed",
                 "date": date_str
             })
    return results

def process_regex_extract(cve_entry, project_name, config, token=None):
    results = []
    cve_id = cve_entry["id"]
    keywords = config.get("keywords", [])
    patterns = config.get("patterns", [])
    target_template = config.get("target_template")
    
    found_hashes = set()
    for ref in cve_entry.get("references", []):
        is_relevant = False
        if not keywords: 
             is_relevant = True
        elif any(k in ref for k in keywords):
             is_relevant = True
        
        if is_relevant:
            h = extract_hash_from_url(ref, patterns)
            if h:
                found_hashes.add(h)

    for git_hash in found_hashes:
        diff_url = target_template.format(git_hash)
        filename = f"./Diff/{project_name}/diff_files/{project_name}_{cve_id}_{git_hash[:12]}.diff"
        
        repo = config.get("repo")
        date_str = fetch_commit_date(repo, git_hash, token)

        # Check if file already exists
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            print(f"  ✅ [Skip] File exists: {filename}")
            results.append({
                "cve": cve_id, 
                "hash": git_hash, 
                "status": "success",
                "date": date_str
            })
            continue

        if download_file(diff_url, filename):
             print(f"  ✅ Downloaded {git_hash[:12]}")
             results.append({
                 "cve": cve_id, 
                 "hash": git_hash, 
                 "status": "success",
                 "date": date_str
             })
        else:
             print(f"  ❌ Failed to download {git_hash[:12]}")
             results.append({
                 "cve": cve_id, 
                 "hash": git_hash, 
                 "status": "failed",
                 "date": date_str
             })
    return results

def process_curl_custom(cve_entry, project_name, config, token=None):
    results = []
    cve_id = cve_entry["id"]
    info_url = f"https://curl.se/docs/{cve_id}.json"
    
    _, fixed_hash = get_git_commit_hashes_from_curl_json(info_url)
    
    if fixed_hash:
        diff_url = f"https://github.com/curl/curl/commit/{fixed_hash}.diff"
        filename = f"./Diff/{project_name}/diff_files/{project_name}_{cve_id}_{fixed_hash[:12]}.diff"
        
        # Check if file already exists
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            print(f"  ✅ [Skip] File exists: {filename}")
            results.append({"cve": cve_id, "hash": fixed_hash, "status": "success"})
            return results

        if download_file(diff_url, filename):
            print(f"  ✅ Downloaded {fixed_hash[:12]}")
            results.append({"cve": cve_id, "hash": fixed_hash, "status": "success"})
        else:
            print(f"  ❌ Failed to download {fixed_hash[:12]}")
            results.append({"cve": cve_id, "hash": fixed_hash, "status": "failed"})
    return results

def process_libxml2_custom(cve_entry, project_name, config, token=None):
    results = []
    cve_id = cve_entry["id"]
    keywords = config.get("keywords", [])
    # https://gitlab.gnome.org/GNOME/libxml2/-/commit/{hash}.diff
    
    found_hashes = set()
    for ref in cve_entry.get("references", []):
        if any(k in ref for k in keywords):
            match = re.search(r'/GNOME/libxml2/-/commit/([0-9a-f]{40})', ref)
            if match:
                found_hashes.add(match.group(1))

    for git_hash in found_hashes:
        diff_url = f"https://gitlab.gnome.org/GNOME/libxml2/-/commit/{git_hash}.diff"
        filename = f"./Diff/{project_name}/diff_files/{project_name}_{cve_id}_{git_hash[:12]}.diff"
        
        # Check if file already exists
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            print(f"  ✅ [Skip] File exists: {filename}")
            results.append({"cve": cve_id, "hash": git_hash, "status": "success"})
            continue

        if download_file(diff_url, filename):
             print(f"  ✅ Downloaded {git_hash[:12]}")
             results.append({"cve": cve_id, "hash": git_hash, "status": "success"})
        else:
             print(f"  ❌ Failed to download {git_hash[:12]}")
             results.append({"cve": cve_id, "hash": git_hash, "status": "failed"})
    return results

def process_freetype_custom(cve_entry, project_name, config, token=None):
    # Freetype needs scraping 
    results = []
    cve_id = cve_entry["id"]
    keywords = config.get("keywords", [])
    
    found_hashes = set()
    for ref in cve_entry.get("references", []):
        if any(k in ref for k in keywords):
            try:
                # Basic scraping attempt
                resp = requests.get(ref, timeout=10)
                if resp.status_code == 200:
                    # Look for standard freetype link
                    # /freetype/freetype/-/commit/HASH
                    hashs = re.findall(r'/freetype/freetype/-/commit/([0-9a-f]{40})', resp.text)
                    for h in hashs:
                        found_hashes.add(h)
            except Exception as e:
                print(f"  [Warn] Failed to scrape {ref}: {e}")

    for git_hash in found_hashes:
        diff_url = f"https://github.com/freetype/freetype/commit/{git_hash}.diff"
        filename = f"./Diff/{project_name}/diff_files/{project_name}_{cve_id}_{git_hash[:12]}.diff"
        
        # Check if file already exists
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            print(f"  ✅ [Skip] File exists: {filename}")
            results.append({"cve": cve_id, "hash": git_hash, "status": "success"})
            continue

        if download_file(diff_url, filename):
             print(f"  ✅ Downloaded {git_hash[:12]}")
             results.append({"cve": cve_id, "hash": git_hash, "status": "success"})
        else:
             print(f"  ❌ Failed to download {git_hash[:12]}")
             results.append({"cve": cve_id, "hash": git_hash, "status": "failed"})
    return results

def process_sqlite_custom(cve_entry, project_name, config, token=None):
    results = []
    cve_id = cve_entry["id"]
    keywords = config.get("keywords", [])
    
    found_hashes = set()
    for ref in cve_entry.get("references", []):
        # 1. Check for github directly (rare but possible)
        if "github.com/sqlite/sqlite/commit/" in ref:
            match = re.search(r'commit/([0-9a-f]+)', ref)
            if match:
                found_hashes.add(match.group(1))
        # 2. Check for sqlite.org link and scrape
        elif "sqlite.org" in ref:
            try:
                resp = requests.get(ref, timeout=10)
                if resp.status_code == 200:
                    # Try to find id="hash-ci" or similar
                    # Simplified regex from original script
                    # <span id="hash-ci">...</span> or "sha": "..."
                     
                    # Method 1: sha property
                    sha_matches = re.findall(r'"sha":\s*"([0-9a-f]{40})"', resp.text)
                    found_hashes.update(sha_matches)
                    
                    # Method 2: hash-ci span (often split by <wbr>)
                    # This is complex to regex purely without bs4, but we try a loose match
                    # Assuming the hash is in the page somewhere visibly as 40 chars hex
                    # This is risky, but might work for simple cases. 
                    # Preferring known specific patterns if possible.
            except Exception as e:
                print(f"  [Warn] Failed to scrape {ref}: {e}")

    for git_hash in found_hashes:
        # Sqlite doesn't use standard .diff URLs on github necessarily for all historical commits
        # But we can try the github mirror: https://github.com/sqlite/sqlite/commit/{hash}.diff
        diff_url = f"https://github.com/sqlite/sqlite/commit/{git_hash}.diff"
        filename = f"./Diff/{project_name}/diff_files/{project_name}_{cve_id}_{git_hash[:12]}.diff"
        
        repo = config.get("repo")
        date_str = fetch_commit_date(repo, git_hash, token)

        # Check if file already exists
        if os.path.exists(filename) and os.path.getsize(filename) > 0:
            print(f"  ✅ [Skip] File exists: {filename}")
            results.append({
                "cve": cve_id, 
                "hash": git_hash, 
                "status": "success", 
                "date": date_str
            })
            continue

        if download_file(diff_url, filename):
             print(f"  ✅ Downloaded {git_hash[:12]}")
             results.append({
                 "cve": cve_id, 
                 "hash": git_hash, 
                 "status": "success",
                 "date": date_str
             })
        else:
             print(f"  ❌ Failed to download {git_hash[:12]}")
             results.append({
                 "cve": cve_id, 
                 "hash": git_hash, 
                 "status": "failed",
                 "date": date_str
             })
    return results


def process_cve_list(project_name, cve_list_file, token=None):
    
    # Determined JSON path
    # Try multiple common paths
    path = f"./cveinfo/{project_name}/parsed.json"
    
    json_path = None
    if os.path.exists(path):
        json_path = path
            
    if not json_path:
         print(f"Error: Could not find parsed JSON file for {project_name}")
         return

    print(f"Using JSON file: {json_path}")
    
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            all_cve_data = json.load(f)
    except Exception as e:
         print(f"Error reading JSON file {json_path}: {e}")
         return

    # Read target list
    try:
        with open(cve_list_file, "r", encoding="utf-8") as f:
            target_cves = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Target list file not found at {cve_list_file}")
        return

    # Filter data
    # Create a map for quick access
    cve_map = {entry["id"]: entry for entry in all_cve_data}
    
    all_results = []
    config = PRODUCT_CONFIG.get(project_name)
    handler_type = config.get("type")

    print(f"Starting processing for {len(target_cves)} CVEs using handler: {handler_type}")

    for cve_id in target_cves:
        if cve_id not in cve_map:
            print(f"Warning: {cve_id} not found in parsed JSON data.")
            continue
            
        print(f"Processing {cve_id} ...")
        entry = cve_map[cve_id]
        
        results = []
        if handler_type == "github_direct":
            results = process_github_direct(entry, project_name, config, token)
        elif handler_type == "curl_custom":
            results = process_curl_custom(entry, project_name, config, token)
        elif handler_type == "regex_extract":
            results = process_regex_extract(entry, project_name, config, token)
        elif handler_type == "libxml2_custom":
            results = process_libxml2_custom(entry, project_name, config, token)
        elif handler_type == "freetype_custom":
            results = process_freetype_custom(entry, project_name, config, token)
        elif handler_type == "sqlite_custom":
            results = process_sqlite_custom(entry, project_name, config, token)
        else:
            print(f"No handler defined for {handler_type}")
            
        all_results.extend(results)

    # Summary
    success_count = sum(1 for r in all_results if r.get("status") == "success")
    print(f"\nTotal Processed: {len(all_results)}")
    print(f"Success: {success_count}")
    print(f"Failed: {len(all_results) - success_count}")

    # Update details.json with successfully downloaded commits that have dates
    new_details = []
    for r in all_results:
        if r.get("status") == "success" and r.get("date"):
            new_details.append({
                "cve": r["cve"],
                "commit": r["hash"],
                "date": r["date"]
            })
    
    if new_details:
        update_details_json(project_name, new_details)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download diff files for CVEs")
    parser.add_argument("-p", "--project", required=True, help="Project name (e.g., tcpdump, curl, binutils...)")
    parser.add_argument("-l", "--list", required=True, help="Path to text file containing list of CVE IDs")
    parser.add_argument("-t", "--token", required=False, help="GitHub API token", default=None)
    
    args = parser.parse_args()
    
    if args.project not in PRODUCT_CONFIG:
        print(f"Error: Project '{args.project}' is not configured. Available projects: {list(PRODUCT_CONFIG.keys())}")
        exit(1)
        
    process_cve_list(args.project, args.list, args.token)
