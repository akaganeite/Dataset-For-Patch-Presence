# Given a project name, this script will create a json file with the project name and a list of CVEs.
import subprocess
import json
import sys
import argparse

try:
    from packaging.version import parse as parse_version
except ImportError:
    print("Please install packaging library first: pip install packaging")
    sys.exit(1)

def extract_vendor_product(command):
    """Extract vendor and product names from command arguments"""
    try:
        index = command.index('-p')
        product_arg = command[index + 1]
    except (ValueError, IndexError):
        print("Error: -p parameter not found")
        sys.exit(1)
    
    parts = [p for p in product_arg.split(':') if p]
    if len(parts) < 2:
        print("Error: Parameter format should be :vendor:product:")
        sys.exit(1)
    return parts[-2], parts[-1]  # Return vendor and product names

def run_cve_search(command):
    """Execute CVE search command"""
    try:
        result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )
    except subprocess.CalledProcessError as e:
        print(f"Command execution failed: {e}")
        sys.exit(1)
    return result.stdout

def run_command_and_format(command):
    # 1. Execute command
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding='utf-8'
    )
    
    if result.returncode != 0:
        print(f"Command execution failed: {result.stderr}")
        return []
    
    # 2. Process output (assume each JSON object is on a separate line)
    raw_output = result.stdout
    json_lines = [line.strip() for line in raw_output.splitlines() if line.strip()]
    
    # 3. Parse and encapsulate
    parsed_data = []
    for line in json_lines:
        try:
            data = json.loads(line)
            parsed_data.append(data)
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}, line content: {line}")
    
    return parsed_data

def analyze_versions(vulnerable_products, target_vendor, target_product):
    """Analyze affected version range"""
    versions = []
    match_string = f"{target_vendor}:{target_product}"
    for cpe in vulnerable_products:
        if match_string not in cpe:
            continue
        parts = cpe.split(':')

        for i,part in enumerate(parts):
            if part == target_vendor and parts[i+1] == target_product and parts[i+2] not in ('*', '-'):
                if parts[i+3] not in ('*', '-'):
                    versions=f"{parts[i+2]}-{parts[i+3]}"
                else:
                    versions=parts[i+2]
    
    return versions


def process_cve_data(output, target_vendor, target_product):
    """Process CVE data and generate results"""
    cve_data= output
    
    # Load config from json file
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
            ref_rules = config.get("ref_rule", [])
    except FileNotFoundError:
        print("Warning: config.json not found, using default rules")
        ref_rules = ['git', 'sourceware', 'bugzilla']
    except Exception as e:
        print(f"Error loading config.json: {e}")
        ref_rules = ['git', 'sourceware', 'bugzilla']

    processed = []
    for entry in cve_data:
        # Version analysis
        vuln_version = analyze_versions(
            entry.get('vulnerable_product', []),
            target_vendor,
            target_product
        )
        # print(version_range)
        
        # Reference filtering
        filter_keywords = ref_rules + [target_product]
        filtered_refs = [
            ref for ref in entry.get('references', [])
            if any(kw in ref.lower() for kw in filter_keywords)
        ]
        
        # Build result entry
        result_entry = {
            'id': entry.get('id'),
            'cwe': entry.get('cwe', []),
            'summary': entry.get('summary', ''),
            'references': filtered_refs
        }
        
        if vuln_version:
            result_entry['last_vuln_version'] = vuln_version
        
        processed.append(result_entry)
        print(f"processed CVE ID: {entry.get('id')}")
    
    return processed

def parse_raw_data(vendor, product):
    with open(f"./rawdata/{product}_raw.json", "r") as f:
        data = json.load(f)  # Load data
    # Process data
    result_data = process_cve_data(data, vendor, product)
    
    final_data = []
    filtered_ids = []
    for item in result_data:
        if 'last_vuln_version' in item:
            final_data.append(item)
        else:
            filtered_ids.append(item['id'])

    # Save results
    output_file = f"./cveinfo/{product}/parsed.json"
    with open(output_file, 'w') as f:
        json.dump(final_data, f, indent=2, ensure_ascii=False)
    
    print(f"Analysis complete! Results saved to {output_file}")
    
    if filtered_ids:
        print(f"Filtered out CVE IDs (missing last_vuln_version): {', '.join(filtered_ids)}")

def get_raw_result(command):
    
    # Extract vendor and product info
    _, product = extract_vendor_product(command)
    
    # Execute CVE search
    data_list = run_command_and_format(command)
    
    # Save to file
    try:
        with open(f"./cveinfo/{product}/raw.json", "w", encoding="utf-8") as f:
            json.dump(data_list, f, indent=2, ensure_ascii=False)
        print("Results saved to raw.json")
    except IOError as e:
        print(f"File save failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help="vendor:product")
    parser.add_argument('-r', action='store_true', help="Get raw data")
    parser.add_argument('-a', action='store_true', help="Analyze data")
    args = parser.parse_args()

    if args.p is None:
        print("Please provide -p parameter")
        sys.exit(1)

    command = [
        '../cve-search/bin/search.py',
        '-p', f':{args.p}:', 
        '--only-if-vulnerable',
        '-o', 'json'
    ]
    # Extract vendor and product info
    vendor, product = extract_vendor_product(command)
    print(f"Vendor: {vendor}, Product: {product}")
    if args.r:
        get_raw_result(command)
    elif args.a:
        parse_raw_data(vendor, product)
    else:
        print("Please provide -r or -a parameter")