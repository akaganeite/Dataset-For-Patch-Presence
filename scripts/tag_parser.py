import argparse
import csv
import requests
import json
import re
import os
import time
from datetime import datetime
from dateutil import parser  # pip install python-dateutil

def load_rules(project_name: str, config_file: str) -> dict:
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file not found: {config_file}")
    
    with open(config_file, 'r') as f:
        data = json.load(f)
    
    # Check if 'tag_rules' key exists (new format), else assume root (old format)
    if "tag_rules" in data:
        rules = data["tag_rules"]
    else:
        rules = data

    if project_name not in rules:
        raise ValueError(f"Project '{project_name}' not defined in config file.")
    
    return rules[project_name]

def parse_version(tag_name: str, rule: dict) -> str:
    pattern = rule.get("tag_pattern")
    if not pattern:
        return tag_name
        
    match = re.match(pattern, tag_name)
    if not match:
        return None
        
    # Extract version part (first non-None group)
    version_part = next((g for g in match.groups() if g is not None), None)
    
    if not version_part:
         return None

    # Apply replacements
    replacements = rule.get("replace", {})
    for old, new in replacements.items():
        version_part = version_part.replace(old, new)
        
    return version_part

def get_all_tags(repo_owner: str, repo_name: str, github_token: str = None) -> list:
    """
    Get all tags from a GitHub repository (including release dates)
    
    Args:
        repo_owner: Repository owner
        repo_name: Repository name
        github_token: GitHub Personal Access Token (optional)
    
    Returns:
        List[dict]: List of dictionaries containing tag information
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    query = """
    query ($owner: String!, $name: String!, $cursor: String) {
      repository(owner: $owner, name: $name) {
        refs(refPrefix: "refs/tags/", first: 50, after: $cursor) {
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            name
            target {
              ... on Commit {
                committedDate
                oid
              }
              ... on Tag {
                tagger {
                  date
                }
                target {
                  ... on Commit {
                    committedDate
                    oid
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    tags = []
    cursor = None
    retry_count = 0
    max_retries = 3

    print(f"Fetching tags for {repo_owner}/{repo_name}...")

    while True:
        try:
            variables = {"owner": repo_owner, "name": repo_name, "cursor": cursor}
            response = requests.post(
                "https://api.github.com/graphql",
                headers=headers,
                json={"query": query, "variables": variables},
                timeout=30
            )
            response.raise_for_status()

            data = response.json()
            if "errors" in data:
                raise ValueError(f"GraphQL Error: {data['errors'][0]['message']}")
            
            if data["data"]["repository"] is None:
                 raise ValueError(f"Repository {repo_owner}/{repo_name} not found or not accessible.")

            refs = data["data"]["repository"]["refs"]
            if not refs:
                break

            for node in refs["nodes"]:
                try:
                    # Handle different tag types (lightweight vs annotated)
                    if "tagger" in node["target"]:
                        date_str = node["target"]["tagger"]["date"]
                        commit_sha = node["target"]["target"]["oid"]
                    else:
                        date_str = node["target"]["committedDate"]
                        commit_sha = node["target"]["oid"]

                    # Parse date safely
                    parsed_date = parser.isoparse(date_str).strftime("%Y-%m-%d %H:%M:%S")
                    
                    tags.append({
                        "tag": node["name"],
                        "commit_sha": commit_sha,
                        "date": parsed_date
                    })
                except KeyError as e:
                    print(f"Warning: Skipping malformed tag data, missing field {str(e)}")
                    continue
                except Exception as e:
                     print(f"Warning: Error processing tag {node.get('name', 'unknown')}: {e}")
                     continue

            if not refs["pageInfo"]["hasNextPage"]:
                break
            cursor = refs["pageInfo"]["endCursor"]
            retry_count = 0  # Reset retry counter on success
            
            print(f"Fetched {len(tags)} tags so far...", end='\r')

        except requests.exceptions.RequestException as e:
            if retry_count < max_retries:
                sleep_time = (retry_count + 1) * 2
                print(f"Request failed, retrying ({retry_count+1}/{max_retries}) in {sleep_time}s...")
                time.sleep(sleep_time)
                retry_count += 1
                continue
            raise RuntimeError(f"API Request failed: {str(e)}") from e
            
    print(f"\nTotal tags fetched: {len(tags)}")
    return tags

def main():
    parser = argparse.ArgumentParser(description="Fetch and parse GitHub tags for a project")
    parser.add_argument("-p", "--project", required=True, help="Project name (key in config file)")
    parser.add_argument("-c", "--config", help="Configuration file path", default=os.path.join(os.path.dirname(__file__), "config.json"))
    parser.add_argument("-t", "--token", help="GitHub API Token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("-o", "--output", help="Output JSON file path")
    
    args = parser.parse_args()
    
    try:
        # Load rules
        rule = load_rules(args.project, args.config)
        repo_owner = rule["owner"]
        repo_name = rule["name"]
        
        # Fetch tags
        raw_tags = get_all_tags(repo_owner, repo_name, args.token)
        
        # Parse and Filter
        processed_tags = []
        for tag in raw_tags:
            version = parse_version(tag["tag"], rule)
            if version:
                tag["version"] = version
                processed_tags.append(tag)
        
        print(f"Valid versions found: {len(processed_tags)}")
        
        # Output
        output_file = args.output if args.output else f"{args.project}_versions.json"
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(processed_tags, f, indent=2)
        print(f"Results saved to {output_file}")
            
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

if __name__ == "__main__":
    main()
    