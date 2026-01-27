#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import argparse
import shutil
import logging
import glob
import multiprocessing
import datetime
import json
import struct
from datetime import datetime as dt

# --- Helper Functions from compile.py ---

def is_elf_file(filepath):
    """
    Check if file is ELF executable (EXEC) or dynamic lib (DYN).
    .o files (REL) return False.
    """
    try:
        with open(filepath, 'rb') as f:
            header = f.read(18)
            
            # 1. Basic length check
            if len(header) < 18:
                return False

            # 2. Check ELF magic
            if header[0:4] != b'\x7fELF':
                return False

            # 3. Determine endianness
            # Offset 5: 1 for little, 2 for big
            endian = header[5]
            
            # 4. Read e_type field (Offset 16, length 2 bytes)
            e_type_bytes = header[16:18]
            if endian == 1:
                # Little endian
                e_type = struct.unpack('<H', e_type_bytes)[0]
            else:
                # Big endian
                e_type = struct.unpack('>H', e_type_bytes)[0]

            # 5. Logic:
            # 2 = ET_EXEC 
            # 3 = ET_DYN 
            return e_type == 2 or e_type == 3

    except Exception:
        return False

def check_functions_in_binary(binary_path, functions):
    if not functions: return True
    try:
        result = subprocess.run(["nm", binary_path], capture_output=True, text=True, check=True)
        nm_output = result.stdout
        # NM output might be different depending on stripping, but for unstripped (compiled with -g) it should be there.
        # We need to be careful matching. 
        # functions is a list of strings
        missing = []
        for f in functions:
            # Simple substring check might be prone to false positives, but nm output usually has " T funcname"
            # Here we just check if the function name exists in the output.
            if f not in nm_output:
                missing.append(f)
                
        if missing:
            logging.warning(f"Missing functions {missing} in {binary_path}")
            return False
        return True
    except subprocess.CalledProcessError:
        return False

def run_cmd(cmd, cwd=None, env=None, shell=False, log_file=None):
    # Auto-enable shell for commands with operators if passed as list
    if isinstance(cmd, list):
        if any(item in ["&&", "||", ";", "|", ">", ">>"] for item in cmd):
            shell = True
            cmd = ' '.join(cmd)

    cmd_str = cmd if isinstance(cmd, str) else ' '.join(cmd)
    logging.debug(f"Executing: {cmd_str} in {cwd}")
    
    # Write to specific build log if provided
    if log_file:
         try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"\n\n=== Executing: {cmd_str} ===\n")
         except Exception as e:
            logging.error(f"Failed to write to task log file {log_file}: {e}")

    try:
        if log_file:
            with open(log_file, "a", encoding="utf-8") as f:
                subprocess.run(cmd, cwd=cwd, env=env, shell=shell, 
                               stdout=f, stderr=subprocess.STDOUT, check=True, encoding="utf-8")
        else:
            subprocess.run(cmd, cwd=cwd, env=env, shell=shell, 
                           capture_output=True, check=True, encoding="utf-8")
        return True
    except subprocess.CalledProcessError as e:
        err_msg = f"Command failed: {cmd_str}\nReturn Code: {e.returncode}"
        if log_file:
             with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"\n{err_msg}\n")
        else:
            err_msg += f"\nStderr: {e.stderr}"
        # logging.error(err_msg) # Optional: don't spam main log with every failed command if retrying
        return False

def find_binary(search_dir, functions, binary_rules):
    # If no rules provided, fallback to default behavior (or just fail safely)
    if not binary_rules:
        logging.warning("No binary rules found in config.")
        return None, None

    # Iterate through rules in priority order
    for rule in binary_rules:
        # Rule is a list: [relative_dir, filename_part, optional_extension]
        # Example 1: ["./", "libssl", "so"] -> search_dir/./*libssl.so*
        # Example 2: ["./apps", "openssl"] -> search_dir/./apps/openssl*
        
        if not rule or len(rule) < 2:
            continue
            
        rel_dir = rule[0]
        name_part = rule[1]
        
        search_path = os.path.join(search_dir, rel_dir)
        
        if len(rule) >= 3:
            pattern = f"*{name_part}*{rule[2]}*"
        else:
            pattern = f"{name_part}*"
            
        full_pattern = os.path.join(search_path, pattern)
        candidates = glob.glob(full_pattern)
        
        # Filter candidates
        candidates = [p for p in candidates if os.path.isfile(p) and not os.path.islink(p) and is_elf_file(p)]
        
        # Check matched files for functions
        for p in candidates:
             if check_functions_in_binary(p, functions):
                 return p, name_part

    return None, None

def load_project_config(config_path, project_name):
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config.get("compile_rule", {}).get(project_name, {})
    except Exception as e:
        logging.error(f"Failed to load config from {config_path}: {e}")
        return {}

def compile_task(repo_path, commit, functions_list, opt, compiler, output_path, cve_id, project_config):
    """
    Compiles the project at a specific commit.
    Returns: 
       (bool, message)
       True, "Success" on success
       False, "Error message" on failure
    """
    
    # Setup Logging for this task
    reponame = os.path.basename(repo_path.rstrip("/"))
    log_dir_base = f"logs/{reponame}"
    os.makedirs(log_dir_base, exist_ok=True)
    
    # Unique log file for this compilation task
    task_log_file = os.path.join(log_dir_base, f"{cve_id}_{commit[:4]}.log")
    
    # Initialize log file
    with open(task_log_file, 'w', encoding='utf-8') as f:
        f.write(f"Compilation Log for {cve_id} commit {commit}\n")
        f.write(f"Timestamp: {dt.now()}\n")
        f.write(f"Options: {opt}, Compiler: {compiler}\n\n")

    # Check if target output already exists (Should be handled by caller, but good double check)
    # The caller checks exact filename. 
    # Here we are about to produce it.

    # 1. Prepare Repo
    try:
        run_cmd(["git", "stash"], cwd=repo_path)
        # Use -f to force checkout
        if not run_cmd(["git", "checkout", "-f", commit], cwd=repo_path, log_file=task_log_file):
             # Try fetching if checkout fails? Usually assumes repo has commits.
             msg = f"Failed to checkout {commit}"
             logging.error(msg)
             return False, msg
        run_cmd(["git", "clean", "-fdx"], cwd=repo_path)
    except Exception as e:
        msg = f"Repo preparation failed for {commit}: {e}"
        logging.error(msg)
        return False, msg

    # 2. Config Environment
    env = os.environ.copy()
    env["CC"] = compiler
    env["CXX"] = "g++" if "gcc" in compiler else "clang++"
    cflags = f"-g3 {opt}"
    env["CFLAGS"] = cflags
    env["CXXFLAGS"] = cflags

    # Append config-specific env variables
    config_env = project_config.get("env", {})
    for k, v in config_env.items():
        if k in env:
            env[k] += f" {v}"
        else:
            env[k] = v

    # 3. Build Process
    try:
        logging.info(f"[{cve_id}] Starting build for {commit[:8]}...")
        
        build_success = False
        config_commands = project_config.get("config", [])
        if not config_commands:
            msg = f"[{cve_id}] No config commands found in config for {reponame}"
            logging.error(msg)
            return False, msg

        for config_cmd in config_commands:
            logging.info(f"[{cve_id}] Config: {' '.join(config_cmd)}")
            run_cmd(["make", "clean"], cwd=repo_path, env=env)
            
            if run_cmd(config_cmd, cwd=repo_path, env=env,log_file=task_log_file):
                logging.info(f"[{cve_id}] Configuration passed. Running make...")
                
                make_commands = project_config.get("make", [])
                if not make_commands:
                    make_commands = [["make"]]

                make_success_for_config = False
                for make_args in make_commands:
                    # Construct make command: make -j{nproc} [other args...]
                    base_make = [make_args[0], "-j", str(multiprocessing.cpu_count())]
                    if len(make_args) > 1:
                        base_make.extend(make_args[1:])
                    
                    if run_cmd(base_make, cwd=repo_path, env=env, log_file=task_log_file):
                        logging.info(f"[{cve_id}] Make succeeded.")
                        make_success_for_config = True
                        break 
                
                if make_success_for_config:
                    build_success = True
                    break 
                else:
                    logging.warning(f"[{cve_id}] Make failed. Retrying with next config...")
                    run_cmd(["make", "clean"], cwd=repo_path, env=env)
            else:
                logging.warning(f"[{cve_id}] Configuration failed. Retrying with next config...")
        
        if not build_success:
            msg = f"[{cve_id}] All build configurations failed for {commit[:8]}"
            logging.error(msg)
            return False, msg

    except Exception as e:
        msg = f"[{cve_id}] Build exception: {e}"
        logging.error(msg)
        return False, msg

    # 4. Find and Copy Binary
    binary_rules = project_config.get("binary", [])
    binary, matched_name = find_binary(repo_path, functions_list, binary_rules)
    
    if binary:
        logging.info(f"[{cve_id}] Found binary: {binary}")
        dest = f"{output_path}-{matched_name}"
        shutil.copy2(binary, dest)
        logging.info(f"[{cve_id}] Binary copied to {dest}")
        return True, "Success"
    else:
        msg = f"[{cve_id}] Binary not found or missing symbols for {commit[:8]}"
        logging.error(msg)
        return False, msg

# --- Dispatcher Functions ---

def get_parent_commit(repo_path, commit):
    try:
        result = subprocess.run(["git", "rev-parse", f"{commit}^"], cwd=repo_path, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        logging.error(f"Failed to find parent commit for {commit}")
        return None

def setup_global_logging(product):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    now_str = dt.now().strftime("%Y%m%d_%H%M")
    main_log = os.path.join(log_dir, f"{product}_{now_str}.log")
    error_log = os.path.join(log_dir, f"{product}_error_{now_str}.log")

    error_handler = logging.FileHandler(error_log, encoding='utf-8')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(main_log, encoding='utf-8'),
            error_handler
        ]
    )
    return main_log

def main():
    parser = argparse.ArgumentParser(description="Unified Compilation Dispatcher")
    parser.add_argument("-p", "--product", required=True, help="Product name (directory name in rules)")
    parser.add_argument("--repo", required=True, help="Path to the repository")
    parser.add_argument("--json", required=True, help="Path to the source_diff.json file")
    parser.add_argument("--opt", default="-O0", help="Optimization level (e.g., -O0)")
    parser.add_argument("--compiler", default="gcc", help="Compiler (e.g., gcc, clang)")
    parser.add_argument("--output", required=True, help="Directory to store confirmed binaries")

    args = parser.parse_args()
    setup_global_logging(args.product)

    # Load Project Config
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config.json")
    if not os.path.exists(config_path):
        logging.error(f"Config file not found at {config_path}")
        sys.exit(1)
        
    project_config = load_project_config(config_path, args.product)
    if not project_config:
        logging.error(f"No configuration found for product: {args.product}")
        sys.exit(1)

    if not os.path.exists(args.json):
        logging.error(f"JSON file not found: {args.json}")
        sys.exit(1)

    with open(args.json, 'r') as f:
        data = json.load(f)

    os.makedirs(args.output, exist_ok=True)
    repo_path = os.path.abspath(args.repo)
    output_abs = os.path.abspath(args.output)

    for cve_id, info in data.items():
        commit = info.get("commit")
        analysis = info.get("analysis", [])
        
        # Extract function names
        functions = [item["function"] for item in analysis if "function" in item]
        # func_str = ",".join(functions) # Not needed as string for internal call, but list
        
        logging.info(f"Processing {cve_id} - Commit: {commit}")

        # Task 1: Target Commit
        target_output_base = os.path.join(output_abs, f"{cve_id}-patch-{commit[:12]}")
        
        # Check if any binary starting with this prefix exists
        # Since compile_task appends -{matched_name}, we check via glob
        if glob.glob(f"{target_output_base}*"):
             logging.info(f"Target binary already exists for {cve_id} (patch), skipping.")
        else:
            logging.info(f"Dispatching target compilation for {commit[:12]}...")
            success, msg = compile_task(
                repo_path=repo_path,
                commit=commit,
                functions_list=functions,
                opt=args.opt,
                compiler=args.compiler,
                output_path=target_output_base,
                cve_id=cve_id,
                project_config=project_config
            )
            
            if not success:
                logging.error(f"Target compilation failed for {cve_id} ({commit[:8]}): {msg}")
                continue 

        # Task 2: Parent Commit
        parent_commit = get_parent_commit(repo_path, commit)
        if parent_commit:
            parent_output_base = os.path.join(output_abs, f"{cve_id}-vuln-{parent_commit[:12]}")
            
            if glob.glob(f"{parent_output_base}*"):
                 logging.info(f"Parent binary already exists for {cve_id} (vuln), skipping.")
            else:
                logging.info(f"Dispatching parent compilation for {parent_commit[:12]}...")
                success, msg = compile_task(
                    repo_path=repo_path,
                    commit=parent_commit,
                    functions_list=functions,
                    opt=args.opt,
                    compiler=args.compiler,
                    output_path=parent_output_base,
                    cve_id=cve_id,
                    project_config=project_config
                )
                
                if not success:
                     logging.error(f"Parent compilation failed for {cve_id} ({parent_commit[:8]}): {msg}")
                     continue
        else:
            logging.error(f"Skipping parent for {commit} (not found)")

if __name__ == "__main__":
    main()
