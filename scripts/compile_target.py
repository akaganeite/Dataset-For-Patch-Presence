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
from collections import defaultdict

# --- Helper Functions ---

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
        return False

def find_specific_binary(search_dir, target_name, binary_rules):
    # If no rules provided, fallback to default behavior (or just fail safely)
    if not binary_rules:
        logging.warning("No binary rules found in config.")
        return None

    # Iterate through rules in priority order
    for rule in binary_rules:
        # Rule is a list: [relative_dir, filename_part, optional_extension]
        
        if not rule or len(rule) < 2:
            continue
            
        rel_dir = rule[0]
        rule_name = rule[1]
        
        # We only care about the rule that matches the requested target_name
        if rule_name != target_name:
            continue
        
        search_path = os.path.join(search_dir, rel_dir)
        
        if len(rule) >= 3:
            pattern = f"*{rule_name}*{rule[2]}*"
        else:
            pattern = f"{rule_name}*"
            
        full_pattern = os.path.join(search_path, pattern)
        candidates = glob.glob(full_pattern)
        
        # Filter candidates
        candidates = [p for p in candidates if os.path.isfile(p) and not os.path.islink(p) and is_elf_file(p)]
        
        if candidates:
            # Return the first match. 
            # Since we are looking for a specific binary name, picking the first ELF match is reasonable
            # if the rule is specific enough.
            return candidates[0]

    return None

def load_project_config(config_path, project_name):
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config.get("compile_rule", {}).get(project_name, {})
    except Exception as e:
        logging.error(f"Failed to load config from {config_path}: {e}")
        return {}

def compile_tag_task(repo_path, tag, binaries_to_collect, opt, compiler, output_dir, project_config):
    """
    Compiles the project at a specific tag and collects requested binaries.
    Returns: 
       (bool, message)
    """
    
    # Setup Logging for this task
    reponame = os.path.basename(repo_path.rstrip("/"))
    log_dir_base = f"logs/{reponame}_targets"
    os.makedirs(log_dir_base, exist_ok=True)
    
    # Unique log file for this compilation task
    task_log_file = os.path.join(log_dir_base, f"{tag}.log")
    
    # Initialize log file
    with open(task_log_file, 'w', encoding='utf-8') as f:
        f.write(f"Compilation Log for tag {tag}\n")
        f.write(f"Timestamp: {dt.now()}\n")
        f.write(f"Options: {opt}, Compiler: {compiler}\n\n")

    # 1. Prepare Repo
    try:
        run_cmd(["git", "stash"], cwd=repo_path, log_file=task_log_file)
        # Use -f to force checkout
        if not run_cmd(["git", "checkout", "-f", tag], cwd=repo_path, log_file=task_log_file):
             msg = f"Failed to checkout {tag}"
             logging.error(msg)
             # Try clean anyway?
             return False, msg
        run_cmd(["git", "clean", "-fdx"], cwd=repo_path, log_file=task_log_file)
    except Exception as e:
        msg = f"Repo preparation failed for {tag}: {e}"
        logging.error(msg)
        return False, msg

    # 2. Config Environment
    env = os.environ.copy()
    env["CC"] = compiler
    env["CXX"] = "g++" if "gcc" in compiler else "clang++"
    cflags = f"-g {opt}"
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
        logging.info(f"[{tag}] Starting build...")
        
        build_success = False
        config_commands = project_config.get("config", [])
        if not config_commands:
            msg = f"[{tag}] No config commands found in config"
            logging.error(msg)
            return False, msg

        for config_cmd in config_commands:
            logging.info(f"[{tag}] Config: {' '.join(config_cmd)}")
            run_cmd(["make", "clean"], cwd=repo_path, env=env, log_file=task_log_file)
            
            if run_cmd(config_cmd, cwd=repo_path, env=env, log_file=task_log_file):
                logging.info(f"[{tag}] Configuration passed. Running make...")
                
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
                        logging.info(f"[{tag}] Make succeeded.")
                        make_success_for_config = True
                        break 
                
                if make_success_for_config:
                    build_success = True
                    break 
                else:
                    logging.warning(f"[{tag}] Make failed. Retrying with next config...")
                    run_cmd(["make", "clean"], cwd=repo_path, env=env, log_file=task_log_file)
            else:
                logging.warning(f"[{tag}] Configuration failed. Retrying with next config...")
        
        if not build_success:
            msg = f"[{tag}] All build configurations failed"
            logging.error(msg)
            return False, msg

    except Exception as e:
        msg = f"[{tag}] Build exception: {e}"
        logging.error(msg)
        return False, msg

    # 4. Find and Copy Binaries
    binary_rules = project_config.get("binary", [])
    
    collected_count = 0
    missing_binaries = []
    
    for binary_name in binaries_to_collect:
        binary_path = find_specific_binary(repo_path, binary_name, binary_rules)
        
        if binary_path:
            dest_name = f"{binary_name}-{tag}"
            dest_path = os.path.join(output_dir, dest_name)
            
            # If dest exists, maybe overwrite? copying is strict.
            try:
                shutil.copy2(binary_path, dest_path)
                logging.info(f"[{tag}] Collected {binary_name} -> {dest_name}")
                collected_count += 1
            except Exception as e:
                logging.error(f"[{tag}] Failed to copy {binary_name}: {e}")
        else:
            logging.warning(f"[{tag}] Binary '{binary_name}' not found")
            missing_binaries.append(binary_name)
    
    if len(missing_binaries) == len(binaries_to_collect):
         return False, f"All requested binaries missing for tag {tag}: {missing_binaries}"
         
    return True, f"Success. Collected {collected_count}/{len(binaries_to_collect)} binaries."

# --- Main Dispatcher ---

def setup_global_logging(product):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    now_str = dt.now().strftime("%Y%m%d_%H%M")
    main_log = os.path.join(log_dir, f"{product}_targets_{now_str}.log")
    error_log = os.path.join(log_dir, f"{product}_targets_error_{now_str}.log")

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
    parser = argparse.ArgumentParser(description="Unified Compilation Dispatcher for Versions")
    parser.add_argument("-p", "--product", required=True, help="Product name (directory name in rules)")
    parser.add_argument("--repo", required=True, help="Path to the repository")
    parser.add_argument("--versions", required=True, help="Path to the versions.json file")
    parser.add_argument("--opt", default="-O0", help="Optimization level (e.g., -O0)")
    parser.add_argument("--compiler", default="gcc", help="Compiler (e.g., gcc, clang)")
    parser.add_argument("--output", required=True, help="Directory to store compiled binaries")

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

    if not os.path.exists(args.versions):
        logging.error(f"Versions file not found: {args.versions}")
        sys.exit(1)

    with open(args.versions, 'r') as f:
        version_data = json.load(f)

    # Invert version_data: Map tag -> [binary_names] to minimize compilations
    # version_data structure: {"binary_name": ["tag1", "tag2"], ...}
    tag_map = defaultdict(set)
    for binary_name, tags in version_data.items():
        for tag in tags:
            tag_map[tag].add(binary_name)

    os.makedirs(args.output, exist_ok=True)
    repo_path = os.path.abspath(args.repo)
    output_abs = os.path.abspath(args.output)
    
    sorted_tags = sorted(tag_map.keys())
    logging.info(f"Found {len(sorted_tags)} unique tags to process.")

    for tag in sorted_tags:
        binaries_to_collect = tag_map[tag]
        
        # Check if all targets already exist
        all_exist = True
        for b_name in binaries_to_collect:
            target_path = os.path.join(output_abs, f"{b_name}-{tag}")
            if not os.path.exists(target_path):
                all_exist = False
                break
        
        if all_exist:
            logging.info(f"All binaries for tag {tag} already exist. Skipping.")
            continue

        logging.info(f"Processing tag: {tag}. Binaries needed: {', '.join(binaries_to_collect)}")
        
        success, msg = compile_tag_task(
            repo_path=repo_path,
            tag=tag,
            binaries_to_collect=binaries_to_collect,
            opt=args.opt,
            compiler=args.compiler,
            output_dir=output_abs,
            project_config=project_config
        )
        
        if not success:
            logging.error(f"Compilation/Collection failed for tag {tag}: {msg}")
        else:
            logging.info(f"Completed tag {tag}: {msg}")

if __name__ == "__main__":
    main()
