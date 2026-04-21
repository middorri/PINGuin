#!/usr/bin/env python3
"""
PINGuin Setup Script
- Checks required tools
- Optionally creates an alias
- Patches Nmap with jitter (interactive)
"""

import os
import sys
import shutil
import subprocess
import shlex
from datetime import datetime

# ------------------------------------------------------------
# Tool checking (fixed)
# ------------------------------------------------------------
REQUIRED_TOOLS = [
    "nmap",
    "sshpass",
    "ssh-audit",
    "whatweb",
    "testssl.sh",
    "enum4linux",
    "ftp",
    "python3"
]

def check_tools():
    """Check which required tools are installed, print status."""
    print("\n🔍 Checking required tools...")
    missing = []
    for tool in REQUIRED_TOOLS:
        # shutil.which returns path if executable found, else None
        path = shutil.which(tool)
        if path:
            print(f"  ✅ {tool}: {path}")
        else:
            print(f"  ❌ {tool}: not found")
            missing.append(tool)
    if missing:
        print("\n⚠️  Some tools are missing. You may want to install them.")
    else:
        print("\n✅ All required tools are installed.")
    return missing

# ------------------------------------------------------------
# Alias creation
# ------------------------------------------------------------
def get_shell_config():
    """Determine the user's shell config file."""
    shell = os.environ.get("SHELL", "/bin/bash")
    home = os.path.expanduser("~")
    if "zsh" in shell:
        return os.path.join(home, ".zshrc")
    elif "bash" in shell:
        # Check for .bashrc first, then .bash_profile
        bashrc = os.path.join(home, ".bashrc")
        if os.path.isfile(bashrc):
            return bashrc
        return os.path.join(home, ".bash_profile")
    else:
        return os.path.join(home, ".profile")

def create_alias(alias_name, target_path):
    """Add an alias line to the user's shell config file."""
    config_file = get_shell_config()
    alias_line = f"\n# PINGuin alias\nalias {alias_name}='{target_path}'\n"

    print(f"\n📝 Adding alias '{alias_name}' to {config_file}")

    # Check if alias already exists
    if os.path.isfile(config_file):
        with open(config_file, 'r') as f:
            content = f.read()
        if f"alias {alias_name}=" in content:
            print(f"⚠️  Alias '{alias_name}' already exists in {config_file}. Skipping.")
            return False

    # Append the alias
    with open(config_file, 'a') as f:
        f.write(alias_line)
    print(f"✅ Alias added. Run 'source {config_file}' or restart your shell to use it.")
    return True

# ------------------------------------------------------------
# Nmap Jitter Patcher (interactive)
# ------------------------------------------------------------
def ask_yes_no(prompt, default_yes=True):
    suffix = " [Y/n]: " if default_yes else " [y/N]: "
    while True:
        ans = input(prompt + suffix).strip().lower()
        if ans == '':
            return default_yes
        if ans in ('y', 'yes'):
            return True
        if ans in ('n', 'no'):
            return False
        print("Please answer 'y' or 'n'.")

def ask_directory(prompt, default):
    ans = input(f"{prompt} [{default}]: ").strip()
    return ans if ans else default

def apply_patch(filepath, verbose):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    old_block1 = '''  if (sdn.delayms) {
    if (TIMEVAL_MSEC_SUBTRACT(USI->now, lastprobe_sent) < (int) sdn.delayms) {
      if (when) {
        TIMEVAL_MSEC_ADD(*when, lastprobe_sent, sdn.delayms);
      }
      return false;
    }
  }'''

    new_block1 = '''  if (sdn.delayms) {
    // --- SCAN DELAY WITH RANDOM JITTER ---
    int base_delay = sdn.delayms;
    int jitter_percent = 20;
    int jitter_range = (base_delay * jitter_percent) / 100;
    if (jitter_range < 1) jitter_range = 1;
    int jitter = (get_random_u16() % (2 * jitter_range + 1)) - jitter_range;
    int effective_delay = base_delay + jitter;
    if (effective_delay < 0) effective_delay = 0;
'''
    if verbose:
        new_block1 += '''    fprintf(stderr, "[JITTER] host %s: base=%d ms, jitter=%+d ms, effective=%d ms\\n",
            target->targetipstr(), base_delay, jitter, effective_delay);
'''
    else:
        new_block1 += '''    // (verbose logs disabled)
'''
    new_block1 += '''    if (TIMEVAL_MSEC_SUBTRACT(USI->now, lastprobe_sent) < effective_delay) {
      if (when) {
        TIMEVAL_MSEC_ADD(*when, lastprobe_sent, effective_delay);
      }
      return false;
    }
  }'''

    if old_block1 not in content:
        print("ERROR: First block not found. Already patched?")
        return False
    content = content.replace(old_block1, new_block1, 1)

    old_block2 = '''  // Will any scan delay affect this?
  if (sdn.delayms) {
    TIMEVAL_MSEC_ADD(sendTime, lastprobe_sent, sdn.delayms);
    if (TIMEVAL_BEFORE(sendTime, USI->now))
      sendTime = USI->now;
    tdiff = TIMEVAL_MSEC_SUBTRACT(earliest_to, sendTime);'''

    new_block2 = '''  // Will any scan delay affect this?
  if (sdn.delayms) {
    // Recalculate jitter (consistent with above)
    int base_delay = sdn.delayms;
    int jitter_percent = 20;
    int jitter_range = (base_delay * jitter_percent) / 100;
    if (jitter_range < 1) jitter_range = 1;
    int jitter = (get_random_u16() % (2 * jitter_range + 1)) - jitter_range;
    int effective_delay = base_delay + jitter;
    if (effective_delay < 0) effective_delay = 0;
'''
    if verbose:
        new_block2 += '''    fprintf(stderr, "[JITTER] host %s (timeout calc): base=%d ms, effective=%d ms\\n",
            target->targetipstr(), base_delay, effective_delay);
'''
    else:
        new_block2 += '''    // (verbose logs disabled)
'''
    new_block2 += '''    TIMEVAL_MSEC_ADD(sendTime, lastprobe_sent, effective_delay);
    if (TIMEVAL_BEFORE(sendTime, USI->now))
      sendTime = USI->now;
    tdiff = TIMEVAL_MSEC_SUBTRACT(earliest_to, sendTime);'''

    if old_block2 not in content:
        print("ERROR: Second block not found. Already patched?")
        return False
    content = content.replace(old_block2, new_block2, 1)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    return True

def build_nmap(source_dir):
    print(f"\n🔨 Building Nmap in '{source_dir}'...")
    original_dir = os.getcwd()
    try:
        os.chdir(source_dir)
        if not os.path.isfile("Makefile"):
            print("Running ./configure ...")
            subprocess.run(["./configure"], check=True)
        print("Running make ...")
        subprocess.run(["make"], check=True)
        print("\n✅ Build successful!")
        return os.path.join(source_dir, "nmap")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Build failed: {e}")
        sys.exit(1)
    finally:
        os.chdir(original_dir)

def run_jitter_patcher():
    print("\n" + "=" * 60)
    print("    Nmap Jitter Patcher - Interactive")
    print("=" * 60)

    # Clone or existing file?
    if ask_yes_no("Clone fresh Nmap from GitHub?", default_yes=True):
        clone_dir = ask_directory("Clone into directory", "nmap-jitter")
        if os.path.exists(clone_dir):
            print(f"Error: Directory '{clone_dir}' already exists.")
            sys.exit(1)
        print(f"Cloning Nmap into '{clone_dir}'...")
        subprocess.run(["git", "clone", "https://github.com/nmap/nmap.git", clone_dir], check=True)
        subprocess.run(["touch", os.path.join(clone_dir, "configure")], check=True)
        filepath = os.path.join(clone_dir, "scan_engine.cc")
        source_dir = clone_dir
    else:
        filepath = input("Path to scan_engine.cc [./scan_engine.cc]: ").strip()
        if not filepath:
            filepath = "./scan_engine.cc"
        filepath = os.path.abspath(filepath)
        if not os.path.isfile(filepath):
            print(f"Error: File not found: {filepath}")
            sys.exit(1)
        source_dir = os.path.dirname(filepath)

    # Verbose logging?
    verbose = ask_yes_no("Enable verbose [JITTER] log messages during scans?", default_yes=True)

    # Build after patching?
    build_after = ask_yes_no("Build Nmap immediately after patching?", default_yes=True)

    # Backup
    backup = f"{filepath}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy(filepath, backup)
    print(f"\n📦 Backup: {backup}")

    # Patch
    print("\n🔧 Applying jitter patch...")
    if not apply_patch(filepath, verbose):
        print("❌ Patch failed. Restoring...")
        shutil.copy(backup, filepath)
        sys.exit(1)
    print("✅ Patch applied.")

    nmap_binary = None
    if build_after:
        nmap_binary = build_nmap(source_dir)
    else:
        print("\nTo build manually:")
        print(f"  cd {source_dir} && ./configure && make")
        nmap_binary = os.path.join(source_dir, "nmap")

    return nmap_binary

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    print("=" * 60)
    print("          P I N G u i n   S e t u p")
    print("=" * 60)

    # 1. Check tools
    check_tools()

    # 2. Ask if user wants to modify Nmap
    print("\n" + "-" * 40)
    if not ask_yes_no("Do you want to modify Nmap with the jitter patch?", default_yes=True):
        print("\n⚠️  Skipping Nmap modification.")
        nmap_path = None
    else:
        # 3. Run jitter patcher
        nmap_path = run_jitter_patcher()

    # 4. Alias creation
    print("\n" + "-" * 40)
    if ask_yes_no("Would you like to create a shell alias for the patched nmap?", default_yes=True):
        alias_name = input("Alias name [pinguin]: ").strip()
        if not alias_name:
            alias_name = "pinguin"
        if nmap_path:
            abs_nmap = os.path.abspath(nmap_path)
            create_alias(alias_name, abs_nmap)
        else:
            print("⚠️  No patched nmap binary found. Alias not created.")
    else:
        print("Alias creation skipped.")

    print("\n" + "=" * 60)
    print("🎉 Setup complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
