#!/usr/bin/env python3
"""
Reliable Nmap Jitter Patcher using exact string replacement.
Works on the exact scan_engine.cc content provided.
"""

import sys
import shutil
import os
from datetime import datetime

def apply_patch(filepath, verbose=False):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # --- First block to replace ---
    old_block1 = '''  if (sdn.delayms) {
    if (TIMEVAL_MSEC_SUBTRACT(USI->now, lastprobe_sent) < (int) sdn.delayms) {
      if (when) {
        TIMEVAL_MSEC_ADD(*when, lastprobe_sent, sdn.delayms);
      }
      return false;
    }
  }'''

    new_block1 = '''  if (sdn.delayms) {
    // --- SCAN DELAY WITH RANDOM JITTER (AUTO-PATCH) ---
    int base_delay = sdn.delayms;
    int jitter_percent = 20;
    int jitter_range = (base_delay * jitter_percent) / 100;
    if (jitter_range < 1) jitter_range = 1;
    int jitter = (get_random_u16() % (2 * jitter_range + 1)) - jitter_range;
    int effective_delay = base_delay + jitter;
    if (effective_delay < 0) effective_delay = 0;
'''
    if verbose:
        new_block1 += '''
    fprintf(stderr, "[JITTER] host %s: base=%d ms, jitter=%+d ms, effective=%d ms\\n",
            target->targetipstr(), base_delay, jitter, effective_delay);
'''
    else:
        new_block1 += '''
    // (verbose logging disabled)
'''
    new_block1 += '''
    if (TIMEVAL_MSEC_SUBTRACT(USI->now, lastprobe_sent) < effective_delay) {
      if (when) {
        TIMEVAL_MSEC_ADD(*when, lastprobe_sent, effective_delay);
      }
      return false;
    }
  }'''

    if old_block1 not in content:
        print("ERROR: First block not found. Already patched or different version?")
        return False

    content = content.replace(old_block1, new_block1, 1)

    # --- Second block to replace ---
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
        new_block2 += '''
    fprintf(stderr, "[JITTER] host %s (timeout calc): base=%d ms, effective=%d ms\\n",
            target->targetipstr(), base_delay, effective_delay);
'''
    else:
        new_block2 += '''
    // (verbose logging disabled)
'''
    new_block2 += '''
    TIMEVAL_MSEC_ADD(sendTime, lastprobe_sent, effective_delay);
    if (TIMEVAL_BEFORE(sendTime, USI->now))
      sendTime = USI->now;
    tdiff = TIMEVAL_MSEC_SUBTRACT(earliest_to, sendTime);'''

    if old_block2 not in content:
        print("ERROR: Second block not found. Already patched or different version?")
        return False

    content = content.replace(old_block2, new_block2, 1)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    return True

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Patch Nmap scan_engine.cc with jitter")
    parser.add_argument("filename", nargs="?", default="scan_engine.cc")
    parser.add_argument("--verbose", "-v", action="store_true", help="Include log messages")
    parser.add_argument("--clone", metavar="DIR", nargs="?", const="nmap-jitter",
                        help="Clone fresh Nmap from GitHub and patch it")
    parser.add_argument("--build", action="store_true", help="Run ./configure && make after patching")
    args = parser.parse_args()

    if args.clone:
        import subprocess
        target_dir = args.clone
        if os.path.exists(target_dir):
            print(f"Directory '{target_dir}' already exists.")
            sys.exit(1)
        print(f"Cloning Nmap into '{target_dir}'...")
        subprocess.run(["git", "clone", "https://github.com/nmap/nmap.git", target_dir], check=True)
        filepath = os.path.join(target_dir, "scan_engine.cc")
    else:
        filepath = args.filename

    filepath = os.path.abspath(filepath)
    if not os.path.isfile(filepath):
        print(f"File not found: {filepath}")
        sys.exit(1)

    backup = f"{filepath}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy(filepath, backup)
    print(f"Backup: {backup}")

    if apply_patch(filepath, args.verbose):
        print("Patch applied successfully.")
    else:
        print("Patch failed. Restoring from backup...")
        shutil.copy(backup, filepath)
        sys.exit(1)

    if args.build:
        source_dir = os.path.dirname(filepath)
        print(f"Building in {source_dir}...")
        os.chdir(source_dir)
        if not os.path.isfile("Makefile"):
            subprocess.run(["./configure"], check=True)
        subprocess.run(["make"], check=True)
        print(f"Build complete. Binary: {os.path.join(source_dir, 'nmap')}")
    else:
        print("To build: cd", os.path.dirname(filepath), "&& ./configure && make")

if __name__ == "__main__":
    main()