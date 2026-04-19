#!/usr/bin/env python3
"""
add_jitter_robust.py - Modifies HostScanStats::sendOK() in scan_engine.cc
to add random jitter to --scan-delay. Works across Nmap versions.
"""

import re
import sys
import shutil
from datetime import datetime

def apply_jitter_modification(content):
    # Find the function definition
    pattern = r'(bool HostScanStats::sendOK\(struct timeval \*when\) const \{)'
    match = re.search(pattern, content)
    if not match:
        print("ERROR: Could not find HostScanStats::sendOK function.")
        return None

    func_start = match.end()

    # Find matching closing brace (simple brace counter)
    brace_count = 1
    i = func_start
    while i < len(content) and brace_count > 0:
        if content[i] == '{':
            brace_count += 1
        elif content[i] == '}':
            brace_count -= 1
        i += 1
    func_end = i
    function_body = content[func_start:func_end-1]  # excluding the final closing brace

    # --- Modify the function body ---
    # Replace the first occurrence of the delay check
    # Pattern: if (sdn.delayms) { ... } block that checks TIMEVAL_MSEC_SUBTRACT
    # We'll find both blocks and replace them.

    # Helper to insert jitter logic
    def replace_delay_block(match):
        indent = match.group(1)
        base_var = match.group(2)
        timeval_check = match.group(3)
        return f'''{indent}// --- SCAN DELAY WITH RANDOM JITTER (AUTO-PATCH) ---
{indent}if ({base_var}) {{
{indent}    // Base delay from --scan-delay (milliseconds)
{indent}    int base_delay = {base_var};
{indent}    
{indent}    // Add ±20% random jitter
{indent}    int jitter_percent = 20;
{indent}    int jitter_range = (base_delay * jitter_percent) / 100;
{indent}    if (jitter_range < 1) jitter_range = 1;
{indent}    int jitter = (get_random_u16() % (2 * jitter_range + 1)) - jitter_range;
{indent}    
{indent}    int effective_delay = base_delay + jitter;
{indent}    if (effective_delay < 0) effective_delay = 0;
{indent}
{indent}    fprintf(stderr, "[JITTER] host %s: base=%d ms, jitter=%+d ms, effective=%d ms\\n",
{indent}            target->targetipstr(), base_delay, jitter, effective_delay);
{indent}
{indent}    {timeval_check}
{indent}    '''

    # Pattern for the first block (the main delay check)
    pattern1 = re.compile(
        r'(\s*)if\s*\(\s*(sdn\.delayms)\s*\)\s*\{\s*'
        r'if\s*\(\s*TIMEVAL_MSEC_SUBTRACT\s*\(\s*USI->now\s*,\s*lastprobe_sent\s*\)\s*<\s*\(int\)\s*\1\s*\)\s*\{',
        re.DOTALL
    )
    function_body = pattern1.sub(replace_delay_block, function_body, count=1)

    # Pattern for the second block (the timeout calculation)
    pattern2 = re.compile(
        r'(\s*)if\s*\(\s*(sdn\.delayms)\s*\)\s*\{\s*'
        r'TIMEVAL_MSEC_ADD\s*\(\s*sendTime\s*,\s*lastprobe_sent\s*,\s*\1\s*\);',
        re.DOTALL
    )

    def replace_second_block(match):
        indent = match.group(1)
        base_var = match.group(2)
        return f'''{indent}if ({base_var}) {{
{indent}    // Recalculate jitter (consistent with above)
{indent}    int base_delay = {base_var};
{indent}    int jitter_percent = 20;
{indent}    int jitter_range = (base_delay * jitter_percent) / 100;
{indent}    if (jitter_range < 1) jitter_range = 1;
{indent}    int jitter = (get_random_u16() % (2 * jitter_range + 1)) - jitter_range;
{indent}    int effective_delay = base_delay + jitter;
{indent}    if (effective_delay < 0) effective_delay = 0;
{indent}
{indent}    TIMEVAL_MSEC_ADD(sendTime, lastprobe_sent, effective_delay);'''

# For debugging, we can also print the timeout calculation on the empty ident line before TIMEVAL_MSEC_ADD
#
#{indent}    fprintf(stderr, "[JITTER] host %s (timeout calc): base=%d ms, effective=%d ms\\n",
#{indent}            target->targetipstr(), base_delay, effective_delay);
#
    function_body = pattern2.sub(replace_second_block, function_body, count=1)

    # Also need to adjust the comparison inside the if block for the first pattern
    # Because our replacement added the condition but we need to change the original condition check
    # Actually our replace_delay_block already handles that; we replaced the whole block.

    # Reconstruct full function
    modified_function = content[:func_start] + function_body + '\n}' + content[func_end:]
    return modified_function

def main():
    filename = 'scan_engine.cc'
    if len(sys.argv) > 1:
        filename = sys.argv[1]

    # Backup
    backup = f"{filename}.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy(filename, backup)
    print(f"Backup created: {backup}")

    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()

    modified = apply_jitter_modification(content)
    if modified is None:
        print("Modification failed.")
        sys.exit(1)

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(modified)

    print(f"Successfully patched {filename}.")
    print("Now run: make clean && make")
    print("To revert: cp " + backup + " " + filename)

if __name__ == '__main__':
    main()