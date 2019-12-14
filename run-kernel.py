#!/usr/bin/env python

# Construct fuzzball command line for running a Linux kernel memdump

import os.path
import argparse
import subprocess
import pickle
from patch_memdump import *

def str_to_hex(s):
    return int(s, 0)


def handle_tainted_memdump(dumpfile, exploitfile, taintfile, offset = 0, page_size = 4096):
    res = []

    # Replace taint with the actual disk image
    taint = load_file_to_hashmap(taintfile, page_size)
    (outfile, mem) = patch_memdump(dumpfile, exploitfile, taint, offset, page_size)

    # Generate cmdline setting replaced memory to concolic
    for m in mem:
        res += ['-concolic-mem', hex(m) + '+' + str(page_size)]

    # Convert QEMU raw memdump to TEMU format state
    subprocess.call(["perl", "raw-to-state.pl", outfile, "0x0", outfile + ".state"])
    with open(outfile + ".tmp", "wb") as tmp:
        pickle.dump(res, tmp)
    return (outfile + ".state", res)


def fuzzball_cmdline_taint(args):
    cmdline = [
            '/export/scratch/Project/mose/fuzzball/exec_utils/fuzzball',
            '-trace-stores', '-trace-loads', '-trace-insns', '-trace-callstack',
            '-trace-basic', '-trace-regions', '-trace-temps', '-trace-register-updates',
            '-trace-decisions', '-trace-conditions',
            '-zero-memory',             
            '-concolic-prob', '1.0', '-num-paths', '1',
            '-solver', 'smtlib', '-solver-path', '../lib/z3/build/z3',

            # Simplify path cond by removing symbolic vals that only have one 
            # possible value
            '-implied-value-conc',

            # Since we run a full execution, turn off sym region to avoid 
            # Strange Term
            '-no-sym-regions',

            # Turn lookup table into a Ite expression rather than branching on 
            # it
            '-table-limit', '10', 
            '-trace-tables',

            # Skip irrelevant function calls that cause unsupported IO operation
            '-skip-func-ret', '0xc1241390=0',
            '-skip-func-ret', '0xc109bc6a=0',

            '-load-region', '0x0+0xffffffff']

    (state, conc_mem) = handle_tainted_memdump(args.dumpfile, args.exploit, 
            args.taint, args.offset, args.size)

    cmdline += ['-state', state]
    cmdline += conc_mem    
    cmdline += [
            '-start-addr', '0xc119a670',
            '-initial-esp', '0xc7193f88',
            '-initial-gdtr', '0xffc01000']
    with open(args.dumpfile + ".cmd", "w") as cmdfile:
        cmdfile.write(" ".join(cmdline))
    subprocess.call(cmdline)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(help="Select mode")
    parser_t = subparsers.add_parser("taint")

    parser_t.add_argument("taint", help="Path to the taint file")
    parser_t.add_argument("exploit", help="Path to the exploit file to replace the taint")
    parser_t.add_argument("dumpfile", help="Path to the memdump file to patch")
    parser_t.add_argument("-pagesize", metavar="Bytes", dest="size", type=int, 
            default=4096, 
            help="Taint page size to be replaced(4096 by default)")
    parser_t.add_argument("-offset", metavar="Addr", dest="offset", type=str_to_hex, 
            default=0, 
            help="Starting location to scan tainted pages (0x0 by default)")
    parser_t.set_defaults(func=fuzzball_cmdline_taint)

    args = parser.parse_args()
    args.func(args)
