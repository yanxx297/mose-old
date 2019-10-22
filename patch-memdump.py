#!/usr/bin/env python

# Find each block of a random file cached in a memdump, and replace it
# with the coressponding block in another exploit disk image.
# The disk image should be the same size of the random file.
#
# This process is similar to taint analysis, where the random file is used
# to taint certain locations in memory.
#
# Usage: ./patch-memdump.py <taint> <exploit> <memdump>

import sys


def search_memdump(dumpfile, taint_page, offset = 0, page_size = 4096):
    with open(dumpfile, "rb+") as dump:
        dump.seek(offset);
        while True:
            memdump_page = dump.read(page_size)
            if memdump_page == "":
                break
            if memdump_page == taint_page:
                return dump.tell()
        return None


def patch_memdump(dumpfile, exploitfile, taint_map, offset = 0, page_size = 4096):
    with open(dumpfile, "rb+") as dump, open(dumpfile + "_patched", "wb") as out:
        out.write(dump.read(offset))
        print "Copied the first " + str(out.tell()) + "Bytes to patched file"
        while True:
            data = dump.read(page_size)
            if data == "":
                break

            if taint_map.has_key(out.tell()):
                with open(exploitfile, "rb+") as exploit:
                    exploit.seek(taint_map[out.tell()])
                    out.write(exploit.read(page_size))
            else:
                out.write(data)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "Usage: ./patch-memdump.py <taint> <exploit> <memdump>"
        exit (1)

    page_size = 4096
    
    # hashmap(memdump_offset, taint/exploit_offset)
    taint_map = {}

    with open(sys.argv[1], "rb") as taint, open(sys.argv[2], "rb") as exploit:
        while True:
            taint_page = taint.read(page_size)
            if taint_page == "":
                break

            res = search_memdump(sys.argv[3], taint_page, 0xc0000000, page_size)
            if res == None:
                print "tainted page not found"
            else:
                print("find tainted page at " + hex(res))
                taint_map[res] = taint.tell()
        print taint_map
        patch_memdump(sys.argv[3], sys.argv[2], taint_map, 0xc0000000, page_size)
        exit(0)
