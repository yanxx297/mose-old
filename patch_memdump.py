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
        res = []
        dump.seek(offset);
        while True:
            memdump_page = dump.read(page_size)
            if memdump_page == "":
                break
            if memdump_page == taint_page:
                res.append(dump.tell() - page_size)
        return res


def patch_memdump(dumpfile, exploitfile, taint_map, offset = 0, page_size = 4096):
    with open(dumpfile, "rb+") as dump, open(dumpfile + "_patched", "wb") as out:
        count = 0
        out.write(dump.read(offset))
        print "Copied the first " + str(out.tell()) + " Bytes to patched file"
        while True:
            data = dump.read(page_size)
            if data == "":
                break

            if taint_map.has_key(out.tell()):
                count = count + 1
                with open(exploitfile, "rb+") as exploit:
                    exploit.seek(taint_map[out.tell()])
                    data = exploit.read(page_size)
                    datalen = len(data)
                    if datalen < page_size:
                        pdata = data.ljust(page_size, '\0')
                        print "Patch " + str(page_size) + " Bytes at " + hex(out.tell()) + \
                                " (orig size " + str(datalen)
                        out.write(pdata)
                    else:
                        print "Patch " + str(page_size) + " Bytes at " + hex(out.tell()) 
                        out.write(data)
            else:
                out.write(data)
        print "Totally patched " + str(count) + " pages"


def get_taint_map(taintfile, exploitfile, page_size = 4096):
    taint_map = {}
    with open(taintfile, "rb") as taint, open(exploitfile, "rb") as exploit:
        while True:
            taint_page = taint.read(page_size)
            if taint_page == "":
                break

            res = search_memdump(sys.argv[3], taint_page, 0xc0000000, page_size)
            if res == []:
                print "tainted page not found"
            else:
                for i in res:
                    print "find tainted page " + hex(taint.tell() - page_size) + " at " + hex(i)
                    taint_map[i] = taint.tell() - page_size
    return taint_map


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "Usage: ./patch-memdump.py <taint> <exploit> <memdump>"
        exit (1)

    page_size = 4096
    
    # hashmap(memdump_offset, taint/exploit_offset)
    taint_map = get_taint_map(sys.argv[1], sys.argv[2], page_size)
    print taint_map
    patch_memdump(sys.argv[3], sys.argv[2], taint_map, 0xc0000000, page_size)
    exit(0)
