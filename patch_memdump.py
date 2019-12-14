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

def load_file_to_hashmap(filename, page_size = 4096):
    res = {}
    with open(filename, "rb+") as fd:
        while True:
            data = fd.read(page_size)
            if data == "":
                break
            else:
                res[data] = fd.tell() - page_size
    return res


def patch_memdump(dumpfile, exploitfile, taint, offset = 0, page_size = 4096):
    res = []
    outfile = dumpfile + "_patched"
    with open(dumpfile, "rb+") as dump, open(outfile, "wb") as out:
        count = 0
        out.write(dump.read(offset))
        print "Copied the first " + str(out.tell()) + " Bytes to patched file"
        while True:
            data = dump.read(page_size)
            if data == "":
                break

            if taint.has_key(data):
                res.append(out.tell())
                count = count + 1
                with open(exploitfile, "rb+") as exploit:
                    exploit.seek(taint[data])
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
        return (outfile, res)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "Usage: ./patch-memdump.py <taint> <exploit> <memdump>"
        exit (1)

    page_size = 4096
    
    taint = load_file_to_hashmap(sys.argv[1], page_size)
    patch_memdump(sys.argv[3], sys.argv[2], taint, 0xc0000000, page_size)
    exit(0)
