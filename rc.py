#!/usr/bin/env python
"""
This script uses objdump to extract code section(s) from a
binary and then disassembles sequences ending with C3 to
determine if this sequence would be a valid return sequence
used for a return-oriented-programming-based attack.
"""

import sys
import re
import os
import scriptine
import scriptine.shell
import scriptine.log
import bdutil

BYTE8_RE = re.compile("([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})")

def parse_readelf_result(tmpfile, sec_name):
    """Scan readelf result for start and size of .text segment"""
    start = -1
    size  = -1

    res = file(tmpfile) .readlines()
    elements = res[0].split()

    # Depending on the position of .text in the section list, splitting
    # the result line will give a varying count of elements.
    # Start and size are at fixed indices from the position of .text, though
    base_index = elements.index(sec_name)

    start = int(elements[base_index + 2], 16)
    size  = int(elements[base_index + 4], 16)

    scriptine.log.info("Start %08x Size %08x", start, size)
    return (start, size)


def parse_objdump_result(tmpfile):
    """Extract the opcode bytes from objdump's output stream"""

    stream = []

    tmpf = file(tmpfile)

    for line in tmpf.readlines():
        bytes = line.split()

        # Strip unneeded output:
        if len(bytes) == 0:
            continue
        if not BYTE8_RE.match(bytes[1]):
            scriptine.log.debug("Dropping %s", bytes)
            continue

        # extract inner 4 columns
        for data in bytes[1:5]:
            match = BYTE8_RE.match(data)
            if match:
                stream += match.groups()
            else:
                pass

    return stream


def find_sequences_in_stream(stream, byte_offs=20,
                             opcode="c3", opcode_str="ret"):
    """
    Run through byte stream, find occurences of opcode and check if the
    corresponding disassembly for the last [1, byte_offs] bytes ends with
    a ret instruction.

    Returns: List of (offset, length) tuples representing the valid sequences.
    """

    tmpfile = "foo.tmp"
    ret = []

    # we need at least one more byte than the C3 instruction,
    # so less than 2 is bad
    if (byte_offs < 2):
        scriptine.log.error("Byte offset (%d) too small.", byte_offs)
        return ret

    scriptine.log.log("Scanning byte stream for %s instruction sequences",
                      opcode)

    # find first occurence
    idx = stream.index(opcode)
    while idx > 0:
        scriptine.log.log("Position in stream: %.2f%%",
                          100.0 * float(float(idx+1) / len(stream)))

        # if occurence is less than byte_offs bytes into the stream,
        # adapt the limit
        if idx > byte_offs:
            limit = byte_offs
        else:
            limit = idx+1

        # validity check sequences by disassembling
        for i in range(1, limit):
            # byte string to send to disassembler
            data = "".join([c+' ' for c in stream[idx-i: idx+1]])

            cmd = "echo %s |  udcli -x -32 -noff -nohex >%s" % (data, tmpfile)
            res = scriptine.shell.sh(cmd)
            if res != 0:
                print cmd, res

            # sequence is valid, if tmpfile contains opcode_str in the last line
            tmpf = file(tmpfile)
            lines = [l.strip() for l in tmpf.readlines()]

            # find first occurrence of RET in disassembly
            try:
                finishing_idx = lines.index(opcode_str)
            except: # might even have NO ret at all
                finishing_idx = -1

            # -> this sequence is a valid new sequence, iff RET only occurs as
            #    the final instruction
            if finishing_idx == len(lines)-1:
                ret += [(idx, i)]

        try:
            idx = stream.index(opcode, idx+1)
        except:
            idx = -1

    os.remove(tmpfile)

    return ret


def scan_command(filename, dump="yes", numbytes=20):
    """
    Shell command: scan binary for C3 instruction sequences

    Options:
       filename  -- binary to scan
       dump      -- dump sequences (yes/no), default: yes
    """
    section_name = ".text" # we search for the text section as this is
                           # the one we'd like to scan through
    tmpfile = "foo.tmp"

    # run readelf -S on the file to find the section info
    cmd = "readelf -S %s | grep %s >%s" % (filename, section_name, tmpfile)
    res = scriptine.shell.sh(cmd)
    if res != 0:
        scriptine.log.error("%sreadelf error%s", bdutil.Colors.Red,
                            bdutil.Colors.Reset)
        return

    (start, size) = parse_readelf_result(tmpfile, section_name)
    if (start == -1 and size == -1):
        scriptine.log.error("%sCannot determine start/size of .text section%s",
                            bdutil.Colors.Red, bdutil.Colors.Reset)
        return

    # use (start, size) to objdump text segment and extract opcode stream
    cmd = "objdump -s "
    cmd += "--start-address=0x%08x --stop-address=0x%08x " % (start, start+size)
    cmd += "%s >%s" % (filename, tmpfile)

    res = scriptine.shell.sh(cmd)
    if res != 0:
        scriptine.log.error("%sError in objdump%s", bdutil.Colors.Red,
                            bdutil.Colors.Reset)

    stream = parse_objdump_result(tmpfile)
    if len(stream) == 0:
        scriptine.log.error("%sEmpty instruction stream?%s",
                            bdutil.Colors.Red, bdutil.Colors.Reset)

    scriptine.log.info("Stream bytes: %d, real size %d", len(stream), size)
    if len(stream) != size:
        print stream
        sys.exit(1)

    os.remove(tmpfile)

    # analyze stream
    locations = find_sequences_in_stream(stream, opcode="c3",
                                         opcode_str="ret", byte_offs=numbytes)
    scriptine.log.log("Found: %d sequences.", len(locations))

    # get unique locations by creating a set of offsets
    c3_locs = set([offs for (offs,length) in locations])
    scriptine.log.log("       %d unique C3 locations", len(c3_locs))

    if dump == "yes":
        for (c3_offset, length) in locations:
            begin = start + c3_offset - length
            print "0x%08x + %3d:  %s" % (begin, length, bdutil.Colors.Cyan),
            print " ".join(stream[c3_offset - length:c3_offset+1]),
            print "%s" % (bdutil.Colors.Reset)


def prereq_check():
    """Check if all required prerequisites for the shell-tool-based version
       are available."""

    # prerequisites to check for
    prereqs = ["udcli",
               "objdump",
               "readelf"]

    for pre in prereqs:
        res = scriptine.shell.backtick("which %s" % pre)
        if res == "":
            scriptine.log.warn("%s%s%s not found", bdutil.Colors.Yellow,
                               pre, bdutil.Colors.Reset)
            return False

    return True


if __name__ == "__main__":
    if (prereq_check()):
        scriptine.run()
    else:
        scriptine.log.error(
            "Missing shell tool(s). No native implementation (yet).")
