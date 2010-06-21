#!/usr/bin/env python
# vim: set et ts=4
"""
This script uses objdump to extract code section(s) from a
binary and then disassembles sequences ending with C3 to
determine if this sequence would be a valid return sequence
used for a return-oriented-programming-based attack.
"""

"""
    DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO. 

  1. This program is free software. It comes without any warranty, to
     the extent permitted by applicable law. You can redistribute it
     and/or modify it under the terms of the Do What The Fuck You Want
     To Public License, Version 2, as published by Sam Hocevar. See
     http://sam.zoy.org/wtfpl/COPYING for more details. 
"""
import sys
import os

import scriptine
import scriptine.shell
import scriptine.log

from bdutil import Colors
from cmd import ReadelfCmd, ObjdumpCmd
from opcodestream import OpcodeStream


class CommandChecker():
    """
    Class for building shell command lines used by the program
    """
    def __init__(self):
        self.prerequisites = [ "udcli", "objdump", "readelf" ]


    def prereq_check(self):
        """Check if all required prerequisites for the shell-tool-based version
           are available."""

        # prerequisites to check for
        prereqs = ["udcli",
                   "objdump",
                   "readelf"]

        for pre in prereqs:
            res = scriptine.shell.backtick("which %s" % pre)
            if res == "":
                scriptine.log.warn("%s%s%s not found", Colors.Yellow,
                                   pre, Colors.Reset)
                return False

        return True


def scan_section(section, filename, dump, numbytes):
    """
    Scan a single section
    """
    tmpfile = "blub.tmp"
    section.dump()
    # use (start, size) to objdump text segment and extract opcode stream
    objdump = ObjdumpCmd()
    cmd = objdump.cmd_str(section.start, section.size, filename, tmpfile)
    res = scriptine.shell.sh(cmd)
    if res != 0:
        scriptine.log.error("%sError in objdump%s", Colors.Red,
                            Colors.Reset)

    stream = objdump.parse_result(tmpfile)
    if len(stream) == 0:
        scriptine.log.error("%sEmpty instruction stream?%s",
                            Colors.Red, Colors.Reset)

    scriptine.log.info("Stream bytes: %d, real size %d", len(stream),
                       section.size)
    # we must have extracted all bytes
    if len(stream) != section.size:
        print "Size mismatch: %d <-> %d" % (len(stream), section.size)
        print stream
        sys.exit(1)

    os.remove(tmpfile)

    ostream = OpcodeStream(stream)
    # analyze stream
    locations = ostream.find_sequences(opcode="c3", opcode_str="ret",
                                       byte_offs=numbytes)
    scriptine.log.log("Found: %d sequences.", len(locations))

    # check for uniqueness of sequences
    uniq_seqs = ostream.unique_sequences(locations)
    scriptine.log.log("       %d unique sequences", len(uniq_seqs))

    # get unique locations by creating a set of offsets
    c3_locs = set([offs for (offs, length) in locations])
    scriptine.log.log("       %d unique C3 locations", len(c3_locs))

    if dump == "yes":
        ostream.dump_locations_with_offset(locations, section.start)

    return (locations, len(uniq_seqs), len(c3_locs))


def scan_command(filename, dump="yes", numbytes=20):
    """
    Shell command: scan binary for C3 instruction sequences

    Options:
       filename  -- binary to scan
       dump      -- dump sequences (yes/no), default: yes
    """
    tmpfile = "foo.tmp"

    # run readelf -S on the file to find the section info
    readelf = ReadelfCmd()
    cmd = readelf.cmd_str(filename, tmpfile)
    res = scriptine.shell.sh(cmd)
    if res != 0:
        scriptine.log.error("%sreadelf error%s", Colors.Red,
                            Colors.Reset)
        return

    the_list = readelf.parse_result(tmpfile)
    scriptine.log.log("Found %d executable sections.", len(the_list))
    if (len(the_list) == 0):
        scriptine.log.error("%sReadelf error: no executable sections found.%s",
                            Colors.Red, Colors.Reset)
        return

    global_sequences = 0
    global_uniq_seqs = 0
    global_uniq_locs = 0

    for sec in the_list:
        (seq, uniq_seq, uniq_loc) = scan_section(sec, filename, dump, numbytes)
        global_sequences = global_sequences + len(seq)
        global_uniq_seqs = global_uniq_seqs + uniq_seq
        global_uniq_locs = global_uniq_locs + uniq_loc

        if dump:
        l = set()
        print "Unique C3 locations:",
        for (loc, ln) in seq:
            if not loc in l:
                l.add(loc)
                print hex(loc + sec.start),

    scriptine.log.log("%s============= FINISHED =============%s",
                      Colors.Cyan, Colors.Reset)
    scriptine.log.log("Overall sequences found: %d", global_sequences)
    scriptine.log.log("       Unique sequences: %d", global_uniq_seqs)
    scriptine.log.log("       Unique locations: %d", global_uniq_locs)

if __name__ == "__main__":
    if (CommandChecker().prereq_check()):
        scriptine.run()
    else:
        scriptine.log.error(
            "Missing shell tool(s). No native implementation (yet).")
