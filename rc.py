#!/usr/bin/env python

import sys
import re
import os
import scriptine
import scriptine.shell
import scriptine.log
import bdutil

byte8_regex = re.compile("([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})")

def parse_readelf_result(res, sec_name):
    """Scan readelf result for start and size of .text segment"""
    start = -1
    size  = -1
    
    elements = res.split()
    
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
    
    f = file(tmpfile)
    
    for line in f.readlines():
        x = line.split()
    
        # Strip unneeded output:
        # We need at least 6 bins here (address + 4 x 4 bytes + textdump).
        # textdump may contain spaces, though, so we must not be sure about
        # having exactly 6 bins.
        if len(x) < 6:
            continue
        if len(x[0]) != 8:
            continue
        
        # extract inner 4 columns
        for data in x[1:5]:
            m = byte8_regex.match(data)
            if (m):
                stream += m.groups()
            else:
                print "\"%s\"" % data, m
    
    return stream


def analyze_byte_stream(stream):
    return ()
    
    
def scan_command(filename):
    section_name = ".text" # we search for the text section as this is
                           # the one we'd like to scan through
    tmpfile = "foo.tmp"
    
    # run readelf -S on the file to find the section info
    cmd = "readelf -S %s | grep %s" % (filename, section_name)
    (start, size) = parse_readelf_result(scriptine.shell.backtick(cmd), section_name)
    if (start == -1 and size == -1):
        scriptine.log.error("%sCannot determine start/size of .text section%s", bdutil.Colors.Red, bdutil.Colors.Reset)
        return

    # use (start, size) to objdump text segment and extract opcode stream    
    cmd = "objdump -s --start-address=0x%08x --stop-address=0x%08x %s >%s" % (start, start+size, filename, tmpfile)
    res = scriptine.shell.sh(cmd)
    if res != 0:
        scriptine.log.error("%sError in objdump%s", bdutil.Colors.Red, bdutil.Colors.Reset)
    
    stream = parse_objdump_result(tmpfile)    
    if len(stream) == 0:
        scriptine.log.error("%sEmpty instruction stream?%s", bdutil.Colors.Red, bdutil.Colors.Reset)
    
    scriptine.log.info("Stream bytes: %d, real size %d", len(stream), size)    
    
    os.remove(tmpfile)
    
    # analyze stream
    analyze_byte_stream(stream)
    
    
def prereq_check():
    """Check if all required prerequisites for the shell-tool-based version
       are available."""

    # prerequisites to check for
    prereqs = ["udcli",
               "objdump",
               "readelf"]
    
    for p in prereqs:
        x = scriptine.shell.backtick("which %s" % p)
        if x == "":
            scriptine.log.warn("%s%s%s not found", bdutil.Colors.Yellow, p, bdutil.Colors.Reset)
            return False
        
    return True


if __name__ == "__main__":
    if (prereq_check()):
        scriptine.run()
    else:
        scriptine.log.error("Missing shell tool(s). No native implementation (yet).")