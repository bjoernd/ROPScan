#!/usr/bin/env python

import sys
import scriptine
import scriptine.shell
import scriptine.log
import bdutil


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
    
    
def parse_objdump_result(res):
    """Extract the opcode bytes from objdump's output stream"""
    
    stream = []
    
    return stream
    
    
def scan_command(filename):
    section_name = ".text" # we search for the text section as this is
                           # the one we'd like to scan through
    
    # run readelf -S on the file to find the section info
    cmd = "readelf -S %s | grep %s" % (filename, section_name)
    (start, size) = parse_readelf_result(scriptine.shell.backtick(cmd), section_name)
    if (start == -1 and size == -1):
        scriptine.log.error("%sCannot determine start/size of .text section%s", bdutil.Colors.Red, bdutil.Colors.Reset)
        return

    # use (start, size) to objdump text segment and extract opcode stream    
    cmd = "objdump -s --start-address=0x%08x --stop-address=0x%08x %s" % (start, start+size, filename)
    stream = parse_objdump_result(scriptine.shell.backtick(cmd))
    
    # analyze stream
    
    
def prereq_check():
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