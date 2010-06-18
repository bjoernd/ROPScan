#!/usr/bin/env python

import sys
import scriptine
import scriptine.shell
import scriptine.log
import bdutil


def parse_readelf_result(res):
    """Scan readelf result for start and size of .text segment"""
    start = -1
    size  = -1
    
    # readelf output parsing
    base_index = res.split().index(".text")
    
    scriptine.log.info("Start %08x Size %08x", start, size)
    return (start, size)
    
    
def scan_command(filename):
    section_name = ".text" # we search for the text section as this is
                           # the one we'd like to scan through
    
    # run readelf -S on the file to find the section info
    cmd = "readelf -S %s | grep %s" % (filename, section_name)
    retline = scriptine.shell.backtick(cmd)
    
    (start, size) = parse_readelf_result(retline)
    if (start == -1 and size == -1):
        scriptine.log.error("%sCannot determine start/size of .text section%s", bdutil.Colors.Red, bdutil.Colors.Reset)
        return
    
    
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