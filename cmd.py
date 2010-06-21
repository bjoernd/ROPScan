# vim: set ts=4 et
"""
Commands used by ROPCheck
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

import re
from bdutil import abstract
from data import Section
import scriptine

class Cmd:
    """
    Abstract command class
    """
    def __init__(self):
        pass

    def cmd_str(self):
        """abstract: return cmd string to execute"""
        abstract()

    def parse_result(self):
        """abstract: parse cmd result"""
        abstract()


class ReadelfCmd(Cmd):
    """
    Command class representing a readelf call
    """
    def __init__(self):
        Cmd.__init__(self)
        # readline formats sections like this:
        #   [Nr] Name Type Addr Off Size ES Flg Lk Inf Al
        self.section_re = re.compile("(\s*)"            # leading spaces
                                   + "\[([\s\d].*)\]"   # number in brackets
                                   + "\s+"              # spaces in between
                                   + "([\.\w-]+)"       # name
                                   + "\s+"              # spaces in between
                                   + "(\w+)"            # type
                                   + "\s+"              # spaces in between
                                   + "([0-9a-f]{8})"    # start addr
                                   + "\s+"              # spaces in between
                                   + "([0-9a-f]{6})"    # offset in file
                                   + "\s+"              # spaces in between
                                   + "([0-9a-f]{6})"    # size
                                   + "\s+"              # spaces in between
                                   + "([0-9a-f]{2})"    # ES
                                   + "(.*)")            # rest

        self.nondigit_re = re.compile("(\D+)")

    def cmd_str(self, binaryfile, tmpfile):
        """
        Generate call to readelf extracting segment list
        """
        cmd = "readelf -S %s > %s" % (binaryfile, tmpfile)
        return cmd


    def parse_result(self, tmpfile):
        """Scan readelf result for start and size of .text segment"""

        retlist = []

        lines = file(tmpfile).readlines()

        for line in lines:
            match = self.section_re.match(line.strip())
            if match:
                name  = match.groups()[2]
                start = match.groups()[4]
                size  = match.groups()[6]
                rest  = match.groups()[8].split()

                # rest has flags member, if the first bin contains
                # alphanumeric characters
                if self.nondigit_re.match(rest[0]) and \
                   'X' in rest[0]:
                    retlist += [Section(name, start, size)]

        return retlist


class ObjdumpCmd(Cmd):
    """
    Objdump command class
    """
    def __init__(self):
        Cmd.__init__(self)
        self.byte4_re = re.compile("([a-f0-9]{2})" + "([a-f0-9][a-f0-9])?"*3)

    def cmd_str(self, start_addr, segment_size, binaryfile, tmpfile):
        """
        Generate call to objdump extracting bytes between start and start+size
        """
        cmd = "objdump -s "
        cmd += "--start-address=0x%08x " % start_addr
        cmd += "--stop-address=0x%08x " % (start_addr+segment_size)
        cmd += "%s >%s" % (binaryfile, tmpfile)
        return cmd


    def parse_result(self, tmpfile):
        """Extract the opcode bytes from objdump's output stream"""
        stream = []

        tmpf = file(tmpfile)

        for line in tmpf.readlines():
            _bytes = line.split()

            # Strip unneeded output:
            if len(_bytes) == 0:
                continue
            if self.byte4_re.match(_bytes[1]) is None:
                scriptine.log.info("Dropping %s", _bytes)
                continue

            # extract inner 4 columns
            for data in _bytes[1:5]:
                match = self.byte4_re.match(data)
                if match:
                    for byte in match.groups():
                        if byte != "" and byte is not None:
                            stream += [byte]
                else: 
                    pass

        return stream


class UDCLICmd(Cmd):
    """
    Command for the UDCLI disassembler
    """
    def __init__(self):
        Cmd.__init__(self)

    def cmd_str(self, data, tmpfile):
        """
        Generate call to UDCLI disassembler
        """
        cmd = "echo %s |  udcli -x -32 -noff -nohex >%s" % (data, tmpfile)
        return cmd

    def parse_result(self):
        """
        We don't do anything with the UDCLI result on stdout so far
        """
        pass



