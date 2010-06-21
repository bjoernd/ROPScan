import re
from data import Section
import scriptine

class Cmd:
    """
    Abstract command class
    """
    def __init__(self):     abstract()
    def cmd_str(self):      abstract()
    def parse_result(self): abstract()


class ReadelfCmd(Cmd):
    def __init__(self):
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
                    flags = rest[0]
                    retlist += [Section(name, start, size)]

        return retlist


class ObjdumpCmd(Cmd):
    """
    Objdump command class
    """
    def __init__(self):
        self.BYTE8_RE = re.compile("([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})([a-f0-9]{2})")


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
            bytes = line.split()

            # Strip unneeded output:
            if len(bytes) == 0:
                continue
            if not self.BYTE8_RE.match(bytes[1]):
                scriptine.log.debug("Dropping %s", bytes)
                continue

            # extract inner 4 columns
            for data in bytes[1:5]:
                match = self.BYTE8_RE.match(data)
                if match:
                    stream += match.groups()
                else:
                    pass

        return stream


class UDCLICmd(Cmd):
    """
    Command for the UDCLI disassembler
    """
    def __init__(self):
        pass

    def cmd_str(self, data, tmpfile):
        """
        Generate call to UDCLI disassembler
        """
        cmd = "echo %s |  udcli -x -32 -noff -nohex >%s" % (data, tmpfile)
        return cmd

    def parse_result(self):
        pass



