"""
OpcodeStream class used by ROPCheck
"""
import scriptine
import os
import hashlib
from cmd import UDCLICmd
from bdutil import Colors

class OpcodeStream():
    """
    An opcode stream represents a stream of bytes that are scanned for
    valid RET sequences
    """
    def __init__(self, bytestream):
        self.stream = bytestream

    def find_sequences(self, byte_offs=20,
                       opcode="c3", opcode_str="ret"):
        """
        Run through byte stream, find occurences of opcode and check if the
        corresponding disassembly for the last [1, byte_offs] bytes ends with
        a ret instruction.

        Returns: List of (offset, length) tuples representing the valid sequences.
        """

        tmpfile = "foo.tmp"
        retlist = []

        # we need at least one more byte than the C3 instruction,
        # so less than 2 is bad
        if (byte_offs < 2):
            scriptine.log.error("Byte offset (%d) too small.", byte_offs)
            return retlist

        scriptine.log.log("Scanning byte stream for %s instruction sequences",
                          opcode)

        # find first occurence
        try:
            idx = self.stream.index(opcode)
            while idx > 0:
                streampos_str = "Position in stream: %02.2f%%" % \
                        (100.0 * float(idx+1) / len(self.stream))
                print streampos_str,

                # if occurence is less than byte_offs bytes into the stream,
                # adapt the limit
                if idx > byte_offs:
                    limit = byte_offs
                else:
                    limit = idx+1

                # validity check sequences by disassembling
                for i in range(1, limit):
                    # byte string to send to disassembler
                    byte_data = \
                        "".join([c+' ' for c in self.stream[idx-i: idx+1]])

                    udcli = UDCLICmd()
                    cmd = udcli.cmd_str(byte_data, tmpfile)
                    res = scriptine.shell.sh(cmd)
                    if res != 0:
                        print "ERROR: ", cmd, res

                    # sequence is valid, if tmpfile contains opcode_str 
                    # in the last line
                    tmpf = file(tmpfile)
                    lines = [l.strip() for l in tmpf.readlines()]

                    # find first occurrence of RET in disassembly
                    try:
                        finishing_idx = lines.index(opcode_str)
                    except ValueError: # might even have NO ret at all
                        finishing_idx = -1

                    # -> this sequence is a valid new sequence, iff RET
                    # only occurs as the final instruction
                    if finishing_idx == len(lines)-1:
                        retlist += [(idx, i)]

                try:
                    idx = self.stream.index(opcode, idx+1)
                except ValueError:
                    idx = -1

                # N chars left, 1 up
                print("\033[%dD\033[A" % len(streampos_str))

            os.remove(tmpfile)
            print ""

        except ValueError:
            pass


        return retlist


    def unique_sequences(self, locations):
        """
        Given a byte stream and a set of locations, determine how
        many unique sequences are within the stream.
        """
        uniq_seqs = set()
        for (off, length) in locations:
            seq = "".join(self.stream[off-length:off+1])
            hsh = hashlib.md5(seq)
            uniq_seqs.add(hsh.hexdigest())

        return uniq_seqs


    def dump_byte_stream(self, offset, length):
        """
        Dump byte stream at given (offset, length) pairs.

        Note: length in (offset, length) means _before_ offset
        """
        print " ".join(self.stream[offset:offset+length+1]),


    def dump_locations_with_offset(self, locations, start_offset):
        """
        Dump all sequences with the correct address offsets
        """
        for (c3_offset, length) in locations:
            begin = start_offset + c3_offset - length
            print "0x%08x + %3d:  %s" % (begin, length, Colors.Cyan),
            self.dump_byte_stream(c3_offset-length, length)
            print "%s" % (Colors.Reset)
