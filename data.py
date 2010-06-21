"""
Data used by ROPCheck
"""

from bdutil import Colors

class Section:
    """
    Represents a binary section
    """
    def __init__(self, name, start, size):
        self.__name = name
        self.__start = int(start, 16)
        self.__size = int(size, 16)

    def dump(self):
        """
        Dump section
        """
        print "Section %s%s%s @ %08x - %08x" % (Colors.Green, self.__name,
                                                Colors.Reset, self.__start,
                                                self.__start + self.__size)

    @property
    def name(self):
        """Section name"""
        return self.__name

    @property
    def start(self):
        """Section start address"""
        return self.__start

    @property
    def size(self):
        """Section size"""
        return self.__size


    @property
    def end(self):
        """Last address within section"""
        return self.__start + self.__size -1
