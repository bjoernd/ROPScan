from bdutil import Colors
import scriptine

class Section:
    def __init__(self, name, start, size):
        self.name = name
        self.start = int(start,16)
        self.size = int(size,16)

    def dump(self):
        print "Section %s%s%s @ %08x - %08x" % (Colors.Green, self.name,
                                                Colors.Reset, self.start,
                                                self.start + self.size)
