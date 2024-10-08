# -- coding: utf-8
""" Module keeping classes related to port-scanning entries """


class ScanEntry(object):
    """ Port scan entry """
    
    def __init__(self, hash):
        self.src = 0
        self.dst = 0
        self.zombie = 0
        self.timestamp = 0
        self.timediffs = []
        # Average of time-stamps
        self.time_avg = 0.0
        # Standard deviation in time-stamps
        self.time_sd = 0.0
        self.logged = False
        self.type = ''
        self.flags = 0
        # Is this a slow scan
        self.slow_scan = False
        # If we are not sure of this scan
        self.maybe = False
        # Is this a duplicate (continuing) scan
        self.duplicate = False
        # SCTP
        self.chunk_type = 0
        self.weight = 0
        self.ports = []
        self.proto = 0
        self.next = None
        self.hash = hash

    def update_time_sd(self):
        """ Update standard deviation of time differences """

        num = float(len(self.timediffs))
        if num>0:
            mean = 1.0*sum(self.timediffs)/num
            sd = pow(sum([pow((x - mean), 2) for x in self.timediffs])/num, 0.5)
            self.time_sd = sd
            self.time_avg = mean

class EntryLog(dict):
    """ Modified dictionary class with fixed size, which
    automatically removes oldest items, for storing port
    scan entry logs """

    def __init__(self, maxsize):
        self.oldest = None
        self.last = None
        self.maxsz = maxsize
        super(EntryLog, self).__init__()

    def __setitem__(self, key, value):
        if not self.__contains__(key) and len(self)==self.maxsz:
            # Remove oldest
            if self.oldest:
                self.__delitem__(self.oldest.hash)
                self.oldest = self.oldest.__next__
        
        super(EntryLog, self).__setitem__(key,value)

        if self.last:
            self.last.next = value
            self.last = value
        else:
            self.last = value
            self.oldest = self.last


class RecentScanEntry(object):
    """ Recent scan entry class, storing
    most recent scan entries """
    
    def __init__(self, scan, is_scan=True):
        self.src = scan.src
        self.dst = scan.dst
        self.zombie = scan.zombie
        self.type = scan.type
        self.flags = scan.flags
        self.ports = scan.ports[:]
        self.timestamp = scan.timestamp
        self.is_scan = is_scan
        # Custom threshold
        self.threshold = 0

    def __eq__(self, entry):
        return ((self.src==entry.src) and (self.dst==entry.dst) and \
                (self.type==entry.type))
    
