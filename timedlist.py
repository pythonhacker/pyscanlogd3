# -- coding: utf-8
import time

class TimedList(list):
    """ List class of fixed size with entries that time out automatically """

    def __getattribute__(self, name):
        if name in ('insert','pop','extend'):
            # We dont want to support these as they are mutation methods
            raise NotImplementedError
        else:
            return super(TimedList, self).__getattribute__(name)
        
    def __init__(self, maxsz, ttl):
        # Maximum size
        self.maxsz = maxsz
        # Time to live for each entry
        self.ttl = ttl

    def append(self, item):
        """ Append an item to end """

        # The actual item we are appending is
        # the original item with a timestamp
        timestamp_item = (time.time(), item)
        if len(self)<self.maxsz:
            super(TimedList, self).append(timestamp_item)
        else:
            n=self.__collect()
            if n:
                # Some items removed, so append
                super(TimedList, self).append(timestamp_item)
            else:
                raise ValueError('could not append item')

    def cleanup(self):
        """ Clean up old items """
        return self.__collect()
    
    def __collect(self):
        """ Collect and remove aged items """

        # Current timestamp
        t=time.time()
        old = []
        for item in self:
            # timed out items
            if (t-item[0])>self.ttl:
                old.append(item)
        
        for item in old:
            self.remove(item)

        return len(old)

    def __getitem__(self, index):
        """ Overridden __getitem___ """
        
        item = super(TimedList, self).__getitem__(index)
        if type(index) is slice:
            return [i[1] for i in item]
        else:
            return item[1]
        
    def __setitem__(self,  index, item):
        # Allow only tuples with time-stamps >= current time-stamp as 1st member
        cond = type(item) == tuple and len(item) == 2  and type(item[0]) == float and item[0]>=time.time()
        if cond:
            super(TimedList, self).__setitem__(index, item)
        else:
            raise TypeError('invalid entry')

    def __contains__(self, item):
        """ Check if item exists """
        items = [rest for (tstamp,rest) in self]
        return item in items
