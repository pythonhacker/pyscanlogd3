# -- coding: utf-8
""" Module with class that manages hashing for src and dst addresses """

class HostHash:
    """ Class managing hashing for host addresses """

    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        
    def perform_hash(self, addr):
        """ Hash a host address """
        
        value = addr
        h = 0
    
        while value:
            # print value
            h ^= value
            value = value >> 9
        
        return h & (8192-1)

    def mix(self, a, b, c):
        """ Hash mixing function """
        
        a -= b; a -= c; a ^= (c>>13)
        b -= c; b -= a; b ^= (a<<8) 
        c -= a; c -= b; c ^= (b>>13)
        a -= b; a -= c; a ^= (c>>12)
        b -= c; b -= a; b ^= (a<<16)
        c -= a; c -= b; c ^= (b>>5) 
        a -= b; a -= c; a ^= (c>>3)
        b -= c; b -= a; b ^= (a<<10)
        c -= a; c -= b; c ^= (b>>15)
        
        return abs(c)
  
    def __hash__(self):
        """ Return the hash """

        return self.perform_hash(self.mix(self.src, self.dst, 0xffffff))

