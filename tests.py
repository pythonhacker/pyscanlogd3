""" Unit tests """

import timedlist
import entry
import utils
import hasher
import constants

import pickle
import unittest
import time

class TestDataStructures(unittest.TestCase):
    """ Unit tests for all supporting data structures """

    def test_TimedList(self):
        """ Test the TimedList data structure """
        
        l=timedlist.TimedList(maxsize=10,ttl=1.0)
        # Append 5 items
        for i in range(5):
            l.append(i)
            
        self.assertEqual(len(l), 5)            
        # Sleep a bit
        time.sleep(2)
        # No cleanup happened - size is still 5
        self.assertEqual(len(l), 5)
        # Cleanup - all entries should disappear
        l.cleanup()
        self.assertEqual(len(l), 0)
        # Add 10 items
        for i in range(10):
            l.append(i)
        self.assertEqual(len(l), 10)            
        # Add one more item - should fail
        with self.assertRaises(ValueError):
            l.append(11)
        # Sleep a bit - now should be able to append
        time.sleep(2)
        l.append(11)
        # All items would be removed except the last one
        self.assertEqual(len(l), 1)                    
        self.assertTrue(11 in l)
        time.sleep(1)
        # Append one more, no need to clean-up so
        # size would be 2 now
        l.append(12)
        self.assertEqual(len(l), 2)                    
        # Sleep and cleanup
        time.sleep(2)
        l.cleanup()
        # Should be zero now
        self.assertEqual(len(l), 0)        

    def test_EntryLog(self):
        """ Test the EntryLog data structure """

        log = entry.EntryLog(5)
        items = {}
        for i in range(5):
            key = f'key_{i+1}'
            value = entry.ScanEntry(str(hash(i)))
            items[i] = value
            log[key] = value
        self.assertEqual(len(log), 5)
        # Oldest would be the first item
        self.assertEqual(log.oldest, items[0])
        # Last would be most recent
        self.assertEqual(log.last, items[4])

        # Add one more entry
        i+=1
        value = entry.ScanEntry(str(hash(i)))
        log[f'key_{i}'] = value
        # One item would be dropped now
        self.assertEqual(len(log), 5)
        # The deleted would be oldest so it wont
        # be there now
        self.assertFalse(items[0] in log)
        self.assertEqual(log.oldest, items[0])
        # Newes would be the one just added
        self.assertEqual(log.last, value)

    def test_HostHasher(self):
        """ Test the HostHasher data structure """

        src = utils.quad2ip('192.168.1.6')
        dst = utils.quad2ip('142.250.77.110')
        # (src, dst) order should not matter
        h1 = hasher.HostHash(src, dst)
        hash_val1 = hash(h1)
        h2 = hasher.HostHash(dst, src)
        hash_val2 = hash(h2)        
        self.assertEqual(hash_val1, hash_val2)

    def test_utils(self):
        """ Test the utility functions """

        with open('packet.pkl','rb') as f:
            pkt = pickle.load(f)
            self.assertTrue('ip' in pkt.__dict__)
            src,dst,dport,proto,flags = utils.unpack(pkt.ip)
            self.assertEqual(utils.ip2quad(src),'20.204.245.84')
            self.assertEqual(utils.ip2quad(dst),'192.168.1.6')            
            self.assertEqual(dport, 40082)
            self.assertEqual(proto, constants.TCP)
            self.assertEqual(flags, 24)                        
    
if __name__ == "__main__":
    unittest.main()
