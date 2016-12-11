import unittest

from ipaddress import ip_address
from crunchnat import CrunchNAT

class TestSimpleCrunchNAT(unittest.TestCase):
    def setUp(self):
        self.crunch = CrunchNAT('192.0.2.0/24', '10.0.0.0/16', algo='simple')
    
    def test_forward_collisions(self):
        self.assertEqual(self.crunch.check_forward_collisions(), [])
    
    def test_bijective(self):
        self.assertTrue(self.crunch.check_bijection(512))
    
    def test_hosts_per_external(self):
        self.assertEqual(self.crunch.hosts_per_external, 2**(24-16))
    
    def test_ports_per_host(self):
        self.assertEqual(self.crunch.ports_per_host,
                         (2**16-2**10)//2**(24-16))
    
    def test_forward(self):
        forward = self.crunch.forward('10.0.0.10')
        self.assertEqual(forward,
                         (ip_address('192.0.2.0'), range(3544, 3796)))
        self.assertEqual(len(forward[1]), self.crunch.ports_per_host)

    def test_reverse(self):
        self.assertEqual(self.crunch.reverse('192.0.2.0', 3600),
                         ip_address('10.0.0.10'))

class TestStripeCrunchNAT(unittest.TestCase):
    def setUp(self):
        self.crunch = CrunchNAT('192.0.2.0/24', '10.0.0.0/16', algo='stripe')
    
    def test_forward_collisions(self):
        self.assertEqual(self.crunch.check_forward_collisions(), [])
    
    def test_bijective(self):
        self.assertTrue(self.crunch.check_bijection(512))
    
    def test_hosts_per_external(self):
        self.assertEqual(self.crunch.hosts_per_external, 2**(24-16))
    
    def test_ports_per_host(self):
        self.assertEqual(self.crunch.ports_per_host,
                         (2**16-2**10)//2**(24-16))
    
    def test_forward(self):
        forward = self.crunch.forward('10.0.0.10')
        self.assertEqual(forward,
                         (ip_address('192.0.2.0'), range(1034, 65546, 256)))
        self.assertEqual(len(forward[1]), self.crunch.ports_per_host)

    def test_reverse(self):
        self.assertEqual(self.crunch.reverse('192.0.2.0', 1290),
                         ip_address('10.0.0.10'))

class TestSecureCrunchNAT(unittest.TestCase):
    def setUp(self):
        self.crunch = CrunchNAT('192.0.2.0/24', '10.0.0.0/16', algo='secure')
    
    def test_forward_collisions(self):
        self.assertEqual(self.crunch.check_forward_collisions(), [])
    
    def test_bijective(self):
        self.assertTrue(self.crunch.check_bijection(512))
    
    def test_hosts_per_external(self):
        self.assertEqual(self.crunch.hosts_per_external, 2**(24-16))
    
    def test_ports_per_host(self):
        self.assertEqual(self.crunch.ports_per_host, 251*257//2**(24-16))
    
    def test_forward(self):
        forward = self.crunch.forward('10.0.0.10')
        self.assertEqual(len(forward[1]), self.crunch.ports_per_host)

    def test_reverse(self):
        self.assertEqual(self.crunch.reverse('192.0.2.0', 2318),
                         ip_address('10.0.0.10'))

if __name__ == '__main__':
    unittest.main()
