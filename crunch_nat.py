from __future__ import division
from __future__ import print_function
import netaddr

_DEFAULT_ALGO = 'secure'
_MAX_CRUNCH_FACTOR = 8

# Basic parameters for 'secure' algo.
# Product P*Q must be <= (_PORTS_PER_IP - _RESERVED_PORTS)
# 251 * 257 = 64511
_DEFAULT_P = 251
_DEFAULT_Q = 257
_DEFAULT_E = 19

# Various semi-fixed parameters
_PORTS_PER_IP   = 65536
_RESERVED_PORTS = 1024
_USABLE_PORTS   = _PORTS_PER_IP - _RESERVED_PORTS

class CrunchNAT(object):
    """
    Crunch Network Address Translation
    Bijective mapping of internal addresses to external (address, port list) pairs, facilitating log-less IPv4 NAT.
    """
    
    def __init__(self, external_network, internal_network, algo='secure', p=_DEFAULT_P, q=_DEFAULT_Q, e=_DEFAULT_E):
        self.external_network = netaddr.IPNetwork(external_network)
        self.internal_network = netaddr.IPNetwork(internal_network)
        self.crunch_factor    = self.external_network.prefixlen - self.internal_network.prefixlen

        if self.crunch_factor > _MAX_CRUNCH_FACTOR:
            raise Exception('Excessive Crunch Factor: {}'.format(self.crunch_factor))

        if self.external_network.prefixlen < 31:
            self.external_hosts = self.external_network.size - 2
        else:
            self.external_hosts = self.external_network.size

        self.algo      = algo
        self.forward   = getattr(self, '{}_forward'.format(algo))
        self.reverse   = getattr(self, '{}_reverse'.format(algo))

        if algo == 'secure':
            if p * q > _USABLE_PORTS:
                raise Exception('Invalid keys: p*q > _USABLE_PORTS')
            (self.encrypt, self.decrypt) = gen_rsa_methods(p, q, e)
            self.num_ports = p * q
        else:
            self.num_ports = _USABLE_PORTS

    @property
    def naive_ports_per_host(self):
        return _PORTS_PER_IP >> self.crunch_factor

    def naive_forward(self, _internal_address):
        """ Naively forward map internal address to external (address, portrange) """
        internal_address = netaddr.IPAddress(_internal_address)
        internal_offset  = int(internal_address) - int(self.internal_network.value)
        external_offset  = internal_offset >> self.crunch_factor
        external_address = netaddr.IPAddress(int(self.external_network.value) + external_offset)
        lo_port          = self.naive_ports_per_host * (internal_offset % 2**self.crunch_factor)
        hi_port          = lo_port + self.naive_ports_per_host
        return (external_address, range(lo_port, hi_port))

    def naive_reverse(self, _external_address, _port):
        """ Naively reverse map external (address, port) to internal address """
        external_address = netaddr.IPAddress(_external_address)
        external_offset  = int(external_address) - int(self.external_network.value)
        internal_offset1 = external_offset << self.crunch_factor
        internal_offset2 = _port // self.naive_ports_per_host
        internal_address = netaddr.IPAddress(int(self.internal_network.value) + internal_offset1 + internal_offset2)
        return internal_address

    @property
    def hosts_per_external(self):
        """ Number of internal hosts per external IP """
        return (self.internal_network.size // self.external_hosts) + 1

    @property
    def ports_per_host(self):
        """ Number of external ports per internal host """
        return (self.num_ports // self.hosts_per_external)

    def simple_forward(self, _internal_address):
        """ Forward map internal address to external (address, portrange), with no obfuscation algorithm """
        internal_address = netaddr.IPAddress(_internal_address)
        internal_offset  = int(internal_address) - int(self.internal_network.value)
        external_offset  = 1 + (internal_offset // self.hosts_per_external)
        external_address = netaddr.IPAddress(int(self.external_network.value) + external_offset)
        lo_port = _RESERVED_PORTS + self.ports_per_host * (internal_offset % self.hosts_per_external)
        hi_port = lo_port + self.ports_per_host
        return (external_address, range(lo_port, hi_port))

    def simple_reverse(self, _external_address, _port):
        """ Reverse map external (address, port) to internal address, the port having not been obfuscated """
        external_address = netaddr.IPAddress(_external_address)
        external_offset  = int(external_address) - int(self.external_network.value)
        internal_offset1 = (external_offset - 1) * self.hosts_per_external
        internal_offset2 = ((_port - _RESERVED_PORTS) // self.ports_per_host)
        internal_address = netaddr.IPAddress(int(self.internal_network.value) + internal_offset1 + internal_offset2)
        return internal_address

    def stripe_forward(self, _internal_address):
        """ Forward map internal address to external (address, portrange), obfuscating portrange with fixed-width striping algorithm """
        internal_address = netaddr.IPAddress(_internal_address)
        internal_offset  = int(internal_address) - int(self.internal_network.value)
        external_offset  = 1 + (internal_offset // self.hosts_per_external)
        external_address = netaddr.IPAddress(int(self.external_network.value) + external_offset)
        port_range  = range(_RESERVED_PORTS + (internal_offset % self.hosts_per_external), _PORTS_PER_IP, self.hosts_per_external)[:self.ports_per_host]
        return (external_address, port_range)

    def stripe_reverse(self, _external_address, _port):
        """ Reverse map external (address, port) to internal address, the port having been obfuscated with fixed-width striping algorithm """
        external_address = netaddr.IPAddress(_external_address)
        external_offset  = int(external_address) - int(self.external_network.value)
        internal_offset1 = (external_offset - 1) * self.hosts_per_external
        internal_offset2 = (_port - _RESERVED_PORTS) % self.hosts_per_external
        internal_address = netaddr.IPAddress(int(self.internal_network.value) + internal_offset1 + internal_offset2)
        return internal_address

    def secure_forward(self, _internal_address):
        """ Forward map internal address to external (address, portrange), obfuscating portrange with RSA-based algorithm """
        internal_address = netaddr.IPAddress(_internal_address)
        internal_offset  = int(internal_address) - int(self.internal_network.value)
        external_offset  = 1 + (internal_offset // self.hosts_per_external)
        external_address = netaddr.IPAddress(int(self.external_network.value) + external_offset)
        port_offset      = internal_offset % self.hosts_per_external
        fn = lambda x: _RESERVED_PORTS + self.encrypt(x)
        port_range = sorted(map(fn, range(port_offset * self.ports_per_host, (port_offset + 1) * self.ports_per_host)))
        return (external_address, port_range)

    def secure_reverse(self, _external_address, _port):
        """ Reverse map external (address, port) to internal address, the port having been obfuscated with RSA-based algorithm """
        external_address = netaddr.IPAddress(_external_address)
        external_offset  = int(external_address) - int(self.external_network.value)
        internal_offset1 = (external_offset - 1) * self.hosts_per_external
        internal_offset2 = self.decrypt(_port - _RESERVED_PORTS) // self.ports_per_host
        internal_address = netaddr.IPAddress(int(self.internal_network.value) + internal_offset1 + internal_offset2)
        return internal_address

    # Various helper functions to check that mappings are sane
    
    def check_forward_collisions(self):
        """ Confirm that port mappings for the first hosts_per_external hosts do not overlap """
        collisions = []
        z = set()
        for x in range(0, self.hosts_per_external):
            i = netaddr.IPAddress(int(self.internal_network.value) + x)
            (e, p) = self.forward(i)
            if len(p) != self.ports_per_host:
                print('Port range for {} is wrong size: {}'.format(i, len(p)))
            if z.intersection(p):
                collisions.append(str(i))
            z.update(p)
        print('{} collisions {}'.format(len(collisions), ', '.join(collisions)))

    def check_bijection(self, count=None):
        """ Confirm that the mapping is bijective for the first (count) internal hosts """
        bijective = True
        if not count:
            count = self.hosts_per_external
        for x in range(0, count):
            i = netaddr.IPAddress(int(self.internal_network.value) + x)
            (e, p) = self.forward(int(self.internal_network.value) + x)
            for q in p:
                if self.reverse(e, q) != i:
                    bijective = False
        return bijective

    def count_strides(self, _internal_address):
        """ Return a dictionary of stride length:count within the portrange calculated for a given internal address """
        (e, p) = self.forward(_internal_address)
        lengths = {}
        for x in range(0, self.ports_per_host - 1):
            d = p[x + 1] - p[x]
            if d in lengths:
                lengths[d] += 1
            else:
                lengths[d] = 1
        return lengths
        
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def gen_rsa_methods(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    encrypt = lambda x: pow(x, e, n)
    decrypt = lambda x: pow(x, d, n)
    return (encrypt, decrypt)
