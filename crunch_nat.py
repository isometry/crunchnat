import ipaddr

_PORTS_PER_IP=65536
_RESERVED_PORTS=1024
_USABLE_PORTS=_PORTS_PER_IP - _RESERVED_PORTS
_MAX_CRUNCH_FACTOR=8

_PUBLIC_KEY=64373
_DEFAULT_PRIVATE_KEY=130969

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

class CrunchNAT(object):
    def __init__(self, external_network, internal_network, algo='stripe', private_key=_DEFAULT_PRIVATE_KEY):
        self.external_network = ipaddr.IPv4Network(external_network)
        self.internal_network = ipaddr.IPv4Network(internal_network)
        self.crunch_factor    = self.external_network.prefixlen - self.internal_network.prefixlen
        if self.crunch_factor > _MAX_CRUNCH_FACTOR:
            raise Exception('Excessive Crunch Factor: {}'.format(self.crunch_factor))
        if (private_key <= _PUBLIC_KEY):
            raise Exception('Bad key: {}'.format(private_key))
        self.forward   = getattr(self, '{}_forward'.format(algo))
        self.reverse   = getattr(self, '{}_reverse'.format(algo))
        self.prime_key = _PUBLIC_KEY * private_key
        self.prime_inv = modinv(self.prime_key, _USABLE_PORTS)

    @property
    def naive_ports_per_host(self):
        return _PORTS_PER_IP >> self.crunch_factor

    def naive_forward(self, _internal_address):
        internal_address = ipaddr.IPv4Address(_internal_address)
        internal_offset  = int(internal_address) - int(self.internal_network)
        external_offset  = internal_offset >> self.crunch_factor
        external_address = ipaddr.IPv4Address(int(self.external_network) + external_offset)
        lo_port          = self.naive_ports_per_host * (internal_offset % 2**self.crunch_factor)
        hi_port          = lo_port + self.naive_ports_per_host - 1
        return (external_address, (lo_port, hi_port))

    def naive_reverse(self, _external_address, _port):
        external_address = ipaddr.IPv4Address(_external_address)
        external_offset  = int(external_address) - int(self.external_network)
        internal_offset1 = external_offset << self.crunch_factor
        internal_offset2 = int(_port / self.naive_ports_per_host)
        internal_address = ipaddr.IPv4Address(int(self.internal_network) + internal_offset1 + internal_offset2)
        return internal_address

    @property
    def external_numhosts(self):
        """ Number of usable external IPs """
        return self.external_network.numhosts - 2

    @property
    def hosts_per_external(self):
        """ Number of internal hosts per external IP """
        return int(self.internal_network.numhosts / self.external_numhosts) + 1

    @property
    def ports_per_host(self):
        """ Number of external ports per internal host """
        return int(_USABLE_PORTS / self.hosts_per_external)

    def simple_forward(self, _internal_address):
        internal_address = ipaddr.IPv4Address(_internal_address)
        internal_offset  = int(internal_address) - int(self.internal_network)
        external_offset  = 1 + int(internal_offset / self.hosts_per_external)
        external_address = ipaddr.IPv4Address(int(self.external_network) + external_offset)
        lo_port = _RESERVED_PORTS + self.ports_per_host * (internal_offset % self.hosts_per_external)
        hi_port = lo_port + self.ports_per_host - 1
        return (external_address, (lo_port, hi_port))

    def simple_reverse(self, _external_address, _port):
        external_address = ipaddr.IPv4Address(_external_address)
        external_offset  = int(external_address) - int(self.external_network)
        internal_offset1 = (external_offset - 1) * self.hosts_per_external
        internal_offset2 = (_port - _RESERVED_PORTS) / self.ports_per_host
        internal_address = ipaddr.IPv4Address(int(self.internal_network) + internal_offset1 + internal_offset2)
        return internal_address

    def stripe_forward(self, _internal_address):
        internal_address = ipaddr.IPv4Address(_internal_address)
        internal_offset  = int(internal_address) - int(self.internal_network)
        external_offset  = 1 + int(internal_offset / self.hosts_per_external)
        external_address = ipaddr.IPv4Address(int(self.external_network) + external_offset)
        port_range = range(_RESERVED_PORTS + (internal_offset % self.hosts_per_external), _PORTS_PER_IP, self.hosts_per_external)[:self.ports_per_host]
        return (external_address, port_range)

    def stripe_reverse(self, _external_address, _port):
        external_address = ipaddr.IPv4Address(_external_address)
        external_offset  = int(external_address) - int(self.external_network)
        internal_offset1 = (external_offset - 1) * self.hosts_per_external
        internal_offset2 = (_port - _RESERVED_PORTS) % self.hosts_per_external
        internal_address = ipaddr.IPv4Address(int(self.internal_network) + internal_offset1 + internal_offset2)
        return internal_address

    def prime_forward(self, _internal_address):
        internal_address = ipaddr.IPv4Address(_internal_address)
        internal_offset  = int(internal_address) - int(self.internal_network)
        external_offset  = 1 + int(internal_offset / self.hosts_per_external)
        external_address = ipaddr.IPv4Address(int(self.external_network) + external_offset)
        modp = lambda x: _RESERVED_PORTS + ((x * self.prime_key) % _USABLE_PORTS)
        port_offset = internal_offset * self.ports_per_host
        port_range = sorted(map(modp, range(port_offset, port_offset + self.ports_per_host)))
        return (external_address, port_range)

    def prime_reverse(self, _external_address, _port):
        external_address = ipaddr.IPv4Address(_external_address)
        external_offset  = int(external_address) - int(self.external_network)
        internal_offset1 = (external_offset - 1) * self.hosts_per_external
        internal_offset2 = ((_port - _RESERVED_PORTS) * self.prime_inv % _USABLE_PORTS) / self.ports_per_host
        internal_address = ipaddr.IPv4Address(int(self.internal_network) + internal_offset1 + internal_offset2)
        return internal_address
