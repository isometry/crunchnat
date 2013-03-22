import ipaddr

_PORTS_PER_IP=65536
_RESERVED_PORTS=1024
_MAX_CRUNCH_FACTOR=8

class CrunchError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return 'Excessive Crunch Factor: {}'.format(repr(self.value))


class CrunchNAT(object):
    def __init__(self, public_network, private_network):
        self.public_network = ipaddr.IPv4Network(public_network)
        self.private_network = ipaddr.IPv4Network(private_network)
        self.crunch_factor = self.public_network.prefixlen - self.private_network.prefixlen
        if self.crunch_factor > _MAX_CRUNCH_FACTOR:
            raise CrunchError(self.crunch_factor)
    
    @property
    def dumb_ports_per_host(self):
        return _PORTS_PER_IP >> self.crunch_factor

    def dumb_pvt2pub(self, _private_address):
        private_address = ipaddr.IPv4Address(_private_address)
        private_offset  = int(private_address) - int(self.private_network)
        public_offset   = private_offset >> self.crunch_factor
        public_address  = ipaddr.IPv4Address(int(self.public_network) + public_offset)
        lo_port         = self.dumb_ports_per_host * (private_offset % 2**self.crunch_factor)
        hi_port         = lo_port + self.dumb_ports_per_host - 1
        return (public_address, (lo_port, hi_port))

    def dumb_pub2pvt(self, _public_address, _port):
        public_address  = ipaddr.IPv4Address(_public_address)
        public_offset   = int(public_address) - int(self.public_network)
        private_offset1 = public_offset << self.crunch_factor
        private_offset2 = int(_port / self.dumb_ports_per_host)
        private_address = ipaddr.IPv4Address(int(self.private_network) + private_offset1 + private_offset2)
        return private_address
    
    @property
    def public_numhosts(self):
        """ Number of usable public IPs """
        return self.public_network.numhosts - 2
    
    @property
    def hosts_per_pub(self):
        """ Number of private hosts per public IP """
        return int(self.private_network.numhosts / self.public_numhosts)
    
    @property
    def ports_per_host(self):
        """ Number of public ports per private host """
        total_ports = self.public_numhosts * (_PORTS_PER_IP - _RESERVED_PORTS)
        return int(total_ports / self.private_network.numhosts)

    def pvt2pub(self, _private_address):
        private_address = ipaddr.IPv4Address(_private_address)
        private_offset  = int(private_address) - int(self.private_network)
        public_offset   = 1 + int(private_offset / self.hosts_per_pub)
        public_address  = ipaddr.IPv4Address(int(self.public_network) + public_offset)
        lo_port         = _RESERVED_PORTS + self.ports_per_host * (private_offset % self.hosts_per_pub)
        hi_port         = lo_port + self.ports_per_host - 1
        return (public_address, (lo_port, hi_port))

    def pub2pvt(self, _public_address, _port):
        public_address  = ipaddr.IPv4Address(_public_address)
        public_offset   = int(public_address) - int(self.public_network)
        private_offset1 = int((public_offset - 1) * self.hosts_per_pub)
        private_offset2 = int((_port - _RESERVED_PORTS) / self.ports_per_host)
        private_address = ipaddr.IPv4Address(int(self.private_network) + private_offset1 + private_offset2)
        return private_address
