#!/usr/bin/env python3

"""
CrunchNAT
(c) Robin Breathe, 2013

Bijective mapping of internal addresses to external (address, port list) pairs,
facilitating log-free Source NAT.
"""

from __future__ import division, print_function
from argparse import ArgumentParser
from ipaddress import ip_address, ip_network

DEFAULT_ALGO = 'secure'
MAX_CRUNCH_FACTOR = 8

# Basic parameters for 'secure' algo.
# Product P*Q must be <= (PORTS_PER_IP - RESERVED_PORTS)
# 251 * 257 = 64511
DEFAULT_P = 251
DEFAULT_Q = 257
DEFAULT_E = 19

# Constants
PORTS_PER_IP = 65536
RESERVED_PORTS = 1024
USABLE_PORTS = PORTS_PER_IP - RESERVED_PORTS

class CrunchNAT(object):
    """
    Crunch Network Address Translation
    Bijective mapping of internal addresses to external (address, port list)
    pairs, facilitating log-less IPv4 NAT.
    """

    def __init__(self, external_network, internal_network, algo=DEFAULT_ALGO,
                 p=DEFAULT_P, q=DEFAULT_Q, e=DEFAULT_E):
        self.external_network = ip_network(external_network)
        self.internal_network = ip_network(internal_network)
        self.crunch_factor = (self.external_network.prefixlen
                              - self.internal_network.prefixlen)

        if self.crunch_factor > MAX_CRUNCH_FACTOR:
            raise Exception('Excessive Crunch Factor: {}'
                            .format(self.crunch_factor))

        self.algo = algo
        self.forward = getattr(self, '{}_forward'.format(algo))
        self.reverse = getattr(self, '{}_reverse'.format(algo))

        if algo == 'secure':
            if p * q > USABLE_PORTS:
                raise Exception('Invalid keys: p*q > USABLE_PORTS')
            (self.encrypt, self.decrypt) = gen_rsa_methods(p, q, e)
            self.num_ports = p * q
        else:
            self.num_ports = USABLE_PORTS

    @property
    def hosts_per_external(self):
        """ Number of internal hosts per external IP """
        return (self.internal_network.num_addresses
                // self.external_network.num_addresses)

    @property
    def ports_per_host(self):
        """ Number of external ports per internal host """
        return self.num_ports // self.hosts_per_external

    def simple_forward(self, internal_address):
        """
        Forward map internal address to external (address, portrange), with no
        obfuscation algorithm
        """
        internal_address = ip_address(internal_address)
        internal_offset = (int(internal_address)
                           - int(self.internal_network.network_address))
        external_offset = internal_offset // self.hosts_per_external
        external_address = self.external_network[external_offset]
        lo_port = (RESERVED_PORTS
                   + self.ports_per_host * (internal_offset
                                            % self.hosts_per_external))
        hi_port = lo_port + self.ports_per_host
        return (external_address, range(lo_port, hi_port))

    def simple_reverse(self, external_address, port):
        """
        Reverse map external (address, port) to internal address, the port
        having not been obfuscated
        """
        external_address = ip_address(external_address)
        external_offset = (int(external_address)
                           - int(self.external_network.network_address))
        internal_offset1 = external_offset * self.hosts_per_external
        internal_offset2 = (port - RESERVED_PORTS) // self.ports_per_host
        internal_address = self.internal_network[internal_offset1 +
                                                 internal_offset2]
        return internal_address

    def stripe_forward(self, internal_address):
        """
        Forward map internal address to external (address, portrange),
        obfuscating portrange with fixed-width striping algorithm
        """
        internal_address = ip_address(internal_address)
        internal_offset = (int(internal_address)
                           - int(self.internal_network.network_address))
        external_offset = internal_offset // self.hosts_per_external
        external_address = self.external_network[external_offset]
        ports = range(RESERVED_PORTS
                      + (internal_offset % self.hosts_per_external),
                      PORTS_PER_IP,
                      self.hosts_per_external)[:self.ports_per_host]
        return (external_address, ports)

    def stripe_reverse(self, external_address, port):
        """
        Reverse map external (address, port) to internal address, the port
        having been obfuscated with fixed-width striping algorithm
        """
        external_address = ip_address(external_address)
        external_offset = (int(external_address)
                           - int(self.external_network.network_address))
        internal_offset1 = external_offset * self.hosts_per_external
        internal_offset2 = (port - RESERVED_PORTS) % self.hosts_per_external
        internal_address = self.internal_network[internal_offset1 +
                                                 internal_offset2]
        return internal_address

    def secure_forward(self, internal_address):
        """
        Forward map internal address to external (address, portrange),
        obfuscating portrange with RSA-based algorithm
        """
        internal_address = ip_address(internal_address)
        internal_offset = (int(internal_address)
                           - int(self.internal_network.network_address))
        external_offset = internal_offset // self.hosts_per_external
        external_address = self.external_network[external_offset]
        port_offset = internal_offset % self.hosts_per_external
        func = lambda x: RESERVED_PORTS + self.encrypt(x)
        ports = sorted(map(func,
                           range(port_offset * self.ports_per_host,
                                 (port_offset + 1) * self.ports_per_host)))
        return (external_address, ports)

    def secure_reverse(self, external_address, port):
        """
        Reverse map external (address, port) to internal address, the port
        having been obfuscated with RSA-based algorithm
        """
        external_address = ip_address(external_address)
        external_offset = (int(external_address)
                           - int(self.external_network.network_address))
        internal_offset1 = external_offset * self.hosts_per_external
        internal_offset2 = (self.decrypt(port - RESERVED_PORTS)
                            // self.ports_per_host)
        internal_address = self.internal_network[internal_offset1 +
                                                 internal_offset2]
        return internal_address

    # Various helper functions to check that mappings are sane

    def check_forward_collisions(self):
        """
        Confirm that port mappings for the first hosts_per_external hosts do not
        overlap
        """
        collisions = []
        all_ports = set()
        for offset in range(0, self.hosts_per_external):
            internal_address = self.internal_network[offset]
            ports = self.forward(internal_address)[1]
            if len(ports) != self.ports_per_host:
                print('Port range for {} is wrong size: {}'
                      .format(internal_address, len(ports)))
            if all_ports.intersection(ports):
                collisions.append(str(internal_address))
            all_ports.update(ports)
        return collisions

    def check_bijection(self, count=None):
        """
        Confirm that the mapping is bijective for the first (count) internal
        hosts
        """
        bijective = True
        if not count:
            count = self.hosts_per_external
        for offset in range(0, count):
            internal_address = self.internal_network[offset]
            (external_address, ports) = self.forward(internal_address)
            for port in ports:
                if self.reverse(external_address, port) != internal_address:
                    bijective = False
        return bijective

    def count_strides(self, internal_address):
        """
        Return a dictionary of stride length:count within the portrange
        calculated for a given internal address
        """
        ports = self.forward(internal_address)[1]
        strides = {}
        for offset in range(0, self.ports_per_host - 1):
            length = ports[offset + 1] - ports[offset]
            if length in strides:
                strides[length] += 1
            else:
                strides[length] = 1
        return strides

def egcd(a, b):
    """ Calculate extended greatest common divisor """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """ Calculate modular inverse """
    g, x = egcd(a, m)[:2]
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def gen_rsa_methods(p, q, e):
    """ Generate RSA encrypt/decrypt methods """
    n = p * q
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    encrypt = lambda x: pow(x, e, n)
    decrypt = lambda x: pow(x, d, n)
    return (encrypt, decrypt)

def main():
    """ Utility mode """
    parser = ArgumentParser(description="Forward and reverse mapping of ip:port"
                                        "tuples through CrunchNAT algorithm")
    parser.add_argument('-a', '--algo', action='store', default=DEFAULT_ALGO,
                        choices=('simple', 'stripe', 'secure'),
                        help='CrunchNAT algorithm')

    parser.add_argument('external', metavar='external/net', action='store',
                        help='external or public network')
    parser.add_argument('internal', metavar='internal/net', action='store',
                        help='internal or private network')

    subparsers = parser.add_subparsers(dest='subparser')

    subparsers.add_parser('validate',
                          help="validate algorithm with provided"
                               "external/internal networks")

    p_forward = subparsers.add_parser('forward',
                                      help="map internal address to external"
                                           "address: [port list]")
    p_forward.add_argument('address', action='store')

    p_reverse = subparsers.add_parser('reverse',
                                      help="map external address:port to"
                                           "internal address")
    p_reverse.add_argument('address_port', metavar='address:port',
                           action='store')

    args = parser.parse_args()

    crunch = CrunchNAT(args.external, args.internal, algo=args.algo)

    if args.subparser is None:
        print('Hosts per external: {}'.format(crunch.hosts_per_external))
        print('Ports per host: {}'.format(crunch.ports_per_host))
    elif args.subparser == 'validate':
        print('Forward collisions: {}'.format(
            crunch.check_forward_collisions() or None))
        print('Bijective: {}'.format(crunch.check_bijection()))
    elif args.subparser == 'forward':
        print('{}: {}'.format(*crunch.forward(args.address)))
    elif args.subparser == 'reverse':
        (address, port) = args.address_port.split(':')
        port = int(port)
        print('{}'.format(crunch.reverse(address, port)))

if __name__ == '__main__':
    main()
