# CrunchNAT

Proof-of-concept algorithms for bijective mapping of internal addresses to
external (address, port list) pairs, with the intent of enabling source NAT
without the need to log translations.

Developed independently, and prior to the publication of
[RFC 7422](https://tools.ietf.org/html/rfc7422), though similarity is pleasantly
uncanny. Production-worthy implementations welcomed.

## CLI Usage
```
usage: crunchnat.py [-h] [-a {simple,stripe,secure}]
                    external/net internal/net {validate,forward,reverse} ...

Forward and reverse mapping of ip:port tuples through CrunchNAT algorithm

positional arguments:
  external/net          external or public network
  internal/net          internal or private network
  {validate,forward,reverse}
    validate            validate algorithm with provided external/internal
                        networks
    forward             map internal address to external address: [port list]
    reverse             map external address:port to internal address

optional arguments:
  -h, --help            show this help message and exit
  -a {simple,stripe,secure}, --algo {simple,stripe,secure}
                        CrunchNAT algorithm
```
