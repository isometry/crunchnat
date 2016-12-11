# CrunchNAT
[![Build Status](https://travis-ci.org/isometry/crunchnat.svg?branch=master)](https://travis-ci.org/isometry/crunchnat)

Various algorithms for bijective mapping of internal addresses to
external (address, port list) pairs, with the intent of enabling deterministic
NAT, so eliminating the need to log individual translations.

## Algorithms

### Simple

Ports are allocated in contiguous blocks.

### Stripe

Ports are allocated in non-contiguous blocks, those associated with a given
internal address separated by a constant stripe size.

### Secure

Ports are allocated in non-contiguous blocks, scrambled with a simplistic
RSA-like cryptographic algorithm.

## RFC 7422

These algorithms were developed independently, and prior to the publication of
[RFC 7422](https://tools.ietf.org/html/rfc7422), though similarity is pleasantly
uncanny. Production-worthy implementations welcomed.

## CLI Usage
```
usage: crunchnat.py [-h] [-a {simple,stripe,secure}]
                    external/net internal/net {validate,forward,reverse} ...

Deterministic forward and reverse address translation through the CrunchNAT
algorithm

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
                        algorithm
```
