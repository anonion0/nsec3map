import re
import hashlib

from . import rr
from .. import name
from .. import vis
from .. import util
from ..exception import (
        NSEC3Error,
        InvalidDomainNameError,
        ParseError
    )

SHA1 = 1
SHA1_LENGTH = 20
SHA1_MAX = 2**160-1

def distance_covered(hashed_owner, next_hashed_owner):
    if hashed_owner == next_hashed_owner:
        # empty zone case
        return SHA1_MAX
    return abs(int.from_bytes(next_hashed_owner, "big") -
                int.from_bytes(hashed_owner, "big"))

def covered_by_nsec3_interval(nsec3_hash, hashed_owner, next_hashed_owner):
    if hashed_owner >= next_hashed_owner:
        # this is the last NSEC3 record in a chain
        # this will also catch the empty zone case in which
        # there is a single record with hashed_owner == next_hashed_owner
        return (nsec3_hash >= hashed_owner or nsec3_hash <= next_hashed_owner)
    return (nsec3_hash >= hashed_owner and nsec3_hash <= next_hashed_owner)

class NSEC3(rr.RR):
    def __init__(self, hashed_owner, ttl, cls, algorithm, flags, iterations,
            salt, next_hashed_owner, types):
        super(NSEC3, self).__init__(hashed_owner, ttl, cls)
        self.algorithm = algorithm
        self.flags = flags
        self.iterations = iterations
        self.salt = salt
        self.next_hashed_owner = next_hashed_owner
        self.types = types

    @property
    def owner(self):
        return self.hashed_owner_dn()

    @owner.setter
    def owner(self, hashed_owner):
        try:
            hash_dn, zone = hashed_owner.split(1)
            hashed_owner = util.base32_ext_hex_decode(hash_dn.labels[0].label)
            if len(hashed_owner) != SHA1_LENGTH:
                raise NSEC3Error('NSEC3 RR: invalid hashed_owner length')
            self.hashed_owner = hashed_owner
            self.zone = zone
        except (InvalidDomainNameError, TypeError, IndexError):
            raise NSEC3Error("NSEC3 RR: could not decode hashed owner name")

    @property
    def algorithm(self):
        return self._algorithm

    @algorithm.setter
    def algorithm(self, algorithm):
        if not (algorithm & SHA1):
            raise NSEC3Error('NSEC3 RR: unknown hash function')
        self._algorithm = algorithm

    @property
    def next_hashed_owner(self):
        return self._next_hashed_owner

    @next_hashed_owner.setter
    def next_hashed_owner(self, v):
        if len(v) != SHA1_LENGTH:
            raise NSEC3Error('NSEC3 RR: invalid next_hashed_owner length')
        self._next_hashed_owner = v

    @property
    def iterations(self):
        return self._iterations

    @iterations.setter
    def iterations(self, v):
        if v < 0 or v > 2500:
            raise NSEC3Error("NSEC3 RR: invalid number of iterations")
        self._iterations = v

    def part_of_zone(self, zone):
        return (zone == self.zone)

    def hashed_owner_dn(self):
        hashed_owner = util.base32_ext_hex_encode(self.hashed_owner).lower()
        return name.DomainName(name.Label(hashed_owner),
                                      *self.zone.labels)

    def next_hashed_owner_dn(self):
        next_hashed_owner = util.base32_ext_hex_encode(self.next_hashed_owner).lower()
        return name.DomainName(name.Label(next_hashed_owner),
                                      *self.zone.labels)

    def covers_hash(self, nsec3_hash):
        return covered_by_nsec3_interval(nsec3_hash, self.hashed_owner, self.next_hashed_owner)

    def __str__(self):
        return '\t'.join((super(NSEC3, self).__str__(),
            ' '.join(("NSEC3",
                      str(self.algorithm),
                      str(self.flags),
                      str(self.iterations),
                      (self.salt.hex() if len(self.salt) > 0 else '-'),
                      util.base32_ext_hex_encode(self.next_hashed_owner).lower()
                      .decode())),
            ' '.join(self.types)))

    def distance_covered(self):
        return distance_covered(self.hashed_owner, self.next_hashed_owner)



def compute_hash(owner_name, salt, iterations, algorithm=SHA1):
    # see RFC5155 for details
    if not (algorithm & SHA1):
        raise NSEC3Error('unknown hash function')
    x = owner_name.to_wire()
    i = 0
    while True:
        h = hashlib.sha1()
        h.update(x)
        h.update(salt)
        x = h.digest()
        i += 1
        if i > iterations:
            break
    return h.digest()

def parser():
    p_nsec3 = re.compile(r'^NSEC3\s+([0-9]|[1-9][0-9]*)\s+([0-9]|[1-9][0-9]*)\s+([0-9]|[1-9][0-9]*)\s+([a-fA-F0-9]+|\-)\s+([a-vA-V0-9]+)((\s+[A-Z0-9]+)*)\s*$')
    rr_parse = rr.parser()
    def nsec3_from_text(s):
        try:
            res = rr_parse(s)
            if res is None:
                return None
            owner, ttl, cls, rest = res
            m = p_nsec3.match(rest)
            if m is None:
                return None
            algorithm = int(m.group(1))
            flags = int(m.group(2))
            iterations = int(m.group(3))
            salt  = m.group(4)
            if salt == '-':
                salt = b""
            else:
                salt = bytes.fromhex(m.group(4))
            next_hashed_owner = util.base32_ext_hex_decode(m.group(5))
            types = m.group(6).strip()
            if not types.isprintable():
                raise ValueError
            types = types.split(' ')
        except (TypeError, ValueError):
            raise ParseError
        return NSEC3(owner, ttl, cls, algorithm, flags, iterations, salt, next_hashed_owner, types)
    return nsec3_from_text

