import re

from . import rr
from .. import name
from .. import vis
from ..exception import NSECError, ParseError

class NSEC(rr.RR):
    def __init__(self, owner, ttl, cls, next_owner, types):
        super(NSEC, self).__init__(owner, ttl, cls)
        self.next_owner = next_owner
        self.types = types
        self.sanity_check()
    
    def sanity_check(self):
        if self.owner == self.next_owner:
            raise NSECError('invalid NSEC record, owner == next_owner')

    def covers(self, dname):
        return dname.covered_by(self.owner, self.next_owner)

    def part_of_zone(self, zone):
        return (self.owner.part_of_zone(zone) and
                self.next_owner.part_of_zone(zone))
    
    def __str__(self):
        return '\t'.join((super(NSEC, self).__str__(), "NSEC", str(self.next_owner), ' '.join(self.types)))

def parser():
    p_nsec = re.compile(r'^NSEC\s+(([a-zA-Z0-9\\_-]+\.|\.)+)((\s+[A-Z0-9]+)*)\s*$')
    rr_parse = rr.parser()
    def nsec_from_text(s):
        try:
            res = rr_parse(s)
            if res is None:
                return None
            owner, ttl, cls, rest = res
            m = p_nsec.match(rest)
            if m is None:
                return None
            next_owner = name.unvis_domainname(m.group(1))
            types = list(map(vis.strvis, m.group(3).strip().split(' ')))
        except ValueError:
                raise ParseError
        return NSEC(owner, ttl, cls, next_owner, types)
    return nsec_from_text
