import re

from .. import name
from ..exception import ParseError

class RR(object):
    """General resource record"""
    def __init__(self, owner, ttl, cls):
        self.owner = owner
        self.ttl = ttl
        self.cls = cls

    def __str__(self):
        return '\t'.join((str(self.owner), str(self.ttl), self.cls))


def parser():
    """Returns a parser for a general resource record"""
    p = re.compile(r'^(([a-zA-Z0-9\\_*-]+\.)+|\.)\s+([0-9]|[1-9][0-9]*)\s+IN\s+(.*)$')
    def rr_from_text(s):
        m = p.match(s)
        try:
            if m is None:
                return None
            else:
                # owner, tt, class, rest
                owner = name.unvis_domainname(m.group(1).encode("ascii"))
                return owner, int(m.group(3)), 'IN', m.group(4)
        except ValueError:
            raise ParseError
    return rr_from_text
