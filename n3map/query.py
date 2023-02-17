import struct

import dns.resolver
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.flags

from . import name
from .rrtypes import nsec3
from .rrtypes import nsec
from . import rrtypes
from . import exception
from . import log

def _rrtypes_from_window_list(window_list):
    # see RFC 3845, section 2.1.2 "The List of Type Bit Map(s) Field"
    types = []
    for win_nr, bitmap in window_list:
        offset = win_nr * 256
        octet_counter = 0
        for b in struct.unpack('B'*len(bitmap), bitmap):
            bitmask = 0x80
            bit_counter = 0
            while bitmask:
                if b & bitmask:
                    types.append(offset + octet_counter*8 + bit_counter)
                bit_counter += 1
                bitmask >>= 1
            octet_counter += 1

    return types

def _rrtypes_to_text(types):
    # TODO: exception
    types_text = []
    for r in types:
        types_text.append(dns.rdatatype.to_text(r))

    return types_text


class DNSPythonResult(object):
    def __init__(self, dnspython_result):
        self._result = dnspython_result

    def status(self):
        return dns.rcode.to_text(self._result.rcode())

    def find_SOA(self, in_answer=True):
        for r in self._result.answer if in_answer else self._result.authority:
            if (r.rdclass == dns.rdataclass.IN and
                    r.rdtype == dns.rdatatype.SOA):
                return name.domainname_from_wire(
                        r.name.to_wire(file=None, compress=None, origin=None))
        return None

    def find_DNSKEY(self):
        for r in self._result.answer:
            if (r.rdclass == dns.rdataclass.IN and
                    r.rdtype == dns.rdatatype.DNSKEY):
                return name.domainname_from_wire(
                        r.name.to_wire(file=None, compress=None, origin=None))
        return None

    def answer_length(self):
        return len(self._result.answer)

    def find_NSEC(self, in_answer=False):
        nsec = []
        for r in self._result.authority if not in_answer else self._result.answer:
            if (r.rdclass == dns.rdataclass.IN and
                    r.rdtype == dns.rdatatype.NSEC):
                types = _rrtypes_from_window_list(r[0].windows)
                nsec.append(rrtypes.nsec.NSEC(
                        name.domainname_from_wire(
                            r.name.to_wire(file=None, compress=None,
                                origin=None)),
                        r.ttl,
                        'IN',
                        name.domainname_from_wire(
                            r[0].next.to_wire(file=None, compress=None,
                                origin=None)),
                        _rrtypes_to_text(types)
                        ))
        return nsec


    def find_NSEC3(self):
        nsec3 = []
        for r in self._result.authority:
            if (r.rdclass == dns.rdataclass.IN and
                    r.rdtype == dns.rdatatype.NSEC3):
                types = _rrtypes_from_window_list(r[0].windows)
                nsec3.append(rrtypes.nsec3.NSEC3(
                    name.domainname_from_wire(r.name.to_wire(file=None,
                        compress=None, origin=None)),
                    r.ttl,
                    'IN',
                    r[0].algorithm,
                    r[0].flags,
                    r[0].iterations,
                    r[0].salt,
                    r[0].next,
                    _rrtypes_to_text(types)))
        return nsec3

def dnspython_query(dname, ns_ip, ns_port, rrtype, timeout):
    # XXX:
    qname = dns.name.from_wire(dname.to_wire(), 0)[0]

    q = dns.message.make_query(qname,
                               rrtype,
                               want_dnssec=True,
                               payload = 4096)
    r = dns.query.udp(q, ns_ip, port=ns_port, timeout=timeout,
            ignore_unexpected=True)
    if r.flags & dns.flags.TC:
        r = dns.query.tcp(q, ns_ip, port=ns_port, timeout=timeout)

    return DNSPythonResult(r)


def query(dname, ns, rrtype, timeout):
    try:
        res = dnspython_query(dname, ns.ip_str(), ns.port, rrtype, timeout)
    except dns.exception.Timeout:
        return exception.TimeOutError()
    except dns.query.BadResponse:
        return exception.QueryError()
    if res.status() != 'NOERROR' and res.status() != 'NXDOMAIN':
        return exception.UnexpectedResponseStatus(res.status())
    return res

def query_ns_records(zone):
    try:
        log.info("looking up nameservers for zone ", str(zone))
        zname = dns.name.from_wire(zone.to_wire(),0)[0]
        ans = dns.resolver.query(zname, 'NS')
        return set([rd.to_text() for rd in ans])
    except dns.resolver.NXDOMAIN as e:
        raise exception.N3MapError('failed to resolve nameservers for zone: NXDOMAIN')
    except dns.exception.DNSException as e:
        raise exception.N3MapError('failed to resolve nameservers for zone')



