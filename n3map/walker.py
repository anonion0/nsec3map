from . import log
from . import name
from .exception import N3MapError

import secrets

def detect_dnssec_type(zone, queryprovider, attempts=5):
    log.info("detecting zone type...")
    i = 0
    while attempts == 0 or i < attempts:
        label_gen = name.label_generator(name.hex_label,
                                         init=secrets.randbits(30 +
                                             secrets.randbelow(31)))
        dname = name.DomainName(next(label_gen)[0], *zone.labels)
        result, _ = queryprovider.query(dname, rrtype='A')

        # check for NSEC/3 records even if we got a NOERROR response
        # to try and avoid loops when the zone contains a wildcard domain
        if len(result.find_NSEC()) > 0:
            log.info("zone uses NSEC records")
            return 'nsec'
        elif len(result.find_NSEC3()) > 0:
            log.info("zone uses NSEC3 records")
            return 'nsec3'

        if result.status() == "NXDOMAIN":
            raise N3MapError("zone doesn't seem to be DNSSEC-enabled")
        elif result.status() != "NOERROR":
            raise N3MapError("unexpected response status: ", result.status())

        # result.status() == "NOERROR":
        log.info("hit an existing owner name")
        i += 1
    raise N3MapError("failed to detect zone type after {0:d} attempt(s), terminating.".format(attempts))

def check_dnskey(zone, queryprovider):
    log.info('checking DNSKEY...')
    res, _ = queryprovider.query(zone, rrtype='DNSKEY')
    dnskey_owner = res.find_DNSKEY()
    if dnskey_owner is None:
        raise N3MapError("no DNSKEY RR found at ", zone,
                "\nZone is not DNSSEC-enabled.")
    if dnskey_owner != zone:
        raise N3MapError("invalid DNSKEY RR received. Aborting")

def check_soa(zone, queryprovider):
    log.info('checking SOA...')
    res, _ = queryprovider.query(zone, rrtype='SOA')
    soa_owner = res.find_SOA()
    if soa_owner is None:
        raise N3MapError("no SOA RR found at ", zone,
                "\nZone name may be incorrect.")
    if soa_owner != zone:
        raise N3MapError("invalid SOA RR received. Aborting")

class Walker(object):
    def __init__(self,
                 zone,
                 queryprovider,
                 output_file=None,
                 stats=None):
        self.zone = zone
        self.queryprovider = queryprovider
        self.stats = stats if stats is not None else {}
        self._output_file = output_file

    def _write_chain(self, chain):
        for record in chain:
            self._write_record(record)

    def _write_record(self, record):
        if self._output_file is not None:
            self._output_file.write_record(record)

    def _write_number_of_records(self, num):
        if self._output_file is not None:
            self._output_file.write_number_of_rrs(num)
