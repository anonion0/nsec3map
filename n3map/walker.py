import log
import name
from exception import N3MapError

from random import randint

def detect_dnssec_type(zone, queryprovider):
    log.info("detecting zone type...")
    label_gen = name.label_generator(name.hex_label,init=randint(0,0xFFFFFFFFFFFFFFFF))
    while True:
        dname = name.DomainName(label_gen.next()[0], *zone.labels)
        result = queryprovider.query(dname, rrtype='A')
        if result.status() == "NOERROR":
            log.info("hit an existing owner name")
            continue
        elif result.status() == "NXDOMAIN":
            if len(result.find_NSEC()) > 0:
                log.info("zone uses NSEC records")
                return 'nsec'
            elif len(result.find_NSEC3()) > 0:
                log.info("zone uses NSEC3 records")
                return 'nsec3'
            else:
                raise N3MapError, "zone doesn't seem to be DNSSEC-enabled"
        else:
            raise N3MapError, ("unexpected response status: ", result.status())

def check_soa(zone, queryprovider):
    log.info('checking SOA...')
    res = queryprovider.query(zone, rrtype='SOA')
    soa_owner = res.find_SOA()
    if soa_owner is None:
        raise N3MapError, ("no SOA RR found at ", zone, 
                "\nZone name may be incorrect.")
    if soa_owner != zone:
        raise N3MapError, "invalid SOA RR received. Aborting"

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
