import itertools
import enum

from . import log
from . import name
from . import walker

from .exception import N3MapError

from .statusline import format_statusline_nsec

from .exception import (
        MaxDomainNameLengthError,
        MaxDomainNameLengthError,
        NSECWalkError
    )


class ResultStatus(enum.Enum):
    OK        = enum.auto()
    ERROR     = enum.auto()
    SUBZONE   = enum.auto()
    HITOWNER  = enum.auto()

class NSECResult:
    def __init__(self, walk_zone, query_dn, query_type, queryresult, ns):
        self.walk_zone = walk_zone
        self.query_dn = query_dn
        self.query_type = query_type
        self.queryresult = queryresult
        self.ns = ns

    def log_NSEC_rrs(self):
        for nsec in self.all_NSEC_rrs():
            log.debug3('received NSEC RR: ' + str(nsec))
            if not nsec.part_of_zone(self.walk_zone):
                log.warn("received invalid NSEC RR, not part of zone: ",
                         str(nsec))

    def _find_RRSIG_signer(self, owner, type_covered):
        signer = self.queryresult.find_RRSIG_signer(owner, type_covered, False)
        if signer is not None:
            return signer
        return self.queryresult.find_RRSIG_signer(owner, type_covered, True)

    def _RRSIG_signer_matches_zone(self, name, rrtype):
        signer = self._find_RRSIG_signer(name, rrtype)
        return signer is not None and signer == self.walk_zone

    def all_NSEC_rrs(self):
        return self.queryresult.all_NSEC_rrs()

    def num_NSEC_rrs(self):
        return sum(1 for _ in self.all_NSEC_rrs())

    def find_covering_nsec(self, check_signer=True, inclusive=True):
        covering_nsec = None
        for nsec in self.all_NSEC_rrs():
            if not nsec.part_of_zone(self.walk_zone):
                continue

            if check_signer and not self._RRSIG_signer_matches_zone(
                    nsec.owner, 'NSEC'):
                continue

            if ((inclusive and nsec.covers(self.query_dn)) or
                    (not inclusive and nsec.covers_exclusive(self.query_dn))
                    or nsec.next_owner == self.walk_zone):
                covering_nsec = nsec
                break
        return covering_nsec

    def status(self):
        return self.queryresult.status()

    def _detect_subdomain_soa(self):
        soa_owner = self.queryresult.find_SOA(in_answer=False)
        if (soa_owner is not None and soa_owner != self.walk_zone
                and soa_owner.part_of_zone(self.walk_zone)):
            log.debug1("subdomain SOA RR received: ", str(soa_owner))
            return soa_owner
        return None

    def _detect_subdomain_ns(self):
        ns_owner = self.queryresult.find_NS(in_answer=False)
        if (ns_owner is not None and ns_owner != self.walk_zone
                and ns_owner.part_of_zone(self.walk_zone)):
            log.debug1("subdomain NS RR received: ", str(ns_owner))
            return ns_owner
        return None

    def _detect_subdomain_auth(self):
        # check for NS or SOA records in authority
        ns_owner = self._detect_subdomain_ns()
        if ns_owner is not None:
            log.warn("walked into a sub-zone at ", str(self.query_dn),
                     " (subdomain NS received)")
            return ns_owner
        soa_owner = self._detect_subdomain_soa()
        if soa_owner is not None:
            log.warn("walked into a sub-zone at ", str(self.query_dn),
                     " (subdomain SOA received)")
            return soa_owner
        return None


    def _extract_from_NSEC_query(self):
        nsec = self.find_covering_nsec()
        if nsec is not None:
            return (ResultStatus.OK, nsec, None)

        nsec = self.find_covering_nsec(check_signer=False)
        if nsec is not None:
            # got NSEC record, but RRSIG signer doesn't match zone
            log.warn("walked into a sub-zone at ", str(self.query_dn),
                     " (RRSIG signer for NSEC RR does not match zone)")
            return (ResultStatus.SUBZONE, nsec,
                    self._find_RRSIG_signer(nsec.owner, 'NSEC'))

        # check for NS or SOA records in authority section
        if self._detect_subdomain_auth() is not None:
            return (ResultStatus.SUBZONE, None, self._detect_subdomain_auth())

        log.error("no covering NSEC RR received for domain name ",
                str(self.query_dn))
        return (ResultStatus.ERROR, None, None)

    def _extract_from_A_query(self):
        if self.status() == 'NXDOMAIN':
            nsec = self.find_covering_nsec(inclusive=False)
            if nsec is not None:
                return (ResultStatus.OK, nsec, None)

            nsec = self.find_covering_nsec(check_signer=False, inclusive=False)
            if nsec is not None:
                # got NSEC record, but RRSIG signer doesn't match zone
                log.warn("walked into a sub-zone at ", str(self.query_dn),
                         " (RRSIG signer for NSEC RR does not match zone)")
                return (ResultStatus.SUBZONE, nsec,
                        self._find_RRSIG_signer(nsec.owner, 'NSEC'))

            # NXDOMAIN but no NSEC

            # check for NS or SOA records in authority section
            if self._detect_subdomain_auth() is not None:
                return (ResultStatus.SUBZONE, None,
                        self._detect_subdomain_auth())

            log.error("no covering NSEC RR received in NXDOMAIN response for ",
                      str(self.query_dn))
            return (ResultStatus.ERROR, None, None)

        elif self.status() == 'NOERROR':
            if self.queryresult.answer_length() > 0:
                log.warn("hit an existing owner name: ", str(self.query_dn))
                signer = self._find_RRSIG_signer(self.query_dn, self.query_type)
                if signer is None:
                    log.warn("walked into a sub-zone at ", str(self.query_dn),
                             " (no RRSIG found)")
                    return (ResultStatus.SUBZONE, None, None)
                if signer != self.walk_zone:
                    log.warn("walked into a sub-zone at ", str(self.query_dn),
                             " (RRSIG signer does not match zone)")
                    return (ResultStatus.SUBZONE, None, signer)
                # part of this zone

                # check for NSEC records anyway. This can happen e.g. if the
                # owner name we hit was actually a wildcard
                # FIXME: wildcards could probably be handled more explicitly
                nsec = self.find_covering_nsec(inclusive=False)
                if nsec is not None:
                    return (ResultStatus.OK, nsec, None)

                return (ResultStatus.HITOWNER, None, None)
            # this happens e.g. when the query name with added label
            # (usually \x00) in front is part of a zone delegated to a
            # (possibly different) nameserver

            # check for NS or SOA records in authority section
            # this check is just to provide better feedback,
            # we'll treat this as a sub-zone in any case
            if self._detect_subdomain_auth() is not None:
                return (ResultStatus.SUBZONE, None,
                        self._detect_subdomain_auth())

            log.warn("got NOERROR response but no RRs for owner: ",
                     str(self.query_dn), ", looks like a sub-zone")
            return (ResultStatus.SUBZONE, None, None)

        # this should never happen as anything other than 'NXDOMAIN' or
        # 'NOERROR' already causes an error in queryprovider
        log.error('unexpected response status: ', str(self.status()))
        return (ResultStatus.ERROR, None, None)

    def extract(self):
        if self.query_type == 'NSEC':
            return self._extract_from_NSEC_query()
        # non-NSEC (A) query
        return self._extract_from_A_query()

class NSECWalker(walker.Walker):
    def __init__(self, zone, queryprovider, nsec_chain=None, startname=None,
            endname=None, output_file=None, stats=None):
        super(NSECWalker, self).__init__(zone, queryprovider, output_file,
                stats)
        if nsec_chain is not None:
            self.nsec_chain = list(sorted(nsec_chain, key=lambda x: x.owner))
            self._write_chain(self.nsec_chain)
        else:
            self.nsec_chain = []
        self.start, self.end = self._get_start_end(startname, endname)

    def _query(self, query_dn, rrtype='A'):
        if not query_dn.part_of_zone(self.zone):
            raise NSECWalkError('query_dn not part of zone!')
        result, ns = self.queryprovider.query(query_dn, rrtype)
        nresult = NSECResult(self.zone, query_dn, rrtype, result, ns)
        nresult.log_NSEC_rrs()
        return nresult


    def walk(self):
        self._set_status_generator()
        try:
            nsec_chain= self._walk_zone()
            self._write_number_of_records(len(nsec_chain))
            return nsec_chain
        except (KeyboardInterrupt, N3MapError) as e:
            raise e
        finally:
            log.logger.set_status_generator(None,None)

    def _append_covering_record(self, covering_nsec):
        log.debug2('covering NSEC RR found: ', str(covering_nsec))

        self._write_record(covering_nsec)

        if (covering_nsec.owner > covering_nsec.next_owner and
                covering_nsec.next_owner != self.zone):
            raise NSECWalkError('NSEC owner > next_owner, ',
                    'but next_owner != zone')

        self.nsec_chain.append(covering_nsec)
        log.debug1('discovered owner: ', str(covering_nsec.owner),
                "\t", ' '.join(covering_nsec.types))
        log.update()


    def _no_NSEC_error(self, ns):
        return ("no NSEC RR received\n" +
               "Maybe the zone doesn't support DNSSEC or uses NSEC3 RRs\n")

    def _walk_zone(self):
        raise NotImplementedError

    def _finished(self, dname):
        return (((dname is not None and dname == self.zone) or (self.end is not
            None and dname >= self.end)) and len(self.nsec_chain) > 0)


    def _get_start(self, startname):
        if len(self.nsec_chain) > 0:
            return self.nsec_chain[-1].next_owner

        if startname is None:
            return self.zone
        else:
            return name.DomainName(
                    *(name.domainname_from_text(startname).labels +
                        self.zone.labels))

    def _get_end(self, endname):
        if endname is None:
            end = None
        else:
            end = name.DomainName(
                    *(name.domainname_from_text(endname).labels +
                        self.zone.labels))
        return end

    def _get_start_end(self, startname, endname):
        start = self._get_start(startname)
        end = self._get_end(endname)
        if end is not None:
            if start >= end:
                raise NSECWalkError("invalid start / endpoint specified")

        return (start, end)

    def _set_status_generator(self):
        def status_generator():
            return (str(self.zone),
                    self.stats['queries'],
                    len(self.nsec_chain),
                    self.queryprovider.query_rate()
                )
        log.logger.set_status_generator(status_generator, format_statusline_nsec)


class NSECWalkerN(NSECWalker):
    def __init__(self, zone, queryprovider, nsec_chain=None, startname=None,
            endname=None, output_file=None, stats=None):
        super(NSECWalkerN, self).__init__(zone, queryprovider, nsec_chain,
                startname, endname, output_file, stats)

    def walk(self):
        log.info("starting enumeration in NSEC query mode...")
        return super(NSECWalkerN,self).walk()

    def _walk_zone(self):
        dname = self.start
        covering_nsec = None
        while not self._finished(dname):
            nresult = self._query(dname, rrtype='NSEC')
            (status, covering_nsec, subzone) = nresult.extract()
            if status == ResultStatus.ERROR:
                if nresult.num_NSEC_rrs() == 0:
                    log.error(self._no_NSEC_error(nresult.ns))
                self.queryprovider.add_ns_error(nresult.ns)
                continue
            elif status == ResultStatus.SUBZONE:
                if covering_nsec is not None:
                    # we write this record down anyway
                    self._append_covering_record(covering_nsec)
                raise NSECWalkError('walked into subzone at: ', str(dname),
                        "\ndon't know how to continue enumeration.\n",
                        "Try using 'mixed' or 'A' query mode instead.")
            elif status == ResultStatus.OK:
                nresult.ns.reset_errors()
            else:
                # in case we ever extend ResultStatus
                raise N3MapError(
                        "Unexpected ResultStatus. This should never happen")

            # status == OK:
            self._append_covering_record(covering_nsec)
            log.debug2("next in chain: ", str(covering_nsec.next_owner))
            dname = covering_nsec.next_owner

        return self.nsec_chain

    def _no_NSEC_error(self, ns):
        return (super()._no_NSEC_error(ns) +
                "or the server {} does not allow NSEC queries.\n".format(ns) +
                "Perhaps try using --query-mode=A")

class NSECWalkerA(NSECWalker):
    def __init__(self, zone, queryprovider, ldh = False, nsec_chain=None,
            startname=None, endname=None, output_file=None, stats=None,
                 never_prefix_label=False):
        super(NSECWalkerA, self).__init__(zone, queryprovider, nsec_chain,
                startname, endname, output_file, stats)
        self.ldh = ldh
        self._never_prefix_label = never_prefix_label

    def walk(self):
        log.info("starting enumeration in A query mode...")
        return super(NSECWalkerA,self).walk()

    def _extract_next_NSEC_a(self, dname):
        while not self._finished(dname):
            if self._never_prefix_label and dname != self.zone:
                query_dn = self._next_dn_extend_increase(dname)
            else:
                query_dn = self._next_dn_label_add(dname)
            nresult = self._query(query_dn, rrtype='A')
            (status, covering_nsec, subzone) = nresult.extract()
            if status == ResultStatus.ERROR:
                if nresult.num_NSEC_rrs() == 0:
                    log.error(self._no_NSEC_error(nresult.ns))
                self.queryprovider.add_ns_error(nresult.ns)
                continue
            elif status == ResultStatus.SUBZONE:
                nresult.ns.reset_errors()
                if covering_nsec is not None:
                    # we write this record down anyway
                    self._append_covering_record(covering_nsec)
                if dname == self.zone:
                    log.warn("trying to skip sub-zone ", str(query_dn))
                    if self._never_prefix_label:
                        # make sure we don't increase the label twice
                        dname = query_dn
                    else:
                        dname = self._next_dn_extend_increase(query_dn)
                else:
                    if (subzone is not None
                            and subzone.num_labels() <= dname.num_labels()):
                        # if we know the subzone, we can move on from there
                        log.debug1("learned sub-zone from response: ",
                                   str(subzone))
                        dname = subzone
                    elif dname.num_labels() > self.zone.num_labels() + 1:
                        (_, dname) = dname.split(dname.num_labels() -
                                            self.zone.num_labels() - 1)
                        log.warn("could not learn sub-zone name from response,",
                                 " skipping ", str(dname), " ENTIRELY to avoid",
                                 " loop")

                    log.warn("trying to skip sub-zone ", str(dname))
                    dname = self._next_dn_extend_increase(dname)
                continue
            elif status == ResultStatus.HITOWNER:
                # hit an existing name, but it is part of this zone
                nresult.ns.reset_errors()
                # add or increase label in nextg iteration
                dname = query_dn
                continue
            elif status == ResultStatus.OK:
                nresult.ns.reset_errors()
            else:
                # in case we ever extend ResultStatus
                raise N3MapError(
                        "Unexpected ResultStatus. This should never happen")

            # status == OK:
            # at this point we have our next record
            return (covering_nsec, dname)
        return (None, dname)

    def _walk_zone(self):
        dname = self.start
        covering_nsec = None
        while not self._finished(dname):
            covering_nsec, dname = self._extract_next_NSEC_a(dname)
            if covering_nsec is None:
                # only happens when self._finished(dname) == True
                break

            self._append_covering_record(covering_nsec)
            log.debug2("next in chain: ", str(covering_nsec.next_owner))
            dname = covering_nsec.next_owner

        return self.nsec_chain

    def _next_dn_label_add(self, dname):
        try:
            query_dn = dname.next_label_add(self.ldh)
        except MaxDomainNameLengthError:
            query_dn = self._next_dn_extend_increase(dname)

        self._check_query_dn(query_dn)
        return query_dn

    def _next_dn_extend_increase(self, dname):
        try:
            query_dn = dname.next_extend_increase(self.ldh)
        except MaxDomainNameLengthError as e:
            raise NSECWalkError(str(e))
        self._check_query_dn(query_dn)
        return query_dn

    def _check_query_dn(self, query_dn):
        if not query_dn.part_of_zone(self.zone):
            raise NSECWalkError('unable to increase ' +
                    'domain name any more.')

class NSECWalkerMixed(NSECWalkerA):

    def walk(self):
        log.info("starting enumeration in mixed query mode...")
        return NSECWalker.walk(self)

    def _walk_zone(self):
        dname = self.start
        covering_nsec = None
        while not self._finished(dname):
            nresult = self._query(dname, rrtype='NSEC')
            (status, covering_nsec, subzone) = nresult.extract()
            if status == ResultStatus.ERROR:
                if nresult.num_NSEC_rrs() == 0:
                    log.error(self._no_NSEC_error(nresult.ns))
                self.queryprovider.add_ns_error(nresult.ns)
                continue
            elif status == ResultStatus.SUBZONE:
                if covering_nsec is not None:
                    # we write this record down anyway
                    self._append_covering_record(covering_nsec)
                nresult.ns.reset_errors()
                # try to skip subzone using 'A' queries
                log.warn("trying to skip sub-zone at ", str(dname))
                if dname != self.zone and not self._never_prefix_label:
                    dname = self._next_dn_extend_increase(dname)
                (covering_nsec, dname) = self._extract_next_NSEC_a(dname)
                if covering_nsec is None:
                    # finished
                    break
            elif status == ResultStatus.OK:
                nresult.ns.reset_errors()
            else:
                # in case we ever extend ResultStatus
                raise N3MapError(
                        "Unexpected ResultStatus. This should never happen")

            # got our next record

            self._append_covering_record(covering_nsec)
            log.debug2("next in chain: ", str(covering_nsec.next_owner))
            dname = covering_nsec.next_owner

        return self.nsec_chain
