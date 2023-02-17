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

    def _retrieve_nsec(self, dname, last_nsec):
        raise NotImplementedError

    def walk(self):
        self._set_status_generator()
        try:
            return self._walk_zone()
        except (KeyboardInterrupt, N3MapError) as e:
            raise e
        finally:
            log.logger.set_status_generator(None,None)

    def _walk_zone(self):
        dname = self.start
        covering_nsec = None
        while not self._finished(dname):
            query_dn, recv_nsec, ns = self._retrieve_nsec(dname, covering_nsec)
            if len(recv_nsec) == 0:
                msg = [
                    'no NSEC RR received\n',
                    "Maybe the zone doesn't support DNSSEC or uses NSEC3 RRs\n",
                    ]
                if isinstance(self, NSECWalkerN) or isinstance(self,
                        NSECWalkerMixed):
                    msg.append("or the server {} does not allow NSEC queries.\n"
                            .format(ns))
                    msg.append("Perhaps try using --query-mode=A")
                log.error(*msg)
                self.queryprovider.add_ns_error(ns)
                continue
            covering_nsec = self._find_covering_rr(recv_nsec, query_dn)
            if covering_nsec is None:
                log.errror("no covering NSEC RR received for domain name ",
                        str(dname))
                self.queryprovider.add_ns_error(ns)
                continue

            ns.reset_errors()

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
            dname = covering_nsec.next_owner

        self._write_number_of_records(len(self.nsec_chain))
        return self.nsec_chain


    def _finished(self, dname):
        return (((dname is not None and dname == self.zone) or (self.end is not
            None and dname >= self.end)) and len(self.nsec_chain) > 0)


    def _find_covering_rr(self, recv_rr, query_dn):
        covering_nsec = None
        for nsec in recv_rr:
            log.debug2('received NSEC RR: ' + str(nsec))
            if not nsec.part_of_zone(self.zone):
                raise NSECWalkError("received invalid NSEC RR, not part of zone")
            if nsec.covers(query_dn) or nsec.next_owner == self.zone:
                covering_nsec = nsec
                break
        return covering_nsec

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

    def _is_subzone_start(self, nsec):
        if (nsec is not None and 'SOA' in nsec.types and
                nsec.owner != self.zone):
            # walked into a subzone which is also signed and served by this
            # nameserver
            log.warn("subdomain NSEC record detected (has SOA RRtype), " +
                     "trying to skip subzone: ",
                     str(nsec.owner))
            return True
        return False

    def _detect_subdomain_soa(self, queryresult):
        soa_owner = queryresult.find_SOA(in_answer=False)
        if (soa_owner is not None and soa_owner != self.zone
                and soa_owner.part_of_zone(self.zone)):
            # walked into a subzone
            # we didn't get an NSEC record so self.is_subzone_start()
            # won't do the trick, but we should get the SOA of
            # the subzone as soon as we hit a non-existing owner
            # This might still be fragile...
            log.warn("subdomain SOA RR received, trying to skip subzone: ",
                     str(soa_owner))
            return True
        return False


class NSECWalkerN(NSECWalker):
    def __init__(self, zone, queryprovider, nsec_chain=None, startname=None,
            endname=None, output_file=None, stats=None):
        super(NSECWalkerN, self).__init__(zone, queryprovider, nsec_chain,
                startname, endname, output_file, stats)

    def walk(self):
        log.info("starting enumeration in NSEC query mode...")
        return super(NSECWalkerN,self).walk()

    def _retrieve_nsec(self, dname, last_nsec):
        if self._is_subzone_start(last_nsec):
            raise NSECWalkError('walked into subzone: ', str(last_nsec.owner),
                    "\ndon't know how to continue enumeration.\n",
                    "Try using mixed or 'A' query mode instead.")
        query_dn = dname
        result, ns = self.queryprovider.query(query_dn, rrtype='NSEC')
        recv_nsec = result.find_NSEC(in_answer=True)
        if len(recv_nsec) == 0 and self._detect_subdomain_soa(result):
            raise NSECWalkError('walked into subzone: ',
                                str(query_dn),
                    "\ndon't know how to continue enumeration.\n",
                    "Try using mixed or 'A' query mode instead.")
        return (query_dn, recv_nsec, ns)

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

    def _retrieve_nsec_mode_a(self, query_dn, base_query_dn=None):
        """Try to extract NSEC records using A queries

        base_query_dn is query_dn without any labels added on the left side.
        """

        while True:
            result, ns = self.queryprovider.query(query_dn, rrtype='A')
            recv_nsec = result.find_NSEC()
            if len(recv_nsec) > 0:
                break
            elif result.status() == "NOERROR":
                if result.answer_length() > 0:
                    log.info("hit an existing owner name: ", str(query_dn))
                    query_dn = self._next_dn_extend_increase(query_dn)
                    ns.reset_errors()
                    continue
                elif base_query_dn is not None:
                    # this happens when the query name with added label (usually
                    # \x00) in front is part of a zone delegated to a different
                    # nameserver
                    log.debug1("got NOERROR response but no RRs for owner: ",
                            str(query_dn))
                    log.debug1("this owner is likely part of a domain " +
                               "delegated to a different nameserver, " +
                               "trying to skip it")
                    # we take the base_query_dn without the added (\x00) label
                    # and increase it to skip this zone
                    query_dn = self._next_dn_extend_increase(base_query_dn)
                    base_query_dn = None
                    ns.reset_errors()
                    continue
            elif result.status() != "NXDOMAIN":
                # some other unexpected status:
                log.error('unexpected response status: ', str(result.status()))
                self.queryprovider.add_ns_error(ns)
            else: # status is NXDOMAIN
                if base_query_dn is not None:
                    if self._detect_subdomain_soa(result):
                        # this happens when the query name with added label
                        # (usually \x00) in front is part of a different zone,
                        # but that zone is also served by this server
                        pass
                    else:
                        # AFAIK this shouldn't happen (at least not when
                        # querying authoritative nameservers)
                        # but lets try to continue anyway after barking loudly
                        log.warn("got NXDOMAIN response without NSEC or " +
                                "subdomain SOA RR\n" +
                                "probably walked into a subzone *somehow*, " +
                                "trying to skip it")

                    # try to skip the subzone we walked into
                    query_dn = self._next_dn_extend_increase(base_query_dn)
                    base_query_dn = None
                    ns.reset_errors()
                    continue
                # no nsec records received:
                break
        return (query_dn, recv_nsec, ns)


    def _retrieve_nsec(self, dname, last_nsec):
        if self._is_subzone_start(last_nsec):
            return self._retrieve_nsec_mode_a(
                    # increase label (e.g. www -> www\x00)
                    self._next_dn_extend_increase(last_nsec.owner)
                    )

        if (self._never_prefix_label and not
                (dname == self.start and self.start == self.zone)):
            return self._retrieve_nsec_mode_a(
                    self._next_dn_extend_increase(dname))

        return self._retrieve_nsec_mode_a(
                # add label (e.g. www -> \x00.www)
                self._next_dn_label_add(dname),
                dname
                )

class NSECWalkerMixed(NSECWalkerA):

    def walk(self):
        log.info("starting enumeration in mixed query mode...")
        return NSECWalker.walk(self)

    def _retrieve_nsec(self, dname, last_nsec):
        if self._is_subzone_start(last_nsec):
            (query_dn, recv_nsec, ns) = self._retrieve_nsec_mode_a(
                    # increase label (e.g. www -> www\x00)
                    self._next_dn_extend_increase(last_nsec.owner)
                    )
        else:
            query_dn = dname
            result, ns = self.queryprovider.query(query_dn, rrtype='NSEC')
            recv_nsec = result.find_NSEC(in_answer=True)
            if len(recv_nsec) == 0 and self._detect_subdomain_soa(result):
                # walked into a subzone
                (query_dn, recv_nsec, ns) = self._retrieve_nsec_mode_a(
                        self._next_dn_extend_increase(query_dn)
                        )
        return (query_dn, recv_nsec, ns)
