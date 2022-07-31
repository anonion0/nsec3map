import itertools

from . import log
from . import name
from . import prehash
from . import util
from . import walker

from .queryprovider import create_aggressive_qp

from .statusline import format_statusline_nsec3

from .exception import N3MapError, NSEC3WalkError
from .nsec3chain import NSEC3Chain


class NSEC3Walker(walker.Walker):
    def __init__(self, zone, queryprovider, hash_queues, prehash_pool,
            nsec3_records, ignore_overlapping=False, label_counter=None,
            output_file=None, stats=None,predictor=None, aggressive=0):
        super(NSEC3Walker, self).__init__(zone, queryprovider, output_file, stats)
        self.stats['tested_hashes'] = 0

        self._prediction_current = None
        if predictor is not None:
            self._predictor_proc,self._predictor_pipe = predictor
        else:
            self._predictor_proc = None

        self._write_chain(nsec3_records)
        self.nsec3_chain = NSEC3Chain(ignore_overlapping=ignore_overlapping)
        self._update_predictor_state()
        for rr in nsec3_records:
            self.nsec3_chain.insert(rr)
            self._update_predictor_state()

        self._prehash_processes = prehash_pool

        if label_counter is not None:
            log.debug2("setting initial label counter to 0x{0:x}".format(
                        label_counter))
            self._label_counter_init = label_counter
        else:
            self._label_counter_init = 0

        self._label_counter_state = 0
        self._hash_queues = itertools.cycle(hash_queues)
        self._reset_prehashing()
        self._aggressive = aggressive

    def _process_query_result(self, query_dn, res):
        recv_nsec3 = res.find_NSEC3()
        if len(recv_nsec3) == 0:
            if res.status() == "NOERROR":
                log.info("hit an existing owner name: ", str(query_dn))
                return
            elif res.status() == 'NXDOMAIN':
                raise NSEC3WalkError('no NSEC3 RR received\n',
                        "Maybe the zone doesn't support DNSSEC or uses NSEC RRs")
            else:
                raise NSEC3WalkError('unexpected response status: ', res.status())
        self._insert_records(recv_nsec3)

    def _insert_records(self, recv_rr):
        # TODO: check if records cover query name
        for rr in recv_rr:
            log.debug2('received NSEC3 RR: ', str(rr))
            if not rr.part_of_zone(self.zone):
                raise NSEC3WalkError('NSEC3 RR not part of zone')

            # check if the record is minimally-covering
            #  ref 'NSEC3 White Lies':
            #  https://tools.ietf.org/html/rfc7129#appendix-B
            if rr.distance_covered() == 2:
                raise NSEC3WalkError('Received minimally-covering NSEC3 record\n',
                             'This zone likely uses "NSEC3 White Lies" to prevent zone enumeration\n',
                             '(See https://tools.ietf.org/html/rfc7129#appendix-B)')
            was_new = self.nsec3_chain.insert(rr)
            if was_new:
                log.debug1("discovered: ", str(rr.owner), " ",
                        ' '.join(rr.types))
                self._write_record(rr)
                self._update_predictor_state()

    def _map_aggressive(self, generator):
        queries = {}
        max_queries = self._aggressive
        oldqp = self.queryprovider
        self.queryprovider = create_aggressive_qp(self.queryprovider, max_queries)
        while not self.nsec3_chain.covers_zone():
            num_queries = len(queries)
            query_dn,dn_hash = self._find_uncovered_dn(generator, num_queries > 0)
            results = self.queryprovider.collectresponses(block=(num_queries >= max_queries))
            for qid, res in results:
                self._process_query_result(queries.pop(qid),res)
            if query_dn is None or self.nsec3_chain.covers(dn_hash):
                continue
            queries[self.queryprovider.query_ff(query_dn, rrtype='A')] = query_dn
        self.queryprovider.stop()
        self.queryprovider = oldqp

    def _map_normal(self, generator):
        while not self.nsec3_chain.covers_zone():
            query_dn,dn_hash = self._find_uncovered_dn(generator)
            result = self.queryprovider.query(query_dn, rrtype='A')
            self._process_query_result(query_dn, result)

    def _map_zone(self):
        generator = name.label_generator(name.hex_label, self._label_counter_init)
        while self.nsec3_chain.size() == 0:
            query_dn = name.DomainName(next(generator)[0], *self.zone.labels)
            res = self.queryprovider.query(query_dn, rrtype='A')
            self._process_query_result(query_dn, res)
        self._start_prehashing()
        if self._aggressive > 0:
            self._map_aggressive(generator)
        else:
            self._map_normal(generator)

        self._write_number_of_records(self.nsec3_chain.size())
        self._stop_prehashing()
        self._stop_predictor()


    def walk(self):
        log.info("starting NSEC3 enumeration...")
        self._set_status_generator()
        try:
            self._map_zone()
        except (KeyboardInterrupt, N3MapError) as e:
            if self._output_file is not None:
                self._output_file.write_label_counter(self._label_counter_state)
            self._stop_prehashing()
            self._stop_predictor()
            raise e
        finally:
            log.logger.set_status_generator(None, None)

        return self.nsec3_chain


    def _find_uncovered_dn(self, generator, break_early=False):
        is_covered = self.nsec3_chain.covers
        while True:
            for ptlabel,dn_hash in self._prehash_iter:
                if not is_covered(dn_hash):
                    dn = name.DomainName(name.Label(ptlabel), *self.zone.labels)
                    owner_b32 = util.base32_ext_hex_encode( dn_hash).lower()
                    hashed_dn = name.DomainName( name.Label(owner_b32), *self.zone.labels)
                    log.debug3('found uncovered dn: ', str(dn), '; hashed: ', str(hashed_dn))
                    return dn,dn_hash

            self.stats['tested_hashes'] += len(self._prehash_list)
            hashes, label_counter_state = next(self._hash_queues).recv()
            if self._label_counter_state < label_counter_state:
                self._label_counter_state = label_counter_state
            self._prehash_list = hashes
            self._prehash_iter = iter(hashes)
            log.update()
            if break_early:
                return None,None


    def _start_prehashing(self):
        for pipe, proc in self._prehash_processes:
            pipe.send((self._label_counter_init, self.zone,
                self.nsec3_chain.salt, self.nsec3_chain.iterations))
        self._prehash_started = True

    def _reset_prehashing(self):
        self._prehash_list = []
        self._prehash_iter = iter(self._prehash_list)
        self._prehash_started = False

    def _stop_prehashing(self):
        for pipe, proc in self._prehash_processes:
            proc.terminate()
        self._reset_prehashing()

    def _stop_predictor(self):
        if self._predictor_proc is not None:
            self._predictor_proc.terminate()

    def _update_predictor_state(self):
        if self._predictor_proc is not None:
            self._predictor_pipe.send((self.nsec3_chain.coverage(),
                                       self.nsec3_chain.size()))
            if self._predictor_pipe.poll():
                self._prediction_current = self._predictor_pipe.recv()

    def _set_status_generator(self):
        def status_generator():
            return (str(self.zone),
                    self.stats['queries'],
                    self.nsec3_chain.size(),
                    self.stats['tested_hashes'],
                    self.nsec3_chain.coverage(),
                    self.queryprovider.query_rate(),
                    self._prediction_current
                )
        log.logger.set_status_generator(status_generator, format_statusline_nsec3)


