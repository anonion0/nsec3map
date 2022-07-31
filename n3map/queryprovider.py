import collections
import socket
import time
import itertools
import threading
import queue

from . import vis
from . import query
from . import log
from .exception import (
        N3MapError,
        InvalidPortError,
        QueryError,
        TimeOutError,
        MaxRetriesError,
        MaxNsErrors,
        UnexpectedResponseStatus,
    )


DEFAULT_PORT = 53
QR_MEASUREMENTS = 256


class QueryProvider(object):
    def __init__(self,
                 ns_list,
                 timeout,
                 max_retries,
                 max_errors = 1,
                 stats=None,
                 query_interval=None):
        self.ns_list = ns_list
        self.next_ns_idx = 0
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_errors = max_errors
        self.query_interval = query_interval
        self._last_query_time = None

        self.stats = stats if stats is not None else {}
        self.stats['queries'] = 0
        self._qr_measurements = collections.deque(maxlen=QR_MEASUREMENTS)

    def _ns_cycle(self, step=1):
        self.next_ns_idx = (self.next_ns_idx + step) % len(self.ns_list)

    def _next_ns(self):
        ns = self.ns_list[self.next_ns_idx]
        self._ns_cycle()
        return ns

    def _remove_ns(self, ns):
        try:
            ns_idx = self.ns_list.index(ns)
        except ValueError:
            # may have been already removed
            return
        removed_ns = self.ns_list.pop(ns_idx)

        log.warn("removed misbehaving/unresponsive nameserver ", str(removed_ns))

        if len(self.ns_list) == 0:
            self._ns_cycle = 0
            raise N3MapError("ran out of working nameservers!")

        # ensure the correct server is next in line:
        if ns_idx < self.next_ns_idx:
            self._ns_cycle(-1)
        else:
            self._ns_cycle(0)


        if self.query_interval is not None:
            # make sure we reduce the query rate such that each server receives
            # the same q/s as before
            single_server_interval = self.query_interval * (len(self.ns_list)+1)
            self.query_interval = single_server_interval/len(self.ns_list)
            log.warn("reducing query rate to avoid increasing the load ",
                    "on remaining servers")

    def add_ns_error(self, ns):
        try:
            ns.add_error(self.max_errors)
        except MaxNsErrors:
            self._remove_ns(ns)

    def add_ns_timeout(self, ns):
        try:
            ns.add_timeouterror(self.max_retries)
        except MaxRetriesError:
            self._remove_ns(ns)

    def _query_timing(self, query_dn, rrtype, ns):
        self._wait_query_interval()
        self._qr_measurements.append(time.monotonic())
        return ns

    def _sendquery(self, query_dn, ns, rrtype):
        # XXX
        # need to block signals because dnspython doesn't handle EINTR
        # correctly
        log.logger.block_signals()
        try:
            self.stats['queries'] += 1
            log.debug2('query: ', query_dn, '; ns = ', ns, '; rrtype = ', rrtype)
            return query.query(query_dn, ns, rrtype, self.timeout)
        finally:
            log.logger.unblock_signals()


    def query(self, query_dn, rrtype='A'):
        ns = self._next_ns()
        self._query_timing(query_dn, rrtype, ns)
        while True:
            res = self._sendquery(query_dn, ns, rrtype)
            if not isinstance(res, N3MapError):
                ns.retries = 0
                # don't know yet if we can reset the error counter, caller
                # decides
                return (res, ns)
            if isinstance(res, TimeOutError):
                self.add_ns_timeout(ns)
                ns = self._next_ns()
                continue
            if isinstance(res, QueryError) or isinstance(res,
                    UnexpectedResponseStatus):
                log.error("{} from server {}".format(res, ns))
                self.add_ns_error(ns)
                ns = self._next_ns()
                continue


    def query_rate(self):
        if len(self._qr_measurements) < 2:
            return 0.0
        else:
            #return 1.0/((self._qr_measurements[-1] -
            #        self._qr_measurements[0])/float(len(self._qr_measurements)))
            interval = self._qr_measurements[-1] - self._qr_measurements[0]
            return len(self._qr_measurements)/interval

    def _wait_query_interval(self):
        if (self.query_interval is not None and
                self._last_query_time is not None):

            # the loop is needed because time.sleep()
            # may be interrupted by a signal
            while True:
                diff = time.monotonic() - self._last_query_time
                if diff < 0 or diff >= self.query_interval:
                    break
                time.sleep(self.query_interval - diff)

        self._last_query_time = time.monotonic()


class Query(object):
    def __init__(self, id, query_dn, ns, rrtype, timeout):
        self.id = id
        self.query_dn = query_dn
        self.ns = ns
        self.rrtype = rrtype
        self.timeout = timeout

def create_aggressive_qp(queryprovider, num_threads):
    return AggressiveQueryProvider(queryprovider.ns_list,
                                   queryprovider.timeout,
                                   queryprovider.max_retries,
                                   queryprovider.max_errors,
                                   queryprovider.stats,
                                   queryprovider.query_interval,
                                   num_threads)

class AggressiveQueryProvider(QueryProvider):
    def __init__(self,
                 ns_list,
                 timeout,
                 max_retries,
                 max_errors,
                 stats=None,
                 query_interval=None,
                 num_threads=1):
        super(AggressiveQueryProvider,self).__init__(
                 ns_list,
                 timeout,
                 max_retries,
                 max_errors,
                 stats,
                 query_interval)
        self._current_queryid = 0
        self._active_queries = {}
        self._results = {}
        self._query_queue = queue.Queue()
        self._result_queue = queue.Queue()
        self._querythreads = []
        self._start_query_threads(num_threads)

    def _start_query_threads(self,num=1):
        for i in range(num):
            qt = QueryThread(self._query_queue, self._result_queue)
            self._querythreads.append(qt)
            qt.start()

    def stop(self):
        for i in range(len(self._querythreads)):
            self._query_queue.put(None)
        for qt in self._querythreads:
            qt.join()

    def _gen_query_id(self):
        self._current_queryid += 1
        return self._current_queryid

    def _sendquery(self, query):
        self.stats['queries'] += 1
        log.debug2('query: ', query.query_dn, '; ns = ', query.ns, '; rrtype = ', query.rrtype)
        self._active_queries[query.id] = query
        self._query_queue.put(query)
        return query.id

    def _checkresult(self, qid, res):
        q = self._active_queries[qid]
        if not isinstance(res, N3MapError):
            q.ns.retries = 0
            self._results[qid] = (res, q.ns)
            del self._active_queries[qid]
            return
        try:
            raise res
        except TimeOutError:
            try:
                self.add_ns_timeout(q.ns)
            except N3MapError as e:
                # happens when we run out of servers
                del self._active_queries[qid]
                raise e
            q.ns = self._next_ns()
            self._sendquery(q)
        except (QueryError, UnexpectedResponseStatus) as e:
            log.error("{} from server {}".format(e, q.ns))
            try:
                self.add_ns_error(q.ns)
            except N3MapError as e:
                # happens when we run out of servers
                del self._active_queries[qid]
                raise e
            q.ns = self._next_ns()
            self._sendquery(q)


    def _collectresponses(self, block=True):
        if block:
            self._checkresult(*self._result_queue.get(True))
        has_responses = True
        while has_responses:
            try:
                self._checkresult(*self._result_queue.get(False))
            except queue.Empty:
                has_responses = False

    def collectresponses(self, block=True):
        self._collectresponses(block)
        res = list(self._results.items())
        self._results.clear()
        return res


    def query_ff(self, query_dn, rrtype='A'):
        ns = self._next_ns()
        self._query_timing(query_dn, rrtype, ns)
        return self._sendquery(Query(self._gen_query_id(), query_dn, ns, rrtype, self.timeout))


    def query(self, query_dn, rrtype='A'):
        qid = self.query_ff(query_dn, rrtype)
        while True:
            self._collectresponses(block=True)
            res = self._results.pop(qid,None)
            if res is not None:
                return res


class QueryThread(threading.Thread):
    def __init__(self, query_queue, result_queue):
        super(QueryThread, self).__init__()
        self.daemon = True
        self._query_queue = query_queue
        self._result_queue = result_queue

    def run(self):
        query_queue = self._query_queue
        result_queue = self._result_queue
        while True:
            q = query_queue.get()
            if q is None:
                return
            result_queue.put((q.id,query.query(q.query_dn, q.ns, q.rrtype, q.timeout)))



class NameServer(object):
    def __init__(self, ip, port, name):
        if port < 0 or port > 65535:
            raise InvalidPortError(str(port))
        self.ip = ip
        self.port = port
        self.name = vis.strvis(name.encode()).decode()
        self.retries = 0
        self.errors = 0

    def add_timeouterror(self, max_retries):
        if max_retries != -1:
            self.retries += 1
            retries_left = max_retries - self.retries
            log.warn("timeout reached when waiting for response from ", str(self),
                    ", ", str(max(0,retries_left)), " retries left")
            if retries_left <= 0:
                raise MaxRetriesError('no response from server: ' + str(self))
        else:
            log.debug2("timeout reached when waiting for response from ", str(self))

    def add_error(self, max_errors):
        self.errors += 1
        if max_errors != -1:
            errors_left = max_errors - self.errors
            log.warn(str(max(0,errors_left)), " errors left for ", str(self))
            if errors_left <= 0:
                raise MaxNsErrors()
        else:
            log.debug2(str(self), " had ", str(self.errors), " error(s)")

    def reset_errors(self):
        self.errors = 0


    def __str__(self):
        ip = str(self.ip)
        name = str(self.name)
        if name == ip:
            name = ''
        else:
            name = ''.join((' (',name,')'))
        return ''.join((ip,':',str(self.port),name))


def _resolve(host, port):
    try:
        ip_list = []
        for info in socket.getaddrinfo(host, port, socket.AF_INET,
                socket.SOCK_DGRAM, socket.IPPROTO_IP):
            if info[0] == socket.AF_INET:
                ip_list.append(info[4][0])
        return ip_list
    except socket.gaierror as e:
        raise N3MapError("could not resolve host '" +
                str(host) + "': " + str(e))

def nameserver_from_text(*hosts):
    lst = []
    ns_dict = {}
    for s in hosts:
        host = None
        port = None
        for i, v in enumerate(s.rsplit(':', 1)):
            if i == 0:
                host = v
            else:
                try:
                    port = int(v)
                except ValueError:
                    raise InvalidPortError(str(v))
        if port is None:
            port = DEFAULT_PORT
        for ip in _resolve(host, port):
            ns = NameServer(ip, port, host)
            if (ip, port) in ns_dict:
                original = ns_dict[(ip, port)]
                if host != original[0]:
                    log.warn("nameserver {} is a duplicate of {}, ignoring it"
                            .format(ns, original[1]))
                continue
            ns_dict[(ip, port)] = (host, ns)
            lst.append(ns)
    return lst


