import gc
import multiprocessing
import os
import sys

from . import log
from . import rrtypes
from . import name
from .name import DomainName,Label


HAS_NSEC3HASH = False
try:
    from . import nsec3hash
    HAS_NSEC3HASH = True
except ImportError:
    pass

def _process_label_generator(label_fun, gap, process_id, num_processes, init=0):
    start = l = int(process_id*gap+init)
    end = start + gap
    while True:
        if l >= end:
            start += int(num_processes*gap)
            end = start + gap
            l = start
        lblstr = label_fun(l)
        yield (lblstr, l)
        l += 1

def create_prehash_pool(num_processes, element_size,
        use_cext):
    processes = []
    hash_queues = []
    for i in range(num_processes):
        par,chld = multiprocessing.Pipe(True)
        p = PreHashProcess(chld, element_size, i, name.hex_label,
                num_processes, use_cext)
        p.start()
        processes.append((par,p))
        hash_queues.append(par)

    return hash_queues, processes


class PreHashProcess(multiprocessing.Process):
    def __init__ (self, pipe, element_size,
            process_id, label_fun, num_processes,  use_cext):
        multiprocessing.Process.__init__(self)
        # Kills this Process when parent exits
        self.daemon = True

        self.pipe = pipe
        self.id = process_id
        self.element_size = element_size
        self.use_cext = use_cext
        self.label_fun = label_fun
        self.num_processes = num_processes

        if self.use_cext and not HAS_NSEC3HASH:
            log.error("failed to import nsec3hash module\n",
                    "falling back to python-based hashing")
            self.use_cext = False

        self.zone = None
        self.generator = None
        self.salt = None
        self.iterations = None

    def run(self):
        try:
            os.nice(15)
            gc.collect()
            log.logger = None
            (label_counter_init,  self.zone, self.salt,
                    self.iterations) = self.pipe.recv()
            self.generator = _process_label_generator(label_fun =
                    self.label_fun, gap = 1024, process_id = self.id,
                    num_processes = self.num_processes,
                    init = label_counter_init)
            if self.use_cext:
                self._precompute_hashes(self._hash_cext)
            else:
                self._precompute_hashes(self._hash)
        except KeyboardInterrupt:
            sys.exit(3)


    def _hash(self, dn):
        return rrtypes.nsec3.compute_hash(dn, self.salt,
                self.iterations)

    def _hash_cext(self, dn):
        return nsec3hash.compute_hash(dn.to_wire(), self.salt,
                self.iterations)

    def _precompute_hashes(self, hash_func):
        counter_state = 0
        element_size = self.element_size
        generator = self.generator
        while True:
            element = []
            for i in range(element_size):
                ptlabel, counter_state = next(generator)
                dn = DomainName(Label(ptlabel), *self.zone.labels)
                hashed_owner =  hash_func(dn)
                element.append((ptlabel,hashed_owner))

            self.pipe.send((element, counter_state))

