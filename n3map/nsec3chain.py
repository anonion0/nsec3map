from . import log
from . import util
from .exception import ZoneChangedError
from .tree.nsec3tree import NSEC3Tree, OverLapError

class NSEC3Chain(object):
    def __init__(self, iterable=None, ignore_overlapping=False):
        self.tree = NSEC3Tree()
        self.salt = None
        self.iterations = None
        self.zone = None
        self.tree.ignore_overlapping = ignore_overlapping
        if iterable is not None:
            for nsec3 in iterable:
                self.insert(nsec3)

    def _sortedvalues(self):
        values = []
        self.tree.inorder(lambda n: values.append(n.value))
        return values

    def _check_salt(self, nsec3):
        if self.salt is None:
            self.salt = nsec3.salt
            log.debug2("salt = 0x", util.str_to_hex(self.salt))
        elif self.salt != nsec3.salt:
            raise ZoneChangedError("NSEC3 salt changed")
        else:
            nsec3.salt = self.salt

    def _check_iterations(self, nsec3):
        if self.iterations is None:
            self.iterations = nsec3.iterations
            log.debug2("number of iterations = ", self.iterations)
        elif self.iterations != nsec3.iterations:
            raise ZoneChangedError("NSEC3 number of iterations changed")

    def _check_zone(self, nsec3):
        if self.zone is None:
            self.zone = nsec3.zone
        elif self.zone != nsec3.zone:
                raise ZoneChangedError("NSEC3 zone name changed")
        else:
            nsec3.zone = self.zone

    def insert(self, nsec3):
        """Inersts an NSEC3 record into the tree.

        Returns True if the record didn't already exist in the tree, False
        otherwise
        """
        self._check_zone(nsec3)
        self._check_salt(nsec3)
        self._check_iterations(nsec3)

        key = nsec3.hashed_owner
        int_end = nsec3.next_hashed_owner
        try:
            new, was_updated = self.tree.insert(key, None, int_end)
        except OverLapError:
            raise ZoneChangedError("NSEC3 record overlaps with " +
                    "another NSEC3 record")
        return (not was_updated)

    def find_hash(self, h):
        n = self.tree.find(h)
        if n is None:
            return None
        else:
            return n.value

    def covers(self, nsec3_hash):
        return (self.tree.find_interval(nsec3_hash) is not None)

    def covers_zone(self):
        return (self.tree.hash_max <= self.tree.covered_distance)

    def coverage(self):
        return float(self.tree.covered_distance)/float(self.tree.hash_max)

    def size(self):
        return self.tree.size()

    def get_list(self):
        return self._sortedvalues()

