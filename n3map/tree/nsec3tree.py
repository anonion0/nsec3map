from . import rbtree
from .. import log
from ..util import str_to_long
from ..exception import N3MapError

class NSEC3TreeNode(rbtree.RBTreeNode):
    def __init__(self, k, v, int_end=None, nil=None):
        super(NSEC3TreeNode, self).__init__(k, v, nil)
        self.int_end = int_end

    def covers(self, k):
        if self.is_last():
            return (k >= self.key or k <= self.int_end)
        return k >= self.key and k <= self.int_end

    def covered_distance(self, hash_max):
        l1 = str_to_long(self.key)
        l2 = str_to_long(self.int_end)
        if self.is_last():
            return hash_max - l1 + l2
        return l2-l1


    def is_last(self):
        return (self.key >= self.int_end)
    

class NSEC3Tree(rbtree.RBTree):
    def __init__(self, node_type=NSEC3TreeNode, hash_max=2**160-1):
        super(NSEC3Tree, self).__init__(node_type)
        self.last = None
        self.hash_max = hash_max
        self.covered_distance = int(0)
        self.ignore_overlapping = False

    def find_interval(self, k):
        """Finds the node n for which n.key <= k <= n.int_end

        Time complexity: O(lg n) (balanced)"""

        x = self.root
        p = self.nil

        if self.last is not None and self.last.covers(k):
            return self.last

        while x is not self.nil and k != x.key:
            p = x
            if k < x.key:
                x = x.left
            else:
                x = x.right

        if x is self.nil and p is not self.nil:
            if p.covers(k):
                x = p
            elif p.key > k:
                y = self.predecessor(p)
                if y is not None:
                    if y.covers(k):
                        x = y

        return x if x is not self.nil else None

    def update(self, x, new):
        if x.int_end != new.int_end:
            # same hashed owner name, but interval changed
            log.warn("next hashed owner changed for existing NSEC3 record\n", 
                            "zone may have changed")
            self.covered_distance += new.covered_distance(self.hash_max)
            self.covered_distance -= x.covered_distance(self.hash_max)
        x.value = new.value
        x.int_end = new.int_end

    def _check_overlap(self, node):
        if self.ignore_overlapping:
            return
        pre = self.predecessor(node)
        if pre is not None:
            if pre.int_end > node.key:
                raise OverLapError
        suc = self.successor(node)
        if suc is not None:
            if node.int_end > suc.key:
                raise OverLapError
    
    def insert(self, k, v, int_end):
        was_updated = False
        new = self.node_type(k=k, v=v, int_end=int_end)
        inserted = super(NSEC3Tree, self).insert_node(new)
        if new is inserted:
            # node didn't already exist
            self.covered_distance += new.covered_distance(self.hash_max)
        else:
            was_updated = True
        new = inserted

        if self.last is None and new.is_last():
            self.last = new

        self._check_overlap(new)
        return (new, was_updated)

    def delete(self, node):
        deleted = super(NSEC3Tree, self).delete(node)
        if self.last is deleted:
            self.last = None

        self.covered_distance -= deleted.covered_distance(self.hash_max)

        return deleted

class OverLapError(N3MapError):
    pass
