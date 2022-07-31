class BSTreeNode(object):
    """Abstract implementation of a binary search tree node."""

    def __init__(self, k, v, nil=None):
        self.key =  k
        self.value = v

        self.left = nil
        self.right = nil
        self.parent = nil

class BSTree(object):
    """Abstract implementation of a binary search tree."""

    def __init__(self, node_type=BSTreeNode):
        self.node_type = node_type
        self.nil = self.node_type(k=None, v=None)
        self.root = self.nil
        self.root.parent = self.nil

    def contains(self, k):
        return self.find(k) is not None


    def find(self, k):
        """Finds the node with key k. Returns None if k is not found.

        Time complexity: O(lg n) (balanced)"""
        x = self.root
        while x is not self.nil and k != x.key:
            if k < x.key:
                x = x.left
            else:
                x = x.right
        return x if x is not self.nil else None


    def inorder(self, f):
        """Does an inorder traversal and calls f(x) for every node x.

        Time complexity: O(n)
        """
        return self._inorder_recurse(self.root, f)

    def _inorder_recurse(self, x, f):
        if x is self.nil:
            return
        self._inorder_recurse(x.left, f)
        f(x)
        self._inorder_recurse(x.right, f)

    def minimum(self, x=None):
        """Finds the node with the minimal key

        Returns nil if tree is empty
        Time complexity: O(lg n) (balanced)"""
        if x is None:
            x = self.root

        while x.left is not self.nil:
            x = x.left
        return x if x is not self.nil else None

    def maximum(self, x=None):
        """Finds the node with the maximum key

        Time complexity: O(lg n) (balanced)"""
        if x is None:
            x = self.root

        while x.right is not self.nil:
            x = x.right
        return x if x is not self.nil else None

    def successor(self, x):
        """Finds the successor of node x in sorted order

        Time complexity: O(lg n) (balanced)"""
        if x.right is not self.nil:
            return self.minimum(x.right)
        y = x.parent
        while y is not self.nil and x is y.right:
            x = y
            y = y.parent
        return y if y is not self.nil else None

    def predecessor(self, x):
        """Finds the predecessor of node x in sorted order

        Time complexity: O(lg n) (balanced)"""
        if x.left is not self.nil:
            return self.maximum(x.left)
        y = x.parent
        while y is not self.nil and x is y.left:
            x = y
            y = y.parent
        return y if y is not self.nil else None

