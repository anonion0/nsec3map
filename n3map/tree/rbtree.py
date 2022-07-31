from . import bstree

RED = 0
BLACK = 1

class RBTreeNode(bstree.BSTreeNode):
    """A node of a Red-Black Tree"""

    def __init__(self, k, v, nil=None):
        super(RBTreeNode, self).__init__(k, v, nil)
        self.color = BLACK
        self.size = 0

    def update_size(self):
        """Update the size attribute using the size attribute of left and right childs.

        Time complexity: O(1)"""
        self.size = 1 + self.left.size + self.right.size

class RBTree(bstree.BSTree):
    """A Red-Black Binary Search Tree"""
    def __init__(self, node_type=RBTreeNode):
        super(RBTree, self).__init__(node_type)
        self.nil.color = BLACK

    def _left_rotate(self, x):
        """Perform a left rotation around node x

        Time complexity: O(1)"""
        y = x.right
        x.right = y.left
        if y.left is not self.nil:
            y.left.parent = x
        y.parent = x.parent
        if x.parent is self.nil:
            self.root = y
        elif x is x.parent.left:
            x.parent.left = y
        else:
            x.parent.right = y
        y.left = x
        x.parent = y
        y.size = x.size
        x.update_size()

    def _right_rotate(self, x):
        """Perform a right rotation around node x

        Time complexity: O(1)"""
        y = x.left
        x.left = y.right
        if y.right is not self.nil:
            y.right.parent = x
        y.parent = x.parent
        if x.parent is self.nil:
            self.root = y
        elif x is x.parent.right:
            x.parent.right = y
        else:
            x.parent.left = y
        y.right = x
        x.parent = y
        y.size = x.size
        x.update_size()

    def _insert_fixup(self, new):
        """Restore Red-Black properties of the tree after node insertion.

        Time complexity: O(lg n)"""
        while new.parent.color == RED:
            if new.parent is new.parent.parent.left:
                y = new.parent.parent.right
                if y.color == RED:
                    new.parent.color = BLACK
                    y.color = BLACK
                    new.parent.parent.color = RED
                    new = new.parent.parent
                else:
                    if new is new.parent.right:
                        new = new.parent
                        self._left_rotate(new)
                    new.parent.color = BLACK
                    new.parent.parent.color = RED
                    self._right_rotate(new.parent.parent)
            else:
                y = new.parent.parent.left
                if y.color == RED:
                    new.parent.color = BLACK
                    y.color = BLACK
                    new.parent.parent.color = RED
                    new = new.parent.parent
                else:
                    if new is new.parent.left:
                        new = new.parent
                        self._right_rotate(new)
                    new.parent.color = BLACK
                    new.parent.parent.color = RED
                    self._left_rotate(new.parent.parent)
        self.root.color = BLACK

    def _transplant(self, old, new):
        """Replace subtree rooted at node old with the subtree rooted at node new

        Time complexity: O(1)"""
        if old.parent is self.nil:
            self.root = new
        elif old is old.parent.left:
            old.parent.left = new
        else:
            old.parent.right = new
        new.parent = old.parent

    def _delete_fixup(self, x):
        """Restore Red-Black properties of the tree after node deletion.

        Time complexity: O(lg n)"""
        while x is not self.root and x.color == BLACK:
            if x is x.parent.left:
                w = x.parent.right
                if w.color == RED:
                    w.color = BLACK
                    x.parent.color = RED
                    self._left_rotate(x.parent)
                    w = x.parent.right
                if w.left.color == BLACK and w.right.color == BLACK:
                    w.color = RED
                    x = x.parent
                else:
                    if w.right.color == BLACK:
                        w.left.color = BLACK
                        w.color = RED
                        self._right_rotate(w)
                        w = x.parent.right
                    w.color = x.parent.color
                    x.parent.color = BLACK
                    w.right.color = BLACK
                    self._left_rotate(x.parent)
                    x = self.root
            else:
                w = x.parent.left
                if w.color == RED:
                    w.color = BLACK
                    x.parent.color = RED
                    self._right_rotate(x.parent)
                    w = x.parent.left
                if w.right.color == BLACK and w.left.color == BLACK:
                    w.color = RED
                    x = x.parent
                else:
                    if w.left.color == BLACK:
                        w.right.color = BLACK
                        w.color = RED
                        self._left_rotate(w)
                        w = x.parent.left
                    w.color = x.parent.color
                    x.parent.color = BLACK
                    w.left.color = BLACK
                    self._right_rotate(x.parent)
                    x = self.root
        x.color = BLACK

    def _update_size(self, node):
        """Updates the size attribute on all nodes from node to the root.

        Time complexity: O(lg n)"""
        while node is not self.nil:
            node.update_size()
            node = node.parent

    def deletekey(self, k):
        node = self.find(k)
        if node is not None:
            node = self.delete(node)
        return node

    def delete(self, node):
        """Delete node from the tree, preserving all red-black properties.

        Returns the deleted node.
        Time complexity: O(lg n)"""
        y = node
        y_orig_color = y.color
        if node.left is self.nil:
            x = node.right
            sz_update = node.parent
            self._transplant(node, node.right)
            self._update_size(sz_update)
        elif node.right is self.nil:
            x = node.left
            sz_update = node.parent
            self._transplant(node, node.left)
            self._update_size(sz_update)
        else:
            y = self.minimum(node.right)
            y_orig_color = y.color
            x = y.right
            if y.parent is node:
                sz_update = y
                x.parent = y
            else:
                sz_update = y.parent
                self._transplant(y, y.right)
                y.right = node.right
                y.right.parent = y
            self._transplant(node, y)
            y.left = node.left
            y.left.parent = y
            y.color = node.color
            self._update_size(sz_update)


        if y_orig_color == BLACK:
            self._delete_fixup(x)
        return node

    def update(self, x, new):
        """Set change value(s) of node x to those from node new

        Time Complexity: O(1)
        """
        x.value = new.value


    def insert_node(self, new):
        """Insert a new node with distinct key k and value v into the tree, preserving all red-black properties.

        Returns the newly inserted/updated node
        Time complexity: O(lg n)"""
        y = self.nil
        x = self.root
        while x is not self.nil:
            y = x
            if new.key < x.key:
                x = x.left
            elif new.key > x.key:
                x = x.right
            else:
                # key is already in tree
                self.update(x, new)
                return x

        new.parent = y
        if y is self.nil:
            self.root = new
        elif new.key < y.key:
            y.left = new
        else:
            y.right = new
        new.left = self.nil
        new.right = self.nil
        new.color = RED
        new.size = 1
        self._update_size(new)
        self._insert_fixup(new)
        return new


    def size(self):
        """Returns the number of nodes stored in the tree.

        Time complexity: O(1)"""
        return self.root.size
