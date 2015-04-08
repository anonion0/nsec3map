import string
import struct

import vis
from exception import (
        InvalidDomainNameError,
        MaxDomainNameLengthError,
        MaxLabelLengthError,
        MaxLabelValueError
    )

# see RFC1035, section 2.3.4 "Size limits" for details
MAX_LABEL = 63
# for wire format:
MAX_DOMAINNAME = 255

ascii_upper_to_lower = string.maketrans(string.ascii_uppercase, 
                                        string.ascii_lowercase)

range_ld = map(ord, "0123456789abcdefghijklmnopqrstuvwxyz")
range_ldh = map(ord, "-0123456789abcdefghijklmnopqrstuvwxyz")

def hex_label(l):
    return "{0:x}".format(l)

def label_generator(label_fun, init=0L):
    l = init
    while True:
        lblstr = label_fun(l)
        yield (Label(lblstr), l)
        l += 1

def _split_domainname_str(s):
    if s == '.':
        return ("",)
    else:
        return s.split('.')


def unvis_domainname(s):
    return DomainName(*[Label(vis.strunvis(l)) for l in
        _split_domainname_str(s)])

def fqdn_from_text(s):
    if not s.endswith('.'):
        s = s + '.'
    return domainname_from_text(s)

def domainname_from_text(s):
    return DomainName(*map(Label, _split_domainname_str(s)))

def domainname_from_wire(ws):
    wire_bytes = []
    wire_bytes[:] = reversed(struct.unpack('B'*len(ws), ws))
    labels = []
    try:
        while True:
            n = wire_bytes.pop()
            lbl = []
            for i in xrange(n):
                try:
                    lbl.append(wire_bytes.pop())
                except IndexError:
                    raise InvalidDomainNameError, 'invalid wire format'
            labels.append(lbl)
    except IndexError:
        return DomainName(*[Label(struct.pack('B'*len(lbl), *lbl)) for lbl in
            labels])

def _label_ldh():
    return Label(chr(range_ld[0]))

def _label_binary():
    return Label("\x00")

class Label(object):
    def __init__(self, labelstr):
        if len(labelstr) > MAX_LABEL:
            raise MaxLabelLengthError
        self.label = labelstr
        self._canonicalize()

    def forward_next(self, ldh, extend):
        if ldh:
            return self.forward_next_ldh(extend)
        else:
            return self.forward_next_binary(extend)

    def _extend_labelstr_binary(self, labelstr):
        return labelstr + '\x00'

    def forward_next_binary(self, extend):
        if extend:
            try:
                return Label(self._extend_labelstr_binary(self.label))
            except MaxLabelLengthError:
                pass
        return Label(self._increase_labelstr_binary(self.label))


    def _increase_labelstr_binary(self, labelstr):
        if self.has_max_value(False):
            raise MaxLabelValueError
        s = []
        increased = False
        for i, c in enumerate(reversed(struct.unpack('B'*len(labelstr),
            labelstr))):
            if not increased:
                if c == 0xff:
                    if i == len(labelstr)-1:
                        # end of string and cannot increase more
                        raise MaxLabelValueError
                    c = 0
                    s.append(c)
                else:
                    c += 1
                    s.append(c)
                    increased = True
            else:
                s.append(c)
        return struct.pack('B'*len(s), *reversed(s))

    def _extend_labelstr_ldh(self, labelstr):
        return labelstr + chr(range_ld[0])

    def forward_next_ldh(self, extend):
        if extend:
            try:
                return Label(self._extend_labelstr_ldh(self.label))
            except MaxLabelLengthError:
                pass
        return Label(self._increase_labelstr_ldh(self.label))

    def _range_next(self, rng, c):
        for rc in rng:
            if c < rc:
                return rc
        return -1

    def has_max_value(self, ldh):
        if ldh:
            for i, c in enumerate(self.label):
                if i == 0 or i == len(self.label) - 1:
                    if ord(c) != range_ld[-1]:
                        return False
                else:
                    if ord(c) != range_ldh[-1]:
                        return False
            return True

        else:
            for c in self.label:
                if ord(c) != 0xff:
                    return False
            return True


    def _increase_labelstr_ldh(self, labelstr):
        if self.has_max_value(True):
            raise MaxLabelValueError
        s = []
        increased = False
        for i, c in enumerate(reversed(struct.unpack('B'*len(labelstr),
            labelstr))):
            if not increased:
                if i == 0 or i == len(labelstr)-1:
                    # at beginning or end of string
                    inc = self._range_next(range_ld, c)
                    if inc == -1:
                        # end of range
                        if i == len(labelstr)-1:
                            raise MaxLabelValueError
                        inc = range_ld[0]
                    else:
                        increased = True
                    s.append(inc)
                else:
                    # in the middle
                    inc = self._range_next(range_ldh, c)
                    if inc == -1:
                        inc = range_ldh[0]
                    else:
                        increased = True
                    s.append(inc)
            else:
                s.append(c)

        return struct.pack('B'*len(s), *reversed(s))

    def wire_length(self):
        return 1 + len(self.label)

    def _canonicalize(self):
        # don't use locale-aware lowercase function, we only want 
        # to convert the ASCII characters
        self.label = self.label.translate(ascii_upper_to_lower)

    def to_wire(self):
        # see RFC1035, section 3.1 "Name space definitions" for more info
        blist = []
        blist.append(len(self.label))
        blist[len(blist):] = struct.unpack('B'*len(self.label), self.label)
        return struct.pack('B'*len(blist), *blist)

    def __cmp__(self, other):
        return cmp(self.label, other.label)

    def __str__(self):
        return vis.strvis(self.label)



class DomainName(object):
    def __init__(self, *labels):
        if len(labels) == 0:
            raise InvalidDomainNameError, 'no label specified'
        self.labels = list(labels)
        if self.wire_length() > MAX_DOMAINNAME:
            raise MaxDomainNameLengthError

    def wire_length(self):
        return sum([l.wire_length() for l in self.labels])

    def next_label_add(self, ldh):
        lbls = self.labels[:]
        if ldh:
            return DomainName(_label_ldh(), *lbls)
        else:
            return DomainName(_label_binary(), *lbls)

    def next_extend_increase(self, ldh):
        lbls = self.labels[:]
        increased = False
        newlabels = []
        extend = False
        if MAX_DOMAINNAME > self.wire_length() + 1:
            extend = True
        for label in lbls:
            if not increased:
                try:
                    newlabels.append(label.forward_next(ldh, extend))
                    increased = True
                except (MaxLabelLengthError, MaxLabelValueError):
                    newlabels.append(label)
            else:
                newlabels.append(label)
        if not increased:
            raise MaxDomainNameLengthError, ('cannot increase domain name')
        return DomainName(*newlabels)

    def covered_by(self, owner, next_owner):
        if owner >= next_owner:
            # last NSEC[3] record
            return (self >= owner or self <= next_owner)
        return (self >= owner and self <= next_owner)


    def part_of_zone(self, zone):
        if len(self.labels) >= len(zone.labels):
            for l in zip(reversed(zone.labels), reversed(self.labels)):
                if l[0] != l[1]:
                    return False
            return True
        return False

    def split(self, position):
        first_labels = []
        second_labels = []
        i = 0
        labels = first_labels
        for l in self.labels:
            if i == position:
                labels = second_labels
            labels.append(l)
            i += 1
        return (DomainName(*first_labels), DomainName(*second_labels))


    def __cmp__(self, other):
        s = self.labels[:]
        o = other.labels[:]
        s.reverse()
        o.reverse()
        for i in xrange(0, max((len(s), len(o)))):
            if i >= len(s):
                return -1
            if i >= len(o):
                return 1
            if s[i] < o[i]:
                return -1
            elif s[i] > o[i]:
                return 1
        return 0

    def is_root(self):
        return (len(self.labels) == 1 and self.labels[0].label == "")

    def to_wire(self):
        # see RFC1035, section 3.1 "Name space definitions" for more info
        labellist = []
        for label in self.labels:
            labellist.append(label.to_wire())

        return ''.join(labellist)

    def __str__(self):
        if self.is_root():
            return '.'
        else:
            return '.'.join(str(l) for l in self.labels)

