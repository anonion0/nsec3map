import string
import struct
import functools

from . import vis
from .exception import (
        InvalidDomainNameError,
        MaxDomainNameLengthError,
        MaxLabelLengthError,
        MaxLabelValueError
    )

# see RFC1035, section 2.3.4 "Size limits" for details
MAX_LABEL = 63
# for wire format:
MAX_DOMAINNAME = 255

range_ld = b"0123456789abcdefghijklmnopqrstuvwxyz"
range_ldh = b"-0123456789abcdefghijklmnopqrstuvwxyz"

def hex_label(l):
    return b"%x" % l

#def binary_label(l: int):
#    return l.to_bytes((l.bit_length() + 7) // 8, 'big')

## XXX: much slower than hex_label
#def b32_label(l: int):
#     return base64.b32encode(l.to_bytes((l.bit_length() + 7) // 8,
#         'big')).rstrip(b'=')

def label_generator(label_fun, init=0):
    l = init
    while True:
        lblstr = label_fun(l)
        yield (Label(lblstr), l)
        l += 1

def _split_domainname_str(s):
    if s == b'.':
        return (b"",)
    else:
        return s.split(b'.')


def unvis_domainname(s):
    return DomainName(*[Label(vis.strunvis(l)) for l in
        _split_domainname_str(s)])

def fqdn_from_text(s):
    if not s.endswith('.'):
        s = s + '.'
    return domainname_from_text(s)

def domainname_from_text(s):
    try:
        bstr = s.encode('ascii')
        return DomainName(*list(map(Label, _split_domainname_str(bstr))))
    except UnicodeError:
        raise InvalidDomainNameError('invalid encoding')

def domainname_from_wire(ws):
    wire_bytes = []
    wire_bytes[:] = reversed(struct.unpack('B'*len(ws), ws))
    labels = []
    try:
        while True:
            n = wire_bytes.pop()
            lbl = []
            for i in range(n):
                try:
                    lbl.append(wire_bytes.pop())
                except IndexError:
                    raise InvalidDomainNameError('invalid wire format')
            labels.append(lbl)
    except IndexError:
        return DomainName(*[Label(struct.pack('B'*len(lbl), *lbl)) for lbl in
            labels])

def _label_ldh():
    return Label(range_ld[0:1])

def _label_binary():
    return Label(b"\x00")

@functools.total_ordering
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
        return labelstr + b'\x00'

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
        return labelstr + range_ld[0:1]

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
                    if c != range_ld[-1]:
                        return False
                else:
                    if c != range_ldh[-1]:
                        return False
            return True

        else:
            for c in self.label:
                if c != 0xff:
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
        # since label is a bytes object, this will only convert ASCII characters
        self.label = self.label.lower()

    def to_wire(self):
        # see RFC1035, section 3.1 "Name space definitions" for more info
        return bytes([len(self.label)]) + self.label

    def __lt__(self, other):
        return self.label < other.label

    def __eq__(self, other):
        return self.label == other.label

    def __str__(self):
        return vis.strvis(self.label).decode("ascii")


@functools.total_ordering
class DomainName(object):
    def __init__(self, *labels):
        if len(labels) == 0:
            raise InvalidDomainNameError('no label specified')
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
            raise MaxDomainNameLengthError(('cannot increase domain name'))
        return DomainName(*newlabels)

    def covered_by(self, owner, next_owner):
        if owner >= next_owner:
            # last NSEC[3] record
            return (self >= owner or self <= next_owner)
        return (self >= owner and self <= next_owner)

    def covered_by_exclusive(self, owner, next_owner):
        if owner >= next_owner:
            return (self > owner or self < next_owner)
        return (self > owner and self < next_owner)


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

    def __lt__(self, other):
        s = self.labels[:]
        o = other.labels[:]
        s.reverse()
        o.reverse()
        for i in range(0, max((len(s), len(o)))):
            if i >= len(s):
                return True
            if i >= len(o):
                return False
            if s[i] < o[i]:
                return True
            elif s[i] > o[i]:
                return False
        return False

    def __eq__(self, other):
        s = self.labels[:]
        o = other.labels[:]
        s.reverse()
        o.reverse()
        for i in range(0, max((len(s), len(o)))):
            if i >= len(s):
                return False
            if i >= len(o):
                return False
            if s[i] != o[i]:
                return False
        return True

    def is_root(self):
        return (len(self.labels) == 1 and self.labels[0].label == b"")

    def to_wire(self):
        # see RFC1035, section 3.1 "Name space definitions" for more info
        wirelabels = bytearray()
        for label in self.labels:
            wirelabels += label.to_wire()
        return bytes(wirelabels)

    def __str__(self):
        if self.is_root():
            return '.'
        else:
            return '.'.join(str(l) for l in self.labels)

