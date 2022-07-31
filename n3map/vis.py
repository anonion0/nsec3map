
import string
import struct

hex_chars = b"0123456789abcdefABCDEF"

ascii_printable = string.printable.encode("ascii")

def vis(char):
    """ Returns True if a character is safe to print

    char:    the character to test

    """
    return char in ascii_printable

def strvis(s):
    """Encode a string so it is safe to print on a tty

    s:    the string to encode

    """
    enc_str = []
    chars = struct.unpack('B' * len(s), s)
    for c in chars:
        if vis(c):
            enc_str.append(struct.pack('B', c))
            if c == struct.unpack('B', b'\\')[0]:
                enc_str.append(b'\\')
        else:
            enc_str.append(b"\\x%02x" % c)
    return b''.join(enc_str)


def strunvis(s):
    """Decode a strvis-encoded string

    s:    the string to decode

    """
    i = 0
    d_s = []
    push = None
    while i < len(s):
        if push is not None:
            push = push + bytes([s[i]])
            if push == b'\\\\':
                d_s.append(b'\\')
                push = None
            elif len(push) == 4:
                if push[:2] == b'\\x' and all([c in hex_chars for c in
                    push[2:]]):
                    d_s.append(bytes([int(push[2:], 16)]))
                    push = None
                else:
                    raise ValueError
        elif bytes([s[i]]) == b'\\':
            push = b'\\'
        else:
            d_s.append(bytes([s[i]]))
        i += 1

    if push is not None:
        raise ValueError

    return b''.join(d_s)

