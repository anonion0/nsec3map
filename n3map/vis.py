
import string
import struct

hex_chars = "0123456789abcdefABCDEF"

def vis(char):
    """ Returns True if a character is safe to print
    
    char:    the character to test
    
    """
    return (chr(char) in string.printable)


def strvis(s):
    """Encode a string so it is safe to print on a tty

    s:    the string to encode

    """
    enc_str = []
    chars = struct.unpack('B' * len(s), s)
    for c in chars:
        if vis(c):
            enc_str.append(struct.pack('B', c))
            if c == struct.unpack('B','\\')[0]:
                enc_str.append('\\')
        else:
            enc_str.append("\\x{0:02x}".format(c))
    return ''.join(enc_str)


def strunvis(s):
    """Decode a strvis-encoded string

    s:    the string to decode

    """
    i = 0
    d_s = []
    push = None
    while i < len(s):
        if push is not None:
            push = push + s[i]
            if push == '\\\\':
                d_s.append('\\')
                push = None
            elif len(push) == 4:
                if push[:2] == '\\x' and all([c in hex_chars for c in
                    push[2:]]):
                    d_s.append(chr(int(push[2:], 16)))
                    push = None
                else:
                    raise ValueError
        elif s[i] == '\\':
            push = '\\'
        else:
            d_s.append(s[i])
        i += 1
    
    if push is not None:
        raise ValueError

    return ''.join(d_s)

