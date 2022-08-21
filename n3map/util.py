import string
import struct
import base64

# see RFC4648 for details
# TODO: python3.10 has support for this included: base64.b32hexencode()
b32_to_b32_ext_hex = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                                     b"0123456789ABCDEFGHIJKLMNOPQRSTUV")
b32_ext_hex_to_b32 = bytes.maketrans(b"0123456789ABCDEFGHIJKLMNOPQRSTUV",
                                     b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
def base32_ext_hex_encode(s):
    return base64.b32encode(s).translate(b32_to_b32_ext_hex)

def base32_ext_hex_decode(s):
    return base64.b32decode(s.upper().translate(b32_ext_hex_to_b32))

def str_to_hex(s):
    hex_list = ["{0:02x}".format(b) for b in struct.unpack('B'*len(s), s)]
    return ''.join(hex_list)

def printsafe(s):
    return ''.join(map(lambda c: c if c.isprintable() else '\uFFFD', s))


