import string
import struct
import base64

# see RFC4648 for details
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

def hex_to_str(s):
    bytes_list = []
    push = None
    for c in s:
        if push is not None:
            push = push + c
            if len(push) == 2:
                bytes_list.append(int(push, 16))
                push = None
        else:
            push = c
    if push is not None:
        raise ValueError

    return struct.pack('B'*len(bytes_list), *bytes_list)
