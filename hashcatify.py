#!/usr/bin/env python

import sys
import os

from n3map import log
from n3map import rrfile
from n3map import util
from n3map.exception import N3MapError

def usage(argv):
    sys.stderr.write("usage: " + os.path.basename(argv[0]) + " file [outfile]\n")
    sys.exit(2)

def main(argv):
    log.logger = log.Logger()
    try:
        if len(argv) < 2:
            usage(argv)
        if len(argv) == 3:
            out = open(argv[2], "wb")
        else:
            out = sys.stdout

        records_file = rrfile.open_input_rrfile(argv[1])

        for nsec3 in records_file.nsec3_reader():
            nsec3_hash = util.base32_ext_hex_encode(nsec3.hashed_owner).lower()
            zone = str(nsec3.zone)
            iterations = "{0:d}".format(nsec3.iterations)
            salt = util.str_to_hex(nsec3.salt)
            out.write(":".join((nsec3_hash, "." + zone, salt, iterations)) 
                    + "\n")
    except (IOError, N3MapError), e:
        log.fatal(e)


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.stderr.write("\nreceived SIGINT, terminating\n")
        sys.exit(3)

