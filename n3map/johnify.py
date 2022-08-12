import sys
import os

from . import log
from . import rrfile
from . import util
from .exception import N3MapError

def usage(argv):
    sys.stderr.write("usage: " + os.path.basename(argv[0]) + " file [outfile]\n")
    sys.exit(2)

def johnify_main(argv):
    log.logger = log.Logger()
    try:
        if len(argv) < 2:
            usage(argv)
        if len(argv) == 3:
            out = open(argv[2], "w")
        else:
            out = sys.stdout

        records_file = rrfile.open_input_rrfile(argv[1])

        for nsec3 in records_file.nsec3_reader():
            nsec3_hash = util.str_to_hex(nsec3.hashed_owner)
            zone = str(nsec3.zone)
            iterations = "{0:d}".format(nsec3.iterations)
            salt = util.str_to_hex(nsec3.salt)
            out.write("$NSEC3$" + "$".join((iterations, salt,
                nsec3_hash, zone)) + "\n")
    except (IOError, N3MapError) as e:
        log.fatal(e)


def main():
    try:
        sys.exit(johnify_main(sys.argv))
    except KeyboardInterrupt:
        sys.stderr.write("\nreceived SIGINT, terminating\n")
        sys.exit(3)

