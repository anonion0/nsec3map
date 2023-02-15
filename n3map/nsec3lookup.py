import sys
import os
import getopt

from . import log
from . import rrfile
from . import rrtypes
from .exception import N3MapError, ZoneChangedError
import n3map.name

stats = {'queries': 0,
         'found' : 0}

def usage(argv):
    sys.stderr.write("usage: " + os.path.basename(argv[0]) + " file [-o outfile] [-z zone] [-v]\n")
    sys.exit(2)

def lookup_nsec3(nsec3_chain, salt, iterations,  zone, line, out):
    line = line.rstrip()
    if zone is None:
        dn = n3map.name.fqdn_from_text(line)
    else:
        if line == "":
            dn = zone
        else:
            owner = n3map.name.domainname_from_text(line)
            dn = n3map.name.DomainName(*(owner.labels + zone.labels))
    stats['queries'] += 1
    try:
        rr =  nsec3_chain[rrtypes.nsec3.compute_hash(dn, salt, iterations)]
    except KeyError:
        return;
    out.write(str(dn) + ": " + str(rr) + "\n")
    stats['found'] += 1


def nsec3lookup_main(argv):
    log.logger = log.Logger()
    out = None
    zone = None
    try:
        nsec3_chain = {}
        try:
            opts, args = getopt.gnu_getopt(argv[1:], "z:o:v")
        except getopt.GetoptError as err:
            usage(argv)
        for opt, arg in opts:
            if opt == '-z':
                zone = n3map.name.fqdn_from_text(arg)
            if opt == '-o':
                out = open(arg, "w")
            if opt == '-v':
                log.logger.loglevel += 1

        if out is None:
            out = sys.stdout

        if len(args) < 1:
            usage(argv)

        records_file = rrfile.open_input_rrfile(args[0])
        salt = None
        iterations = None
        for nsec3 in records_file.nsec3_reader():
            if salt == None or iterations == None:
                salt = nsec3.salt
                iterations = nsec3.iterations
            elif salt != nsec3.salt or iterations != nsec3.iterations:
                raise ZoneChangedError("zone salt or iterations not unique!")
            nsec3_chain[nsec3.hashed_owner] = nsec3;
        records_file.close()
        log.info("read {0:d} records. ready for input!".format(len(nsec3_chain)))

        if len(nsec3_chain) == 0:
            return 0
        if sys.stdin.isatty():
            try:
                while True:
                    line = input()
                    lookup_nsec3(nsec3_chain, salt, iterations, zone, line, out)
            except (EOFError) as e:
                pass
        else:
            for line in sys.stdin:
                lookup_nsec3(nsec3_chain, salt, iterations, zone, line, out)

        log.info( "queries total = {0:d}\nhits = {1:d}".format(
            stats['queries'], stats['found']))

    except (IOError, N3MapError) as e:
        log.fatal(e)
    finally:
        if out is not None:
            out.close()

def main():
    try:
        sys.exit(nsec3lookup_main(sys.argv))
    except KeyboardInterrupt:
        sys.stderr.write("\nreceived SIGINT, terminating\n")
        sys.exit(3)

