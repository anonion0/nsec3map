import getopt
import multiprocessing
import re
import sys
import os
import time
from datetime import timedelta

from . import log
from . import prehash
from . import queryprovider
from .query import query_ns_records
from . import rrfile
from .exception import N3MapError, FileParseError, HashLimitReached
from .nsec3walker import NSEC3Walker
from .predict import create_zone_predictor
from .nsecwalker import NSECWalkerN, NSECWalkerMixed, NSECWalkerA

import n3map.name
import n3map.walker

def _def_num_of_processes():
    try:
        ncpus = multiprocessing.cpu_count()
    except NotImplementedError:
        log.error("could not detect number of cpus.")
        ncpus = 1

    if ncpus > 1:
        return ncpus - 1
    return 1

def _compute_query_interval(n, unit):
    units = { 's': 1.0, 'm' : 60.0, 'h': 3600.0 }
    return units[unit]/n

def _query_interval(s):
    p = re.compile('^(([0-9]\.|[1-9][0-9]*[.]?)[0-9]*)/([smh])$')
    m = p.match(s)
    if m is None:
        raise ValueError
    try:
        return _compute_query_interval(n=float(m.group(1)), unit=m.group(3))
    except ZeroDivisionError:
        raise ValueError


def check_part_of_zone(rr, zone):
    if not rr.part_of_zone(zone):
        raise N3MapError(("not all read records are part of the specified zone"))

def get_nameservers(zone, ipproto='', ns_names=None):
    if ns_names is not None:
        return queryprovider.nameserver_from_text(ipproto, *ns_names)

    ns_names = query_ns_records(zone)
    nslist = queryprovider.nameserver_from_text(ipproto, *ns_names,
                                                ignore_unresolved=True)
    for ns in nslist:
        log.info("using nameserver: ", str(ns))
    return nslist

def read_input_file(input_filename, cont, zone, zone_type):
    chain = None
    records_file = None
    label_counter = None
    try:
        records_file = rrfile.open_input_rrfile(input_filename)
    except FileNotFoundError as e:
        if cont:
            log.info('zone file {} does not exist yet, creating it'
                    .format(input_filename))
            return (None, None)
        else:
            log.fatal("unable to open input file: \n", str(e))
    try:
        chain = []
        if zone_type == 'nsec3':
            for rr in records_file.nsec3_reader():
                check_part_of_zone(rr, zone)
                chain.append(rr)
            label_counter = records_file.label_counter
        elif zone_type == 'nsec':
            for rr in records_file.nsec_reader():
                check_part_of_zone(rr, zone)
                chain.append(rr)
    except IOError as e:
        log.fatal("unable to read input file: \n", str(e))
    except FileParseError as e:
        log.fatal("unable to parse input file: \n", str(e))
    finally:
        if records_file is not None:
            records_file.close()
    if cont:
        try:
            records_file.into_backup()
        except OSError as e:
            log.fatal("failed to create backup file: \n", str(e))
    return (chain, label_counter)



def n3map_main(argv):
    log.logger = log.Logger()
    try:
        (options, ns_names, zone) = parse_arguments(argv)
    except N3MapError as e:
        log.fatal_exit(2, e)

    output_rrfile = None
    chain = None
    label_counter = None
    walker = None
    process_pool = None
    hash_queues = None
    if options['progress']:
        log.logger = log.ProgressLineLogger.from_logger(log.logger)

    log.info("n3map {}: starting mapping of {}".format(
        n3map.__version__, str(zone)))

    try:
        nslist = get_nameservers(zone, options['ipproto'], ns_names)
        stats = {}
        options['timeout'] /= 1000.0
        qprovider = queryprovider.QueryProvider(nslist,
                timeout=options['timeout'], max_retries=options['max_retries'],
                max_errors=options['max_errors'],
                query_interval = options['query_interval'], stats=stats)

        if options['soa_check']:
            n3map.walker.check_soa(zone, qprovider)

        if options['dnskey_check']:
            n3map.walker.check_dnskey(zone, qprovider)

        if options['zone_type'] == 'auto':
            options['zone_type'] = n3map.walker.detect_dnssec_type(zone,
                    qprovider, options['detection_attempts'])

        if options['zone_type'] == 'nsec3':
            (hash_queues, process_pool) = prehash.create_prehash_pool(
                options['processes'], options['queue_element_size'],
                options['use_openssl'])
            if options['predict']:
                proc,pipe = create_zone_predictor()
                predictor = (proc,pipe)
            else:
                predictor = None


        if options['continue'] is not None:
            chain, label_counter = read_input_file(options['continue'], True,
                    zone, options['zone_type'])
            try:
                output_rrfile =  rrfile.open_output_rrfile(options['continue'])
            except IOError as e:
                log.fatal("unable to open output file: ", str(e))
        else:
            if options['input'] is not None:
                chain, label_counter = read_input_file(options['input'], False,
                        zone, options['zone_type'])
            if options['output'] is not None:
                if options['output'] == '-':
                    output_rrfile = rrfile.RRFileStream(sys.stdout)
                else:
                    try:
                        output_rrfile =  rrfile.open_output_rrfile(
                                options['output'])
                    except IOError as e:
                        log.fatal("unable to open output file: ", str(e))



        if options['zone_type'] == 'nsec3':
            if output_rrfile is not None:
                output_rrfile.write_header(zone, "List of NSEC3 RRs")
            if options['label_counter'] is not None:
                label_counter = options['label_counter']
            walker = NSEC3Walker(zone,
                                 qprovider,
                                 hash_queues,
                                 process_pool,
                                 nsec3_records=[] if chain is None else chain,
                                 ignore_overlapping=options['ignore_overlapping'],
                                 label_counter=label_counter,
                                 output_file=output_rrfile,
                                 stats=stats,
                                 predictor=predictor,
                                 aggressive=options['aggressive'],
                                 hashlimit=options['hashlimit']
                                 )

        elif options['zone_type'] == 'nsec':
            if output_rrfile is not None:
                output_rrfile.write_header(zone, "List of NSEC RRs")

            if options['query_mode'] == "mixed":
                walker = NSECWalkerMixed(zone,
                                         qprovider,
                                         options['query_chars'] == 'ldh',
                                         nsec_chain=chain,
                                         startname=options['start'],
                                         endname=options['end'],
                                         stats=stats,
                                         output_file=output_rrfile)
            elif options['query_mode'] == "A":
                walker = NSECWalkerA(zone,
                                     qprovider,
                                     options['query_chars'] == 'ldh',
                                     nsec_chain=chain,
                                     startname=options['start'],
                                     endname=options['end'],
                                     stats=stats,
                                     output_file=output_rrfile)
            else:
                walker = NSECWalkerN(zone,
                                     qprovider,
                                     nsec_chain=chain,
                                     startname=options['start'],
                                     endname=options['end'],
                                     stats=stats,
                                     output_file=output_rrfile)
        finished = False
        if walker is not None:
            starttime = time.monotonic()
            stopped_prematurely = False
            try:
                walker.walk()
            except HashLimitReached:
                stopped_prematurely = True
            elapsed = timedelta(seconds=time.monotonic() - starttime)
            if stopped_prematurely:
                log.info("stopped mapping of {0:s} after {1:s}: hashlimit reached"
                         .format( str(zone), str(elapsed)))
            else:
                log.info("finished mapping of {0:s} in {1:s}"
                         .format( str(zone), str(elapsed)))
            finished = True

        if output_rrfile is not None:
            output_rrfile.write_stats(stats)
            if finished and options['continue'] is not None:
                output_rrfile.unlink_backup()

    except N3MapError as e:
        log.fatal(e)
    except IOError as e:
        log.fatal(str(e))
    finally:
        if output_rrfile is not None:
            output_rrfile.close()
    return 0

def default_options():
    opts = {
            'zone_type' : 'auto',
            'output': None,
            'input' : None,
            'continue' : None,
            'aggressive' : 0,
            'ignore_overlapping' : False,
            'query_mode' : 'mixed',
            'query_chars' : 'binary',
            'start' : None,
            'end' : None,
            'label_counter' : None,
            'hashlimit' : 0,
            'timeout' : 2500,
            'max_retries' : 5,
            'max_errors' : 1,
            'query_interval' : None,
            'detection_attempts' : 5,
            'soa_check' : True,
            'dnskey_check' : True,
            'predict' : False,
            'processes' : _def_num_of_processes(),
            'progress' : True,
            'queue_element_size' : 256,
            'use_openssl' : True,
            'ipproto' : '',
            }
    return opts

def invalid_argument(opt, arg):
    log.fatal_exit(2, "invalid " + opt + " argnument `" + str(arg) + "'")

def parse_arguments(argv):
    long_opts = [
            'aggressive=',
            'auto',
            'binary',
            'continue=',
            'end=',
            'help',
            'ignore-overlapping',
            'input=',
            'label-counter=',
            'hashlimit=',
            'ldh',
            'limit-rate=',
            'max-retries=',
            'max-errors=',
            'mixed',
            'nsec',
            'nsec3',
            'omit-soa-check',
            'omit-dnskey-check',
            'detection-attempts=',
            'output=',
            'predict',
            'processes=',
            'query-mode=',
            'queue-element-size=',
            'quiet',
            'start=',
            'timeout=',
            'no-openssl',
            'verbose',
            'color=',
            'version'
    ]
    options = default_options()
    opts = '346AMNabc:e:f:hi:lm:no:pqs:v'
    try:
        opts, args = getopt.gnu_getopt(argv[1:], opts, long_opts)
    except getopt.GetoptError as err:
        log.fatal_exit(2, err, "\n", "Try `",
                str(os.path.basename(argv[0])),
                " --help' for more information.")

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(os.path.basename(argv[0]))
            sys.exit(0)

        elif opt in ('-a' '--auto'):
            options['zone_type'] = 'auto'

        elif opt in ('-n', '--nsec'):
            options['zone_type'] = 'nsec'

        elif opt in ('-3', '--nsec3'):
            options['zone_type'] = 'nsec3'

        elif opt in ('-4',):
            options['ipproto'] = 'ipv4'

        elif opt in ('-6',):
            options['ipproto'] = 'ipv6'

        elif opt in ('-c', '--continue'):
            options['continue'] = arg

        elif opt in ('-i', '--input'):
            options['input'] = arg

        elif opt in ('-o', '--output'):
            options['output'] = arg

        elif opt in ('--label-counter',):
            try:
                options['label_counter'] = int(arg, 0)
            except ValueError:
                invalid_argument(opt, arg)
            if options['label_counter']  < 0:
                invalid_argument(opt, arg)

        elif opt in ('--hashlimit',):
            try:
                options['hashlimit'] = int(arg)
            except ValueError:
                invalid_argument(opt, arg)
            if options['hashlimit'] < 0:
                invalid_argument(opt, arg)

        elif opt in ('--ignore-overlapping',):
            options['ignore_overlapping'] = True

        elif opt in ('-m', '--query-mode'):
            if arg not in ('mixed', 'NSEC', 'A'):
                invalid_argument(opt, arg)
            options['query_mode'] = arg

        elif opt in ('-M', '--mixed'):
            options['query_mode']  = 'mixed'

        elif opt in ('-A',):
            options['query_mode']  = 'A'

        elif opt in ('-N',):
            options['query_mode']  = 'NSEC'

        elif opt in ('-l', '--ldh'):
            options['query_chars'] = 'ldh'

        elif opt in ('-b', '--binary'):
            options['query_chars'] = 'binary'

        elif opt in ('-e', '--end'):
            options['end'] = arg

        elif opt in ('--limit-rate',):
            try:
                options['query_interval'] = _query_interval(arg)
            except ValueError:
                invalid_argument(opt, arg)

        elif opt in ('--max-retries',):
            try:
                options['max_retries'] = int(arg)
            except ValueError:
                invalid_argument(opt, arg)
            if options['max_retries'] < -1:
                invalid_argument(opt, arg)

        elif opt in ('--max-errors',):
            try:
                options['max_errors'] = int(arg)
            except ValueError:
                invalid_argument(opt, arg)
            if options['max_errors'] < -1:
                invalid_argument(opt, arg)

        elif opt in ('--detection-attempts',):
            try:
                options['detection_attempts'] = int(arg)
            except ValueError:
                invalid_argument(opt, arg)
            if options['detection_attempts'] < 0:
                invalid_argument(opt, arg)


        elif opt in ('--omit-soa-check',):
            options['soa_check'] = False

        elif opt in ('--omit-dnskey-check',):
            options['dnskey_check'] = False

        elif opt in ('-f', '--aggressive',):
            try:
                options['aggressive'] = int(arg)
            except ValueError:
                invalid_argument(opt, arg)
            if options['aggressive'] < 1:
                invalid_argument(opt, arg)

        elif opt in ('-p', '--predict',):
            options['predict'] = True

        elif opt in ('--processes',):
            try:
                options['processes'] = int(arg)
            except ValueError:
                invalid_argument(opt, arg)
            if options['processes'] < 1:
                invalid_argument(opt, arg)


        elif opt in ('--queue-element-size',):
            try:
                options['queue_element_size'] = int(arg)
            except ValueError:
                invalid_argument(opt, arg)
            if options['queue_element_size']  < 1:
                invalid_argument(opt, arg)

        elif opt in ('-q', '--quiet'):
            options['progress'] = False

        elif opt in ('-s', '--start'):
            options['start'] = arg

        elif opt in ('--timeout',):
            try:
                options['timeout'] = int(arg)
            except ValueError:
                invalid_argument(opt, arg)
            if options['timeout']  < 1:
                invalid_argument(opt, arg)

        elif opt in ('--no-openssl',):
            options['use_openssl'] = False

        elif opt in ('-v', '--verbose'):
            log.logger.loglevel += 1

        elif opt in ('--color',):
            try:
                log.logger.set_colors(arg)
            except ValueError:
                invalid_argument(opt, arg)

        elif opt in ('--version'):
            version()
            sys.exit(0)

        else:
            invalid_argument(opt, "")

    if len(args) < 1:
        log.fatal_exit(2, 'missing arguments', "\n", "Try `",
                str(os.path.basename(argv[0])),
                " --help' for more information.")
    else:
        zone = n3map.name.fqdn_from_text(args[-1])
        if len(args) >= 2:
            ns_names = args[:-1]
        else:
            ns_names = None

    if options['continue'] is not None and (options['input'] is not None or
            options['output'] is not None):
        log.fatal_exit(2, 'Invalid arguments: use -c xor (-i or -o)')

    return (options, ns_names, zone)

def version():
    sys.stdout.write("nsec3map " + n3map.__version__ + "\n")


def usage(program_name):
    def_opts = default_options()
    sys.stdout.write(
            'Usage: {0:s} [option]... [-o file] [nameserver[:port]]... zone'
            .format(program_name))
    sys.stdout.write(
'''
Enumerate a DNSSEC signed zone based on NSEC or NSEC3 resource records

Options:
      --version              show program's version number and exit
  -h, --help                 show this help message and exit
  -v, --verbose              increase verbosity level (use multiple times for
                               greater effect)
      --color=WHEN           colorize output; WHEN can be 'auto' (default),
                               'always' or 'never'.

Enumeration:
  -a, --auto                 autodetect enumeration method (default)
  -3, --nsec3                use NSEC3 enumeration
  -n, --nsec                 use NSEC enumeration
  -o, --output=FILE          write all records to FILE (use '-' for stdout)
  -i, --input=FILE           read records from FILE and continue
                               the enumeration.
  -c, --continue=FILE        same as -i FILE -o FILE, but will preserve FILE as
                               a backup file until the enumeration is finished.
                               Will create FILE if it does not exist yet.

NSEC Options:
  -m, --query-mode=MODE      sets the query mode. Possible values are
                               'mixed', 'A', and 'NSEC' (default {qmode:s})
  -M, --mixed                shortcut for --query-mode=mixed
  -A                         shortcut for --query-mode=A
  -N                         shortcut for --query-mode=NSEC
  -b, --binary               use all possible binary values in queries (default)
  -l, --ldh                  use only lowercase characters, digits and hyphen in
                               queries
  -s, --start=DOMAIN
  -e, --end=DOMAIN           use DOMAIN as the enumeration start-/endpoint.
                               DOMAIN is relative to the zone name.

NSEC3 Options:
  -f, --aggressive=N         send up to N queries in parallel. This may speed
                               up the enumeration significantly if the DNS
                               server's round-trip time is high. However, it will
                               also cause n3map to make more queries than usual
                               because it cannot completely avoid queries which
                               resolve to the same NSEC3 records.
                               Use with caution.
      --ignore-overlapping   ignore overlapping NSEC3 records. Useful when
                               enumerating large zones that may change during
                               enumeration.
  -p, --predict              try to predict the size of the zone based on the
                               records already received. Note that this option
                               might slow down the enumeration process
                               (experimental)
      --processes=N          defines the number of pre-hashing processes.
                               Default is 1 or the number of CPUs - 1 on
                               multiprocessor systems ({processes:d} on this system)
      --hashlimit=N          stop the enumeration after checking N hashes, even
                               if it is not finished. Default = 0 (unlimited).

Advanced NSEC3 Options:
  Use with caution.
      --label-counter=N      set the initial label counter
      --queue-element-size=N set the queue elment size. (default {queue_element_sz:d})
      --no-openssl           do not use openssl for hashing (slower)

General Options:
  -q, --quiet                do not display progress information during enumeration
      --limit-rate=N{{/s|/m|/h}}
                             limit the query rate (default = unlimited)
      --max-retries=N        limit the maximum number of retries when a DNS query
                               times out. Defaults to {max_retries:d}.
                               N=-1 means no limit.
      --max-errors=N         limit the maximum number of consecutive
                               errors/wrongful responses a DNS server may
                               return. Defaults to {max_errors:d}.
                               N=-1 means no limit (use with extreme caution).
      --timeout=N            timeout to wait for a server response,
                               in miliseconds (default {timeout:d})
      --detection-attempts=N limit the maximum number of zone type (NSEC/NSEC3)
                               detection attempts. N=0 specifies no limit.
                               (default {detection_attempts:d})
      --omit-soa-check       don't check the SOA record of the zone
                               before starting enumeration (use with caution).
      --omit-dnskey-check    don't check the DNSKEY record of the zone
                               before starting enumeration (use with caution).
      -4                     Use IPv4 only.
      -6                     Use IPv6 only.
'''.format(qmode=def_opts['query_mode'], processes=def_opts['processes'],
        queue_element_sz=def_opts['queue_element_size'],
        timeout=def_opts['timeout'], max_retries=def_opts['max_retries'],
        max_errors=def_opts['max_errors'],
        detection_attempts=def_opts['detection_attempts'])
    )

def main():
    try:
        sys.exit(n3map_main(sys.argv))
    except KeyboardInterrupt:
        sys.stderr.write("\nreceived SIGINT, terminating\n")
        sys.exit(3)

