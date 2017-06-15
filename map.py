#!/usr/bin/env python

import getopt
import multiprocessing
import re
import sys
import os
import time
from datetime import timedelta


from n3map import log
from n3map import prehash
from n3map import queryprovider
from n3map.query import query_ns_records
from n3map import rrfile
from n3map.exception import N3MapError, FileParseError
from n3map.nsec3walker import NSEC3Walker
from n3map.predict import create_zone_predictor
from n3map.nsecwalker import NSECWalkerN, NSECWalkerMixed, NSECWalkerA
import n3map.name
import n3map.walker
import n3map.version


def _compute_query_interval(n, unit):
    units = { 's': 1.0, 'm' : 60.0, 'h': 3600.0 }
    return units[unit]/n

def _def_num_of_processes():
    try:
        ncpus = multiprocessing.cpu_count()
    except NotImplementedError:
        log.error("could not detect number of cpus.")
        ncpus = 1

    if ncpus > 1:
        return ncpus - 1
    return 1

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
        raise N3MapError, ("not all read records are part of the specified zone")

        
def main(argv):
    log.logger = log.Logger()
    try:
        (options, nslist, zone) = parse_arguments(argv)
    except N3MapError, e:
        log.fatal_exit(2, e)
    output_rrfile = None
    chain = None
    label_counter = None
    walker = None
    process_pool = None
    hash_queues = None
    if options['progress']:
        loglevel = log.logger.loglevel
        log.logger = log.ProgressLineLogger()
        log.logger.loglevel = loglevel

    try:
        stats = {}
        options['timeout'] /= 1000.0
        qprovider = queryprovider.QueryProvider(nslist,
                timeout=options['timeout'], max_retries=options['max_retries'], 
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


        if options['input'] is not None:
            records_file = None
            try:
                records_file = rrfile.open_input_rrfile(options['input'])
                chain = []
                if options['zone_type'] == 'nsec3':
                    for rr in records_file.nsec3_reader():
                        check_part_of_zone(rr, zone)
                        chain.append(rr)
                    label_counter = records_file.label_counter
                elif options['zone_type'] == 'nsec':
                    for rr in records_file.nsec_reader():
                        check_part_of_zone(rr, zone)
                        chain.append(rr)
            except IOError, e:
                log.fatal("unable to read input file: \n", str(e))
            except FileParseError, e:
                log.fatal("unable to parse input file: \n", str(e))
            finally:
                if records_file is not None:
                    records_file.close()
                    records_file = None

        if options['output'] is not None:
            if options['output'] == '-':
                output_rrfile = rrfile.RRFile(sys.stdout)
            else:
                try:
                    output_rrfile =  rrfile.open_output_rrfile(options['output'])
                except IOError, e:
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
                                 aggressive=options['aggressive'])

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

        if walker is not None:
            starttime = time.time()
            walker.walk()
            elapsed = timedelta(seconds=time.time() - starttime)
            log.info("finished mapping of {0:s} in {1:s}".format( str(zone), str(elapsed)))
        

        if output_rrfile is not None:
            output_rrfile.write_stats(stats)
            
    except N3MapError, e:
        log.fatal(e)
    except IOError, e:
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
            'aggressive' : 0,
            'ignore_overlapping' : False,
            'query_mode' : 'mixed',
            'query_chars' : 'binary',
            'start' : None,
            'end' : None,
            'label_counter' : None,
            'timeout' : 2500,
            'max_retries' : 5,
            'query_interval' : None,
            'detection_attempts' : 5,
            'soa_check' : True,
            'dnskey_check' : True,
            'predict' : False,
            'processes' : _def_num_of_processes(),
            'progress' : True,
            'queue_element_size' : 256,
            'use_openssl' : True
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
            'ldh',
            'limit-rate=',
            'max-retries=',
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
            'version'
    ]
    options = default_options()
    opts = '3AMNabc:e:f:hi:lm:no:pqs:v'
    try:
        opts, args = getopt.gnu_getopt(argv[1:], opts, long_opts)
    except getopt.GetoptError, err:
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

        elif opt in ('-c', '--continue'):
            options['input'] = options['output'] = arg

        elif opt in ('-i', '--input'):
            options['input'] = arg

        elif opt in ('-o', '--output'):
            options['output'] = arg

        elif opt in ('--label-counter',):
            try:
                options['label_counter'] = long(arg, 0)
            except ValueError:
                invalid_argument(opt, arg)
            if options['label_counter']  < 0:
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
            nslist = queryprovider.nameserver_from_text(*ns_names)
        else:
            ns_names = query_ns_records(zone)
            nslist = queryprovider.nameserver_from_text(*ns_names)
            for ns in nslist:
                log.info("using nameserver: ", str(ns))

    return (options, nslist, zone)

def version():
    sys.stdout.write("nsec3map " + n3map.version.version_str() + "\n")


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

Enumeration:
  -a, --auto                 autodetect enumeration method (default)
  -3, --nsec3                use NSEC3 enumeration
  -n, --nsec                 use NSEC enumeration
  -o, --output=FILE          write all records to FILE (use '-' for stdout)
  -i, --input=FILE           read records from FILE and continue 
                               the enumeration.
  -c, --continue=FILE        shortcut for --input FILE --output FILE

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
                               servers round-trip time is high. However, it will
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
                               fails. N=-1 means no limit. (default {max_retries:d})
      --timeout=N            timeout to wait for a server response, 
                               in miliseconds (default {timeout:d})
      --detection-attempts=N limit the maximum number of zone type (NSEC/NSEC3)
                               detection attempts. N=0 specifies no limit.
                               (default {detection_attempts:d})
      --omit-soa-check       don't check the SOA record of the zone 
                               before starting enumeration (use with caution).
      --omit-dnskey-check    don't check the DNSKEY record of the zone 
                               before starting enumeration (use with caution).
'''.format(qmode=def_opts['query_mode'], processes=def_opts['processes'],
        queue_element_sz=def_opts['queue_element_size'],
        timeout=def_opts['timeout'], max_retries=def_opts['max_retries'],
        detection_attempts=def_opts['detection_attempts'])
    )

import cProfile
if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        sys.stderr.write("\nreceived SIGINT, terminating\n")
        sys.exit(3)

