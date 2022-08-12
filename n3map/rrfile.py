import re
import gzip
import bz2
import os

from . import log
from .rrtypes import nsec
from .rrtypes import nsec3
from . import rrtypes
from .exception import (
        FileParseError,
        MaxDomainNameLengthError,
        MaxLabelLengthError,
        NSECError,
        NSEC3Error,
        ParseError
    )

_comment_pattern = r'^\s*([;#].*)?$'

def _open(filename, mode):
    if filename.endswith(".gz"):
        return gzip.open(filename, mode, encoding="utf-8")
    elif filename.endswith(".bz2"):
        return bz2.BZ2File(filename, mode, encoding="utf-8")
    return open(filename, mode, encoding="utf-8")



def open_output_rrfile(filename):
    return RRFile(_open(filename, "w+"), filename)

def open_input_rrfile(filename):
    return RRFile(_open(filename, "r"), filename)

class RRFile(object):
    def __init__(self, f, fname):
        self.f = f
        self.filename = fname
        self.label_counter = None

    def close(self):
        if self.f is not None:
            if self.f.writable():
                # ensure data is written to disk before we try to delete the
                # backup file
                self.f.flush()
                os.fsync(self.f.fileno())
            self.f.close()
            self.f = None

    def _backup_filename(self):
        return self.filename + '~'

    def unlink_backup(self):
        try:
            os.unlink(self._backup_filename())
        except OSError as e:
            log.debug2("failed to unlink backup file: \n", str(e))

    def into_backup(self):
        os.replace(self.filename, self._backup_filename())

    def write_header(self, zone, title):
        self.f.write(';' *  80 + '\n')
        zonestr = " zone: " + str(zone)
        self.f.write(';' + zonestr.center(79).rstrip() + '\n')
        self.f.write(';' + title.center(79).rstrip() + '\n')
        self.f.write(';' * 80 + '\n')

    def write_number_of_rrs(self, n):
        self.f.write("; number of records = " + str(n) + "\n")

    def write_stats(self, stats):
        self.f.write("\n;; statistics\n")
        for k, v in stats.items():
            self.f.write("; " + str(k) + " = " + str(v) + '\n')

    def write_record(self, rr):
        self.f.write(str(rr) + '\n')

    def _desc_filename(self):
        return self.f.name

    def nsec_reader(self):
        log.info("reading NSEC RRs from ", str(self.f.name))
        self.f.seek(0)
        p_ignore = re.compile(_comment_pattern)
        nsec_parse = rrtypes.nsec.parser()
        for i, line in enumerate(self.f):
            i += 1
            if p_ignore.match(line):
                continue
            try:
                nsec = nsec_parse(line)
                if nsec is None:
                    raise FileParseError(self._desc_filename(), i,
                            "invalid file format")
                yield nsec
            except ParseError:
                raise FileParseError(self._desc_filename(), i,
                        "could not parse NSEC record")
            except (NSECError,
                    MaxDomainNameLengthError,
                    MaxLabelLengthError) as e:
                raise FileParseError(self._desc_filename(), i,
                        "invalid NSEC record:\n" + str(e))

    def write_label_counter(self, label_counter):
        self.f.write(";;;; label_counter = 0x{0:x}\n".format(label_counter))

    def nsec3_reader(self):
        log.info("reading NSEC3 RRs from ", str(self.f.name))
        self.f.seek(0)
        p_counter = re.compile("^;;;; label_counter\s*=\s*0x([0-9a-fA-F]+)")
        p_ignore = re.compile(_comment_pattern)
        nsec3_parse = rrtypes.nsec3.parser()
        for i, line in enumerate(self.f, start=1):
            m_counter = p_counter.match(line)
            if m_counter is not None:
                try:
                    self.label_counter = int(m_counter.group(1), 16)
                except ValueError:
                    raise FileParseError(self._desc_filename(), i,
                            "cannot parse label counter value")
                continue
            elif p_ignore.match(line):
                continue
            try:
                nsec3 = nsec3_parse(line)
                if nsec3 is None:
                    raise FileParseError(self._desc_filename(), i,
                            "invalid file format")
                yield nsec3
            except ParseError:
                raise FileParseError(self._desc_filename(), i,
                        "could not parse NSEC3 record")
            except (NSEC3Error,
                    MaxDomainNameLengthError,
                    MaxLabelLengthError) as e:
                raise FileParseError(self._desc_filename(), i,
                        "invalid NSEC3 record:\n" + str(e))

def nsec_from_file(filename):
    """Read NSEC records from a file"""
    rrf = None
    try:
        rrf = open_input_rrfile(filename)
        return list(rrf.nsec_reader())
    finally:
        if rrf is not None:
            rrf.close()

def nsec3_from_file(filename):
    """Read NSEC3 records from a file"""
    rrf = None
    try:
        rrf = open_input_rrfile(filename)
        return list(rrf.nsec3_reader())
    finally:
        if rrf is not None:
            rrf.close()




