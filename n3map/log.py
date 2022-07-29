import sys
import os
import fcntl
import array
import termios

import signal
import time
import collections

LOG_FATAL = -2
LOG_ERROR = -1
LOG_WARN = 0
LOG_INFO = 1
LOG_DEBUG1 = 2
LOG_DEBUG2 = 3
LOG_DEBUG3 = 4

BUFFER_INTERVAL = 0.2

def update():
    logger.update()

def fatal_exit(exitcode, *msg):
    logger.do_log(LOG_FATAL, os.path.basename(sys.argv[0]), ": fatal: ", *msg)
    exit(exitcode)

def fatal(*msg):
    fatal_exit(1, *msg)

def warn(*msg):
    logger.do_log(LOG_WARN, "warning: ", *msg)

def error(*msg):
    logger.do_log(LOG_ERROR, "error: ", *msg)

def info(*msg):
    logger.do_log(LOG_INFO, *msg)

def debug1(*msg):
    logger.do_log(LOG_DEBUG1, *msg)

def debug2(*msg):
    logger.do_log(LOG_DEBUG2, *msg)

def debug3(*msg):
    logger.do_log(LOG_DEBUG3, *msg)


class Logger(object):
    def __init__(self, loglevel=LOG_WARN, logfile=sys.stderr):
        self.loglevel = loglevel
        self._file = logfile

    def _write_log(self, msg):
        self._file.write(msg)

    def _compile_msg(self, *msg):
        l = list(map(str, msg))
        l.append("\n")
        return ''.join(l)

    def do_log(self, level, *msg):
        if level == LOG_FATAL:
            msg = self._compile_msg(*msg)
            self._write_log(msg)
            return
        if self.loglevel >= level:
            msg  = self._compile_msg(*msg)
            self._write_log(msg)

    def update(self):
        pass

    def set_status_generator(self, generator, formatfunc):
        pass

    def block_signals(self):
        pass

    def unblock_signals(self):
        pass


received_sigwinch = False

def sigwinch_handler(signum, frame):
	global received_sigwinch 
	received_sigwinch = True

def setup_signal_handling():
    signal.signal(signal.SIGWINCH,sigwinch_handler)
    signal.siginterrupt(signal.SIGWINCH, False)

def reset_signal_handling():
	signal.signal(signal.SIGWINCH, signal.SIG_DFL)

class ProgressLineLogger(Logger):
    def __init__(self, loglevel=LOG_WARN, logfile=sys.stderr):
        super(ProgressLineLogger,self).__init__(loglevel,logfile)
        self._generator = None
        self._formatter = None
        self._buffer = collections.deque()
        self._flush_interval = 0.0
        self._last_flush = 0
        self._screen_width = 0
        self._screen_height = 0
        self._current_status = None
        self._statuslines = None
        self._enabled = False

    def enable(self):
        self._last_flush = 0;
        self._flush_interval = BUFFER_INTERVAL
        setup_signal_handling()
        self._determine_screen_size()
        self._enabled = True

    def disable(self):
        self._enabled = False
        self.flush()
        reset_signal_handling()
        self._last_flush = 0
        self._flush_interval = 0

    def block_signals(self):
        if not self._enabled:
            return
        signal.signal(signal.SIGWINCH, signal.SIG_IGN)

    def unblock_signals(self):
        if not self._enabled:
            return
        setup_signal_handling()
        # in case a signal would have arrived in the meantime
        self._determine_screen_size()



    def set_status_generator(self, generator, formatfunc):
        self.flush()
        self._generator, self._formatter = generator, formatfunc
        if generator is not None:
            self.enable()
        else:
            self.disable()

    def flush(self):
        self._format_statuslines()
        self._write_log(''.join(self._buffer))
        self._buffer.clear()
        self._file.flush()
        self._last_flush = time.monotonic()

    def do_log(self, level, *msg):
        if level == LOG_FATAL:
            self.set_status_generator(None, None)
            self._buffer.append(self._compile_msg(*msg))
            self.disable()
            return
        if self.loglevel >= level:
            self._buffer.append(self._compile_msg(*msg))
            self.update(force=(level <= LOG_WARN))
        elif level <= LOG_DEBUG1:
            self.update(force=(level <= LOG_WARN))

    def update(self, force=False):
        if self._generator is not None:
            gen = self._generator
            self._current_status = gen()
        if not force and time.monotonic() - self._last_flush < self._flush_interval:
            return
        self.flush()

    def _format_statuslines(self):
        if self._current_status is None or self._formatter is None:
            self._statuslines = None
            self._current_status = None
            return
        # new statusline
        global received_sigwinch
        if received_sigwinch:
            received_sigwinch = False
            self._determine_screen_size()
        if self._statuslines is not None and self._file.isatty():
            # clear old statuslines
            self._buffer.appendleft(''.join(("\r\033[0K","\033[A\033[0K"*len(self._statuslines))))
        formatfunc = self._formatter
        self._statuslines = formatfunc(self._screen_width,
                                       *(self._current_status))
        self._current_status = None
        self._buffer.extend(('\n'.join(self._statuslines), "\n"))


    def _determine_screen_size(self):
        if self._file.isatty():
            buf = array.array('h', [0, 0, 0, 0]) 
            res = fcntl.ioctl(self._file.fileno(), termios.TIOCGWINSZ, buf)
            if res != 0:
                raise EnvironmentError("ioctl() failed")
            self._screen_height = buf[0]
            self._screen_width = buf[1]
        else:
            self._screen_height = 20
            self._screen_width = 80

