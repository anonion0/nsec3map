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
    def __init__(self, loglevel=LOG_WARN, logfile=sys.stderr, colors='auto'):
        self.loglevel = loglevel
        self._file = logfile
        self.set_colors(colors)

    def set_colors(self, preference):
        if preference == 'always':
            colors = Colors()
        elif preference == 'auto':
            if self._file.isatty():
                colors = Colors()
            else:
                colors = NoColors()
        elif preference == 'never':
            colors = NoColors()
        else:
            raise ValueError
        self.colors = ColorSchemeDefault(colors)
        self._make_colormap()

    def _make_colormap(self):
        self._colormap = {
                LOG_WARN  : self.colors.WARN,
                LOG_ERROR : self.colors.ERROR,
                LOG_FATAL : self.colors.ERROR,
                LOG_DEBUG1: self.colors.DEBUG1,
                LOG_DEBUG2: self.colors.DEBUG2,
                LOG_DEBUG3: self.colors.DEBUG3
            }

    def _write_log(self, msg):
        self._file.write(msg)

    def _colorize_msg(self, level, *msg):
        try:
            return self.colors.wrap_list(self._colormap[level], list(msg))
        except KeyError:
            return msg

    def _compile_msg(self, *msg):
        l = list(map(str, msg))
        l.append("\n")
        return ''.join(l)

    def do_log(self, level, *msg):
        if self.loglevel < level and level > LOG_FATAL:
            return
        msg = self._colorize_msg(level, *msg)
        msg = self._compile_msg(*msg)
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
    def __init__(self, loglevel=LOG_WARN, logfile=sys.stderr, colors='auto'):
        super(ProgressLineLogger,self).__init__(loglevel,logfile, colors)
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

    def from_logger(logger):
        plogger = ProgressLineLogger(logger.loglevel, logger._file)
        plogger.colors = logger.colors
        plogger._colormap = logger._colormap
        return plogger

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
            msg = self._colorize_msg(level, *msg)
            self._buffer.append(self._compile_msg(*msg))
            self.disable()
            return
        if self.loglevel >= level:
            msg = self._colorize_msg(level, *msg)
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

class NoColors:
    RESET          = ''
    RED            = ''
    GREEN          = ''
    YELLOW         = ''
    BLUE           = ''
    MAGENTA        = ''
    CYAN           = ''
    BRIGHT_RED     = ''
    BRIGHT_GREEN   = ''
    BRIGHT_YELLOW  = ''
    BRIGHT_BLUE    = ''
    BRIGHT_MAGENTA = ''
    BRIGHT_CYAN    = ''

    def __init__(self):
        pass

    def wrap(self, color, s):
        return s

    def wrap_list(self, color, l):
        return l

class Colors(NoColors):
    RESET          = '\033[0m'
    RED            = '\033[31m'
    GREEN          = '\033[32m'
    YELLOW         = '\033[33m'
    BLUE           = '\033[34m'
    MAGENTA        = '\033[35m'
    CYAN           = '\033[36m'
    BRIGHT_RED     = '\033[1;31m'
    BRIGHT_GREEN   = '\033[1;32m'
    BRIGHT_YELLOW  = '\033[1;33m'
    BRIGHT_BLUE    = '\033[1;34m'
    BRIGHT_MAGENTA = '\033[1;35m'
    BRIGHT_CYAN    = '\033[1;36m'

    def __init__(self):
        pass

    def wrap(self, color, s):
        return ''.join((color, s, self.RESET))

    def wrap_list(self, color, l):
        l.insert(0, color)
        l.append(self.RESET)
        return l

class ColorSchemeDefault:
    def __init__(self, colors):
        if colors is None:
            colors = Colors()
        self.WARN = colors.BRIGHT_YELLOW
        self.ERROR = colors.BRIGHT_RED
        self.DEBUG1 = colors.CYAN
        self.DEBUG2 = colors.CYAN
        self.DEBUG3 = colors.CYAN
        self.PROGRESSBAR = colors.CYAN
        self.PROGRESS = colors.BRIGHT_CYAN
        self.RECORDS = colors.BRIGHT_GREEN
        self.NUMBERS = colors.CYAN
        self.ZONE = colors.BRIGHT_BLUE
        self.DECO = colors.BRIGHT_MAGENTA

        self.RESET = colors.RESET
        self.colors = colors

    def wrap(self, color, s):
        return self.colors.wrap(color, s)

    def wrap_list(self, color, l):
        return self.colors.wrap_list(color, l)

    def gradient(self, ratio):
        if ratio < 0.33:
            return self.colors.BRIGHT_CYAN
        elif ratio < 0.66:
            return self.colors.BRIGHT_GREEN
        elif ratio < 1.0:
            return self.colors.BRIGHT_YELLOW
        else:
            return self.colors.BRIGHT_RED

