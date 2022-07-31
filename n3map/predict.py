import os
import gc
import sys
import multiprocessing
import signal
import math

from . import log

from .exception import N3MapError

HAS_NUMPY = False
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    pass
HAS_SCIPY = False
try:
    from scipy.optimize import leastsq
    HAS_SCIPY = True
except ImportError:
    pass


def np_func(p,x):
    a,b = p
    return b - np.sqrt(np.exp(a)*(np.ones(len(x))-x))

def np_dfunc(p,x,y):
    a,b = p
    return np.array([-0.5 * np.sqrt(-np.exp(a)*(x-np.ones(len(x)))),
            np.ones(len(x))])

def np_residuals(p,x,y):
    return np_func(p,x) - y

def compute_fit(params,xdata,ydata):
    res = [0,0]
    try:
        args = (xdata, ydata)
        res = leastsq(np_residuals,params, Dfun=np_dfunc,col_deriv=True, args=args)
    except (ValueError,OverflowError,ZeroDivisionError):
        pass
    return res[0]

def sample(data, n):
    length = float(len(data))
    return [data[i] for i in [int(math.ceil(j * length / n)) for j in range(n)]]


def create_zone_predictor():
    if not HAS_NUMPY:
        raise N3MapError("failed to start predictor: could not import numpy")
    if not HAS_SCIPY:
        raise N3MapError("failed to start predictor: could not import scipy")
    par,chld = multiprocessing.Pipe(True)
    proc = PredictorProcess(chld)
    proc.start()
    return proc,par

class PredictorProcess(multiprocessing.Process):
    def __init__ (self, pipe):
        multiprocessing.Process.__init__(self)
        self.daemon = True
        self.pipe = pipe
        self._coverage_data = []

    def run(self):
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            # sometimes scipy spills warnings to stderr
            # redirect stdout,stderr to /dev/null
            nullfd = os.open(os.devnull,os.O_RDWR)
            os.dup2(nullfd,sys.stdout.fileno())
            os.dup2(nullfd,sys.stderr.fileno())

            os.nice(15)
            gc.collect()
            log.logger = None
            repredict_threshold = 20
            while True:
                cov,rec = self.pipe.recv()
                self._coverage_data.append((cov,rec))
                for i in range(repredict_threshold):
                    if not self.pipe.poll():
                        break;
                    cov,rec = self.pipe.recv()
                    self._coverage_data.append((cov,rec))
                size = self._predict_zone_size()
                self.pipe.send(int(size))
        except EOFError:
            sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(3)

    def _predict_zone_size(self):
        npts = len(self._coverage_data)
        if npts <= 1:
            return 1e8

        sample_sz = 5
        if npts < sample_sz:
            sample_sz = npts

        subset = sample(self._coverage_data,sample_sz-1)
        subset.append(self._coverage_data[-1])

        xdata,ydata = list(zip(*subset))
        lastcov = xdata[-1]
        if lastcov < 1e-8:
            lastcov = 1e-8
        binit = (1/lastcov*ydata[-1])
        ainit = 2.0*math.log(binit)
        a,b = compute_fit([ainit,binit],xdata,ydata)
        current_records = self._coverage_data[-1][1]
        return b if b >= current_records else current_records
