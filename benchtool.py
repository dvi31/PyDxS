#!/usr/bin/python2.7
import sys, logging, time, threading
from suds.client import Client
from httpslib import HTTPSClientCertTransport


class Bench(threading.Thread):
    success = 0
    error = 0
    min = sys.maxint
    max = 0
    avg = -1
    tps = -1
    total = 0

    def __init__(self, threadID, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.counter = counter


    def run(self):
        self.isAlive = True
        for x in range(0, self.counter):
            try:
                start = time.time()

                if self.execute():
                    self.success += 1
                else:
                    self.error += 1

                end = time.time()
                ts = int((end - start) * 1000)
                if self.min > ts: self.min = ts
                if self.max < ts: self.max = ts
                self.total += ts
            except Exception as e:
                print e
                self.error += 1

        self.isAlive = False
        if self.total > 0:
            self.avg = int(self.total / self.counter)
            self.tps = round(1000 / (self.total / self.counter), 3)

    def execute(self):
        raise Exception('execute', 'must be override')

    def isRunning(self):
        return self.isAlive

    def getpeercert(self):
        return self.caller.getpeercert()

    def pprintBenchResult(self):
        # return "# %10s # %8.2f # %8s # %8s # %8s # %10s # %8s # %8s #".format(
        #     self.threadID, self.tps, self.avg, self.min, self.max, self.total, self.success, self.error)
        return "# %10s # %8.2f # %8s # %8s # %8s # %10s # %8s # %8s #" % (
            self.threadID, self.tps, self.avg, self.min, self.max, self.total, self.success, self.error)
        # return format(self.threadID, "#", self.tps, "#", self.avg, "#", self.min, "#", self.max, "#", self.total,
        #                   "#", self.success, "#", self.error)


def pprintBenchHeader():
    return "\n---------------------------------------------------------------------------------------------\n" \
           "# %10s # %8s # %8s # %8s # %8s # %10s # %8s # %8s #\n" \
           "---------------------------------------------------------------------------------------------" % (
               "ThreadId", "TPS", "AVG (ms)", "Min (ms)", "Max (ms)", "Total (ms)", "Success", "Error")


def pprintBenchTotal(executors, executionTime):
    _loop = 0
    _min = sys.maxint
    _max = 0
    # _total = 0
    _avg = 0
    _tps = 0
    _success = 0
    _error = 0
    for ex in executors:
        _loop += ex.counter
        # _total += ex.total
        _success += ex.success
        _avg += ex.avg
        _error += ex.error
        if _min > ex.min: _min = ex.min
        if _max < ex.max: _max = ex.max

    if (_success != 0):
        _tps = round(1000 / (executionTime / _success), 3)
        _avg = _avg / _success

    return "---------------------------------------------------------------------------------------------\n" \
           "# %10s # %8.2f # %8s # %8s # %8s # %10s # %8s # %8s #\n " \
           "---------------------------------------------------------------------------------------------\n\n" \
           " Execution time : %s \n" \
           " Total TPS : %.2f \n" \
           " Total SUCCESS : %s \n" \
           " Total ERROR : %s \n" % (
               "*", _tps, _avg, _min, _max, executionTime, _success, _error, executionTime, _tps, _success,
               _error)
