#!/usr/bin/env python3
from __future__ import with_statement
import use_local # HACK so don't have to rebuild constantly
from xml.dom import minidom
import xml
import time
import random
import logging
import traceback
import sys
from xdrdef.nfs4_const import nfsstat4
from errorfunctions import Errors

log = logging.getLogger("nfs.proxy.errorhandler")
log.setLevel(logging.INFO)

class ErrorDesc():
    def __init__(self):
        self.name = []
        self.operation = []
        self.errorcode = []
        self.function = []
        self.delay = [0] # default no delay
        self.frequency = [10] # default value is 1/10

    def addField(self, field, value):
        log.debug("%s -- %s" % (field, value))
        setattr(self, field, value)

class ErrorParser():
    def __init__(self, filename):
        random.seed()
        self.dom = xml.dom.minidom.parse(filename)
        self.errors = []
        if filename is None:
                log.info("No error description file specified")
        else:
                log.info("Loading file %s " % filename)
                try:
                    self.get_error_desc()
                except:
                    traceback.print_exc(file=sys.stdout)
                    log.error("Error loading file")

    def get_error_desc(self):
        self.handleErrorConf()

    def getText(self, nodelist):
        rc = []
        for node in nodelist:
            if node.nodeType == node.TEXT_NODE:
                rc.append(node.data.lower())
        return rc

    def handleErrorConf(self):
        self.handleError(self.dom.getElementsByTagName("error"))

    def handleError(self, elements):
        errorconf = self.dom
        for el in elements:
            error = ErrorDesc()
            self.handleElement(error, "name",
                               el.getElementsByTagName("name"))
            self.handleElement(error, "operation",
                               el.getElementsByTagName("operation"))
            self.handleElement(error, "errorcode",
                               el.getElementsByTagName("errorcode"))
            self.handleElement(error, "delay",
                               el.getElementsByTagName("delay"))
            self.handleElement(error, "frequency",
                               el.getElementsByTagName("frequency"))
            self.handleElement(error, "function",
                               el.getElementsByTagName("function"))
            self.errors.append(error)

    def handleElement(self, error, name, elements):
        x = []
        for el in elements:
            x.extend(self.getText(el.childNodes))
        error.addField(name, x)

    def get_error(self, opname, arg=None, env=None):
        # opname must be e.g "create_session" or "sequence" from the caller
        for err in self.errors:
            if opname not in err.operation:
                continue
            freq = int(err.frequency[0])
            delay = float(err.delay[0])
            log.debug("found match :%s" % opname.upper())
            # check frequency and see if we should proceed
            if random.randint(1,freq) != freq:
                continue
            # delay first
            if delay > 0:
                log.info("Delaying operation %s by %f" %
                         (opname.upper(), delay))
                time.sleep(delay)
            if len(err.errorcode) == 0 and len(err.function) == 0:
                continue
            try:
                error = random.choice(err.errorcode)
                # .xml has an errorcode
                log.info("%s returning error code %s" % (opname.upper(),
                                                         error.upper()))
                return int(error)
            except ValueError: # .xml has an errorstring
                    for code, string in nfsstat4.iteritems():
                        if error.upper() == string.upper():
                            return code
                    log.error("Error %s not applied" % error)
                    continue
            except IndexError: # function
                functions = Errors()
                func = getattr(functions, random.choice(err.function))
                print(func)
                if callable(func):
                    func(opname, arg, env)

#if __name__ == "__main__":
#    e = ErrorParser("error.xml")
#    e.get_error_desc()
