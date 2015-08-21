#!/usr/bin/python2.7
import base64, time
import logging
import benchtool
from suds.client import Client
from httpslib import HTTPSClientCertTransport
import urllib
import urllib2
import rfc3161
import hashlib
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder, decoder
from pyasn1.error import PyAsn1Error


def getHash(file, algo):
    with open(file, 'rb') as f:
        b64data = f.read()

    hashValue = None

    if algo is None or "sha256":
        hashValue = hashlib.sha256(b64data).digest()
    elif algo is "sha1":
        hashValue = hashlib.sha1(b64data).digest()
    elif algo is "sha512":
        hashValue = hashlib.sha512(b64data).digest()
    elif algo is "md5":
        hashValue = hashlib.md5(b64data).digest()
    else:
        print "Unsupported hash algorithm ", hash

    return hashValue


class TSACaller():
    def __init__(self, wsUri, certificate, hashName, keystore=None, truststore=None, verbose=False):
        self.url = wsUri

        self.rt = rfc3161.RemoteTimestamper(self.url, certificate, hashname=hashName, keystore=keystore,
                                            truststore=truststore)
        if verbose:
            logging.basicConfig(level=logging.DEBUG)

    def timeStamp(self, digest, include_tsa_certificate):
        ts = time.time()

        tst = self.rt.timestamp(digest=digest)

        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return tst

    def getExcetionTime(self):
        return self.wsTime

    def getpeercert(self):
        cert = self.rt.getpeercert()
        if cert is not None:
            return ", ".join(str(val[0][1]) for val in cert['subject'])
        else:
            return None


class benchTimeStamp(benchtool.Bench):
    def __init__(self, threadID, counter, wsUri, certificate, hashName, hashValue, include_tsa_certificate,
                 keystore=None, truststore=None):
        benchtool.Bench.__init__(self, threadID, counter)
        self.caller = TSACaller(wsUri, certificate, hashName, keystore, truststore)
        self.digest = hashValue
        self.include_tsa_certificate = include_tsa_certificate

    def execute(self):
        response, res = self.caller.timeStamp(self.digest, self.include_tsa_certificate)
        if response is False:
            return False
        else:
            return True


def ppResponse(response, wsTime, outFile):
    print '\nExecution Time :', wsTime, " ms\n"
    # print 'OpStatus \t:', response.opStatus
    # print 'DTSSStatus \t:', response.DTSSGlobalStatus

    if response is not None:
        # print 'requestId \t:', response.requestId
        # print 'DTSSArchiveId \t:', response.DTSSArchiveId

        if outFile != None:
            f = open(outFile, "wb")
            f.write(response)
            f.close()
        else:
            print 'TSA Response \t:\n', response

        exitCode = 0
    else:
        exitCode = 1

    return exitCode
