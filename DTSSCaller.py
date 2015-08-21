#!/usr/bin/python2.7
import base64, time
import logging
import benchtool
import DTSSStatus
from suds.client import Client
from httpslib import HTTPSClientCertTransport


class DTSSCaller():
    wsdl = "file:caller/wsdl/dxs/49/DTSSInterfaceFrontEnd.wsdl"
    wsTime = -1

    def __init__(self, keyStore, trustStore, wsUri, verbose):
        self.transport = HTTPSClientCertTransport(keyStore, keyStore, trustStore)
        self.c = Client(self.wsdl, location=wsUri, transport=self.transport)
        if verbose:
            logging.basicConfig(level=logging.INFO)
            logging.getLogger('suds.client').setLevel(logging.DEBUG)
            logging.getLogger('suds.transport').setLevel(logging.DEBUG)

    def buildInsertTimeStampExParameter(self):
        return self.c.factory.create('insertTimeStampEx')

    def insertTimeStampEx(self, parameters):
        ts = time.time()
        response = self.c.service.insertTimeStampEx(parameters.requestId, parameters.transactionId, parameters.tag,
                                                    parameters.signature, parameters.signatureParameter,
                                                    parameters.pluginParameter)
        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return response

    def getExcetionTime(self):
        return self.wsTime

    def getpeercert(self):
        cert = self.transport.getpeercert()
        return ", ".join(str(val[0][1]) for val in cert['subject'])


class benchInsertTimeStampEx(benchtool.Bench):
    def __init__(self, threadID, counter, keystore, truststore, wsuri, requestId, transactionId, tag,
                 b64data, signatureParameter):
        benchtool.Bench.__init__(self, threadID, counter)

        self.caller = DTSSCaller(keystore, truststore, wsuri, False)

        self.parameters = self.caller.buildInsertTimeStampExParameter()
        self.parameters.requestId = requestId
        self.parameters.transactionId = transactionId
        self.parameters.tag = tag
        self.parameters.signature.binaryValue = b64data
        self.parameters.signatureParameter = signatureParameter
        self.parameters.pluginParameter = None

        self.caller.insertTimeStampEx(self.parameters)

    def execute(self):
        response = self.caller.insertTimeStampEx(self.parameters)
        if response.opStatus == 0 and response.DTSSGlobalStatus == 0:
            return True
        else:
            return False


def ppResponse(response, wsTime, outFile):
    print '\nExecution Time :', wsTime, " ms\n"

    if response.opStatus == 0:
        print 'requestId \t:', response.requestId
        print 'DTSSArchiveId \t:', response.DTSSArchiveId

    print '\nOpStatus \t:', response.opStatus
    print DTSSStatus.pprint(DTSSStatus.OpStatus(response.opStatus))

    if response.opStatus == 0:
        print 'DTSSGlobalStatus:', response.DTSSGlobalStatus
        print DTSSStatus.pprint(DTSSStatus.DTSSGlobalStatus(response.DTSSGlobalStatus))

    if response.opStatus == 0 and response.DTSSGlobalStatus == 0:
        if outFile != None:
            f = open(outFile, "w")
            f.write(base64.b64decode(response.ExtendedSignature.binaryValue))
            f.close()
        else:
            print 'DTSSSignature \t:', response.ExtendedSignature.binaryValue

        exitCode = 0
    else:
        exitCode = 1

    return exitCode


def timeStamp(url, hashValue):
    import urllib
    import urllib2
    # import base64;

    # first we construct the parameters for the request
    data = {}
    data['hashAlgo'] = "SHA256"
    data['withCert'] = "true"
    data['hashValue'] = hashValue
    params = urllib.urlencode(data)

    # basic HTTP authentication is needed to access this service
    headers = {}
    # auth = base64.encodestring(username + ":" + password);
    # headers["Authorization"] = "Basic " + auth;

    # then the request itself
    request = urllib2.Request(url, params, headers)

    # all is ready, the request is made
    response = urllib2.urlopen(request)
    tsp = response.read()
