#!/usr/bin/python2.7
import base64, uuid, hashlib, time
import logging
import benchtool
import D2SStatus
from suds.client import Client
from httpslib import HTTPSClientCertTransport

try:
    import StringIO
    import lxml.etree as ET
except Exception as e:
    # TODO find lib unix
    TODO = 1
    # print e
    # traceback.print_exc(file=sys.stdout)


class D2SCaller():
    wsdl = "file:caller/wsdl/dxs/49/D2SInterfaceFrontEnd.wsdl"
    wsTime = -1

    def __init__(self, keyStore, trustStore, wsUri, verbose):
        self.transport = HTTPSClientCertTransport(keyStore, keyStore, trustStore)
        self.c = Client(self.wsdl, location=wsUri, transport=self.transport)
        if verbose:
            logging.basicConfig(level=logging.INFO)
            logging.getLogger('suds.client').setLevel(logging.INFO)
            logging.getLogger('suds.transport').setLevel(logging.DEBUG)

    def buildSignatureExParameter(self):
        return self.c.factory.create('signatureEx')

    def signatureEx(self, parameters):
        ts = time.time()
        response = self.c.service.signatureEx(parameters.requestId, parameters.transactionId, parameters.tag,
                                              parameters.dataToSign, parameters.detachedSignature,
                                              parameters.signatureFormat, parameters.signatureType,
                                              parameters.signatureParameter)
        wsTime = time.time() - ts
        self.wsTime = int(wsTime * 1000)
        return response

    def getExcetionTime(self):
        return self.wsTime

    def getpeercert(self):
        # print "pprint ", pprint.pprint(transport.getpeercert())
        cert = self.transport.getpeercert()
        return ", ".join(str(val[0][1]) for val in cert['subject'])


class benchSignature(benchtool.Bench):
    def __init__(self, threadID, counter, keystore, truststore, wsuri, requestId, transactionId, tag,
                 signatureFormat, signatureType, b64data, signatureParameter):
        benchtool.Bench.__init__(self, threadID, counter)

        self.caller = D2SCaller(keystore, truststore, wsuri, False)

        self.parameters = self.caller.buildSignatureExParameter()
        self.parameters.requestId = requestId
        self.parameters.transactionId = transactionId
        self.parameters.tag = tag
        self.parameters.dataToSign.binaryValue = b64data
        self.parameters.signatureFormat = signatureFormat
        self.parameters.signatureType = signatureType
        self.parameters.signatureParameter = signatureParameter
        self.parameters.detachedSignature = None
        self.parameters.signatureContext = None
        self.parameters.pluginParameter = None

        self.caller.signatureEx(self.parameters)

    def execute(self):
        response = self.caller.signatureEx(self.parameters)
        if response.opStatus == 0 and response.D2SStatus == 0:
            return True
        else:
            return False


def ppResponse(response, wsTime, outFile):
    print '\nExecution Time :', wsTime, " ms\n"

    if response.opStatus == 0:
        print 'requestId \t:', response.requestId
        print 'D2SArchiveId \t:', response.D2SArchiveId

    print '\nOpStatus \t:', response.opStatus
    print D2SStatus.pprint(D2SStatus.OpStatus(response.opStatus))

    if response.opStatus == 0:
        print 'D2SGlobalStatus\t:', response.D2SStatus
        print D2SStatus.pprint(D2SStatus.D2SGlobalStatus(response.D2SStatus))

    if response.opStatus == 0 and response.D2SStatus == 0:

        if outFile != None:
            f = open(outFile, "w")
            f.write(base64.b64decode(response.D2SSignature.binaryValue))
            f.close()
        else:
            print 'D2SSignature \t:', response.D2SSignature.binaryValue

        exitCode = 0
    else:
        exitCode = 1

    return exitCode


def buildSignatureParameter(signatureType, file, isC14n):
    if file == None:
        return None

    hash = computeXMLHash(file) if isC14n else computeHash(file)

    if isC14n:
        transform = "<Transforms>" \
                    "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" \
                    "</Transforms>";

    signatureParameterManifest = \
        "<Reference>", \
        transform, \
        "<DigestValue>", hash, "</DigestValue>", \
        "<DigestMethod>SHA256</DigestMethod>", \
        "<URI>", "mydata#", uuid.uuid4(), "</URI>", \
        "</Reference>"

    sigParam = "<Parameters>"
    sigParam += "<Manifest>" if signatureType == "MANIFEST"  else "<DetachedSignature>"
    sigParam += signatureParameterManifest
    sigParam += "</Manifest>" if signatureType == "MANIFEST" else "</DetachedSignature>"
    sigParam += "</Parameters>"
    return sigParam


def computeHash(file_name):
    with open(file_name) as f:
        m = hashlib.sha256()
        chunk_size = 1024
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            m.update(data)

        res = base64.b64encode(m.digest())
    return res


def computeXMLHash(file):
    with ET.parse(file) as et:
        m = hashlib.sha256()
        output = StringIO.StringIO()
        et.write_c14n(output)
        m.update(output.getvalue())
        res = base64.b64encode(m.digest())
    return res
